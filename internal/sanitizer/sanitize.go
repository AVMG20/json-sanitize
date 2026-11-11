// Package sanitizer strips personal data from JSON while keeping its exact structure.
//
// Passes over the leaf values (only leaves ever change, so the shape can't drift):
//  1. key rules    — values under keys like `email`, `phone_number`, `last_name` are replaced outright;
//     a bare `name` only when its parent looks like a person (`customer.name`)
//  2. regex        — emails, phones, IPs, IBANs, grouped card numbers, postcodes, streets
//  3. known values — whatever 1 found (and the parts of names) is replaced everywhere else too
//  4. detector     — the LLM lists remaining names/addresses; filtered, then replaced
//
// IDs, codes, tokens, tracking numbers and URLs are always preserved. Afterwards the input and
// output trees are compared; the output is only returned when the structure is identical.
package sanitizer

import (
	"strings"
)

// ChunkChars caps the JSON size of one detector batch.
const ChunkChars = 2500

// pseudonymizer: same value → same placeholder across the document, so relations stay readable.
type pseudonymizer struct {
	ids    map[string]string
	counts map[string]int
}

func (p *pseudonymizer) get(typ, original string) string {
	id := typ + "\x00" + strings.ToLower(strings.TrimSpace(original))
	if ph, ok := p.ids[id]; ok {
		return ph
	}
	p.counts[typ]++
	ph := "[" + typ + "_" + itoa(p.counts[typ]) + "]"
	p.ids[id] = ph
	return ph
}

// reasons records why each path changed, in first-seen order.
type reasons map[string][]string

func (r reasons) note(path, reason string) {
	for _, x := range r[path] {
		if x == reason {
			return
		}
	}
	r[path] = append(r[path], reason)
}

// Sanitize parses input, redacts personal data and returns the pretty-printed result.
// detect may be nil (rules and regex only). A detector error aborts the whole run, so a
// half-sanitized document is never returned.
func Sanitize(input string, detect Detector) (Result, error) {
	in, err := Parse(input)
	if err != nil {
		return Result{}, err
	}
	ph := &pseudonymizer{ids: map[string]string{}, counts: map[string]int{}}
	why := reasons{}

	// Values found by key rules, reused in pass 3 to catch the same person/address in free text.
	var known []Entity
	// Values under city/company/product keys: an LLM hit equal to one of these is a false positive.
	safeValues := map[string]bool{}

	// Pass 1+2: key rules and regex.
	out := mapLeaves(in, func(n *Node, path, key, parent string) *Node {
		keyType := ""
		if key != "" {
			keyType = KeyRuleType(key, parent)
		}
		if keyType != "" && n.Kind == KString && strings.TrimSpace(n.Str) != "" && !isPlaceholderOnly(n.Str) {
			why.note(path, "key:"+keyType)
			known = append(known, Entity{Text: strings.TrimSpace(n.Str), Type: keyType})
			return str(ph.get(keyType, n.Str))
		}
		if n.Kind == KString && isSafeContext(key, parent) {
			safeValues[strings.TrimSpace(n.Str)] = true
		}
		if keyType != "" && n.Kind == KNumber {
			why.note(path, "key:"+keyType)
			return &Node{Kind: KNumber, Num: "0"} // keep the type, drop the value
		}
		if n.Kind == KString {
			return str(redactPatterns(n.Str, func(typ, text string) string {
				why.note(path, "regex:"+typ)
				return ph.get(typ, text)
			}))
		}
		return n
	})

	replaceAll := func(entities []Entity, source string, onMatch func(Entity)) {
		if len(entities) == 0 {
			return
		}
		out = mapLeaves(out, func(n *Node, path, _, _ string) *Node {
			if n.Kind != KString {
				return n
			}
			return str(replaceEntities(n.Str, entities, func(e Entity) string {
				if onMatch != nil {
					onMatch(e)
				}
				why.note(path, source+":"+e.Type)
				return ph.get(e.Type, e.Text)
			}))
		})
	}

	// Pass 3: the same names/addresses elsewhere in the document ("Jan" from firstname in a comment).
	replaceAll(expandKnown(known), "known", nil)

	res := Result{Diffs: []string{}, Changes: []Change{}, Unmatched: []string{}}

	// Pass 4: detector (LLM) on what's left.
	if detect != nil {
		seen := map[string]bool{}
		var items []DetectItem
		mapLeaves(out, func(n *Node, _, key, parent string) *Node {
			if isSafeContext(key, parent) || n.Kind != KString || !worthAsking(n.Str) {
				return n
			}
			id := key + "\x00" + n.Str
			if !seen[id] {
				seen[id] = true
				items = append(items, DetectItem{Key: key, Value: n.Str})
			}
			return n
		})

		chunks := chunk(items, ChunkChars)
		var entities []Entity
		for _, c := range chunks {
			found, err := detect(c)
			if err != nil {
				return Result{}, err
			}
			entities = append(entities, found...)
		}

		usable := filterDetected(entities, safeValues)
		matched := map[string]bool{}
		replaceAll(usable, "llm", func(e Entity) { matched[e.Text] = true })
		// First/last names on their own, once the LLM found the full name.
		var parts []Entity
		for _, p := range namePartsOf(usable) {
			if !safeValues[p.Text] {
				parts = append(parts, p)
			}
		}
		replaceAll(parts, "llm", nil)

		res.Chunks, res.Entities = len(chunks), len(usable)
		for _, e := range usable {
			if !matched[e.Text] {
				res.Unmatched = append(res.Unmatched, e.Text)
			}
		}
	}

	res.Diffs, res.Changes = DiffTrees(in, out, why)
	res.Valid = len(res.Diffs) == 0
	res.Counts = ph.counts
	if res.Valid {
		res.Output = Pretty(out)
	}
	return res, nil
}

func str(s string) *Node { return &Node{Kind: KString, Str: s} }

type leafFn func(n *Node, path, key, parentKey string) *Node

// mapLeaves rebuilds the tree, calling fn on every non-container value with its key and the key
// of the object holding it (`customer.name` → key "name", parent "customer"). Arrays pass both down.
func mapLeaves(n *Node, fn leafFn) *Node {
	return mapNode(n, fn, "$", "", "")
}

func mapNode(n *Node, fn leafFn, path, key, parent string) *Node {
	switch n.Kind {
	case KArray:
		out := &Node{Kind: KArray, Arr: make([]*Node, len(n.Arr))}
		for i, v := range n.Arr {
			out.Arr[i] = mapNode(v, fn, path+"["+itoa(i)+"]", key, parent)
		}
		return out
	case KObject:
		out := &Node{Kind: KObject, Keys: append([]string{}, n.Keys...), Vals: make([]*Node, len(n.Vals))}
		for i, k := range n.Keys {
			out.Vals[i] = mapNode(n.Vals[i], fn, childPath(path, k), k, key)
		}
		return out
	default:
		return fn(n, path, key, parent)
	}
}

// DiffTrees checks the structure (same types at every path, same keys in the same order, same
// array lengths; non-string leaves may only change through a key rule) and lists changed leaves.
func DiffTrees(a, b *Node, why reasons) (diffs []string, changes []Change) {
	diffs, changes = []string{}, []Change{}
	var walk func(x, y *Node, path string)
	walk = func(x, y *Node, path string) {
		if x.Kind != y.Kind {
			diffs = append(diffs, path+": type changed "+x.Kind.String()+" → "+y.Kind.String())
			return
		}
		switch x.Kind {
		case KArray:
			if len(x.Arr) != len(y.Arr) {
				diffs = append(diffs, path+": array length "+itoa(len(x.Arr))+" → "+itoa(len(y.Arr)))
			}
			for i := 0; i < len(x.Arr) && i < len(y.Arr); i++ {
				walk(x.Arr[i], y.Arr[i], path+"["+itoa(i)+"]")
			}
		case KObject:
			xi, yi := index(x), index(y)
			for _, k := range x.Keys {
				if _, ok := yi[k]; !ok {
					diffs = append(diffs, childPath(path, k)+": key missing")
				}
			}
			for _, k := range y.Keys {
				if _, ok := xi[k]; !ok {
					diffs = append(diffs, childPath(path, k)+": key added")
				}
			}
			if len(diffs) == 0 && strings.Join(x.Keys, "\x00") != strings.Join(y.Keys, "\x00") {
				diffs = append(diffs, path+": key order changed")
			}
			for i, k := range x.Keys {
				if j, ok := yi[k]; ok {
					walk(x.Vals[i], y.Vals[j], childPath(path, k))
				}
			}
		default:
			before, after := Literal(x), Literal(y)
			if before == after {
				return
			}
			r := why[path]
			if r == nil {
				r = []string{}
			}
			if x.Kind != KString && !hasKeyReason(r) {
				diffs = append(diffs, path+": "+x.Kind.String()+" value changed")
			}
			changes = append(changes, Change{Path: path, Before: before, After: after, Reasons: r})
		}
	}
	walk(a, b, "$")
	return diffs, changes
}

// index maps each key to its first position (duplicate keys pair up by first occurrence).
func index(n *Node) map[string]int {
	m := make(map[string]int, len(n.Keys))
	for i := len(n.Keys) - 1; i >= 0; i-- {
		m[n.Keys[i]] = i
	}
	return m
}

func hasKeyReason(r []string) bool {
	for _, s := range r {
		if strings.HasPrefix(s, "key:") {
			return true
		}
	}
	return false
}
