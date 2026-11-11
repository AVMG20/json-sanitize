package sanitizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Kind of a JSON node.
type Kind int

const (
	KNull Kind = iota
	KBool
	KNumber
	KString
	KArray
	KObject
)

func (k Kind) String() string {
	return [...]string{"null", "boolean", "number", "string", "array", "object"}[k]
}

// Node is an ordered JSON value: object keys keep their input order (and duplicates), numbers
// keep their exact literal ("1.0", "1e5", big integers), so a round trip changes nothing but the
// values we redact and the whitespace.
type Node struct {
	Kind Kind
	Bool bool
	Num  string // number literal
	Str  string
	Arr  []*Node
	Keys []string
	Vals []*Node
}

// Parse decodes one JSON document into an ordered tree.
func Parse(s string) (*Node, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	n, err := parseValue(dec)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid JSON: unexpected data after the end of the document")
	}
	return n, nil
}

func parseValue(dec *json.Decoder) (*Node, error) {
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("unexpected end of input")
		}
		return nil, err
	}
	switch t := tok.(type) {
	case nil:
		return &Node{Kind: KNull}, nil
	case bool:
		return &Node{Kind: KBool, Bool: t}, nil
	case json.Number:
		return &Node{Kind: KNumber, Num: t.String()}, nil
	case string:
		return &Node{Kind: KString, Str: t}, nil
	case json.Delim:
		switch t {
		case '[':
			n := &Node{Kind: KArray, Arr: []*Node{}}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				n.Arr = append(n.Arr, v)
			}
			if _, err := dec.Token(); err != nil { // ]
				return nil, err
			}
			return n, nil
		case '{':
			n := &Node{Kind: KObject, Keys: []string{}, Vals: []*Node{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("expected object key, got %v", kt)
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				n.Keys = append(n.Keys, k)
				n.Vals = append(n.Vals, v)
			}
			if _, err := dec.Token(); err != nil { // }
				return nil, err
			}
			return n, nil
		}
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
}

// Pretty encodes the tree like JSON.stringify(v, null, 2).
func Pretty(n *Node) string {
	var b strings.Builder
	writeNode(&b, n, 0)
	return b.String()
}

func writeNode(b *strings.Builder, n *Node, depth int) {
	switch n.Kind {
	case KArray:
		if len(n.Arr) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, v := range n.Arr {
			indent(b, depth+1)
			writeNode(b, v, depth+1)
			if i < len(n.Arr)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		indent(b, depth)
		b.WriteByte(']')
	case KObject:
		if len(n.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range n.Keys {
			indent(b, depth+1)
			b.WriteString(quote(k))
			b.WriteString(": ")
			writeNode(b, n.Vals[i], depth+1)
			if i < len(n.Keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		indent(b, depth)
		b.WriteByte('}')
	default:
		b.WriteString(Literal(n))
	}
}

func indent(b *strings.Builder, depth int) {
	for i := 0; i < depth; i++ {
		b.WriteString("  ")
	}
}

// Literal is the JSON text of a leaf (strings quoted).
func Literal(n *Node) string {
	switch n.Kind {
	case KNull:
		return "null"
	case KBool:
		if n.Bool {
			return "true"
		}
		return "false"
	case KNumber:
		return n.Num
	case KString:
		return quote(n.Str)
	default:
		return Pretty(n)
	}
}

// quote JSON-encodes a string without HTML escaping (<, >, & stay readable).
func quote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

var identRe = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

func childPath(path, key string) string {
	if identRe.MatchString(key) {
		return path + "." + key
	}
	return path + "[" + quote(key) + "]"
}
