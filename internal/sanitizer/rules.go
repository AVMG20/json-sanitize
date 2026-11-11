package sanitizer

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

// Key rules. Keys are normalised to lowercase alphanumerics first (`customer_email` →
// `customeremail`, `Straße` → `strasse`). Order matters: `emailaddress` must hit EMAIL before
// ADDRESS. English, Dutch and German variants.
var keyRules = []struct {
	typ string
	re  *regexp.Regexp
}{
	{Email, regexp.MustCompile(`^e?mail$|e?mail(address|adres|adresse)?$`)},
	{IP, regexp.MustCompile(`^(ip|remoteip|remoteaddr|clientip|customerip|xforwardedfor)$|ipaddress$`)},
	{Phone, regexp.MustCompile(`(phone|telephone|mobile|mobilephone|cellphone|fax|gsm|telefoon|telefon|mobiel|handy)(number|nr|nummer)?$|^tel$`)},
	{Postcode, regexp.MustCompile(`(postcode|postalcode|zipcode|zip|plz|postleitzahl)$`)},
	{DOB, regexp.MustCompile(`(dob|birthdate|dateofbirth|birthday|geboortedatum|geburtsdatum)$`)},
	{IBAN, regexp.MustCompile(`(iban|bankaccount|bankaccountnumber|rekeningnummer)$`)},
	{Person, regexp.MustCompile(`^(firstname|lastname|middlename|fullname|surname|givenname|familyname|displayname|nickname|realname|initials|voornaam|achternaam|tussenvoegsel|vorname|nachname)$|(first|last|middle|full|given|family|customer|contact|billing|shipping|account|display)name$|(accountholder|cardholder|author)$`)},
	{Address, regexp.MustCompile(`(street|streetname|streetline\d*|address|addressline\d*|housenumber|housenr|streetnumber|straat|straatnaam|huisnummer|strasse|hausnummer)(extension|addition|suffix|toevoeging|zusatz)?$|^(lat|lng|lon|latitude|longitude)$`)},
}

var (
	// A bare `name`/`naam` is usually a product, store or project — only personal under these parents.
	personParent = regexp.MustCompile(`(customer|contact|user|author|assignee|owner|creator|createdby|updatedby|recipient|sender|person|employee|member|profile|billing|shipping|client|klant|kunde|buyer|requester|reporter|commenter|follower|guest|driver|lead|from|to|cc|bcc)s?$`)
	// Values under these keys are never personal; an LLM hit equal to one of them is dropped.
	safeKey       = regexp.MustCompile(`(city|town|woonplaats|plaats|stadt|ort|country|land|region|state|province|company|companyname|organization|organisation|bedrijf|bedrijfsnaam|firma|store|storename|shop|brand|product|productname|sku|title|label|status|type|method|carrier)$`)
	productParent = regexp.MustCompile(`(item|items|product|products|line|lines|orderitems|project|projects|store|stores|website|websites|category|categories)$`)
	nonAlnum      = regexp.MustCompile(`[^a-z0-9]`)
)

func normKey(key string) string {
	return nonAlnum.ReplaceAllString(strings.ReplaceAll(strings.ToLower(key), "ß", "ss"), "")
}

// KeyRuleType returns the PII type for a value under key (parentKey = key of the object holding
// it), or "" when the key says nothing.
func KeyRuleType(key, parentKey string) string {
	k := normKey(key)
	for _, r := range keyRules {
		if r.re.MatchString(k) {
			return r.typ
		}
	}
	if (k == "name" || k == "naam") && parentKey != "" && personParent.MatchString(normKey(parentKey)) {
		return Person
	}
	return ""
}

func isSafeContext(key, parentKey string) bool {
	if key == "" {
		return false
	}
	k := normKey(key)
	if safeKey.MatchString(k) {
		return true
	}
	return (k == "name" || k == "naam") && parentKey != "" && productParent.MatchString(normKey(parentKey))
}

// --- regex pass ----------------------------------------------------------------------------------
// regexp2 (backtracking, .NET syntax) because these need look-arounds and back-references.

type pattern struct {
	typ   string
	re    *regexp2.Regexp
	check func(string) bool
}

func re2(p string, opts ...regexp2.RegexOptions) *regexp2.Regexp {
	o := regexp2.None
	for _, x := range opts {
		o |= x
	}
	return regexp2.MustCompile(p, o)
}

var datePrefix = regexp.MustCompile(`^\d{2}-\d{2}-\d{4}`)

var patterns = []pattern{
	{Email, re2(`[\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.\p{L}{2,}`), nil},
	{IBAN, re2(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`), ibanValid},
	// Only card numbers written in groups ("4111 1111 1111 1111"): bare digit runs are IDs.
	{Card, re2(`(?<![\d-])\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}(?![\d-])`), luhnValid},
	{IP, re2(`(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])`), nil},
	{IP, re2(`(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])`, regexp2.IgnoreCase), nil},
	{Phone, re2(`(?<![\w+])(?:\+|00)[1-9]\d{0,2}(?:[ .-]?\(0\))?(?:[ .-]?\d){6,12}(?!\w)`), nil},
	{Phone, re2(`(?<![\w+\-/.:])0[1-9](?:[ -]?\d){8}(?![\w\-/:]|\.\d)`), func(m string) bool { return !datePrefix.MatchString(m) }},
	{Postcode, re2(`\b[1-9]\d{3} ?(?!SS|SD|SA)[A-Z]{2}\b`), nil},
	// Street + house number: "Kerkstraat 12a", "Hauptstraße 21", "221B Baker Street"
	{Address, re2(`\b[\p{Lu}][\p{L}'-]*(?:straat|weg|laan|gracht|plein|kade|dijk|singel|steeg|hof|pad|dreef|markt|baan|park|straße|strasse|str\.|gasse|allee|platz|ring|damm)\s+\d{1,5}(?:\s?[a-zA-Z]\b|-\d+)?`), nil},
	{Address, re2(`\b\d{1,5}[A-Za-z]?\s+(?:[\p{Lu}][\p{L}'-]+\s+){1,3}(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane|Ln\.|Drive|Dr\.|Way|Close|Court|Place|Boulevard|Blvd\.)`), nil},
}

type hit struct {
	start, end int // rune offsets
	typ        string
}

// redactPatterns replaces every pattern hit (earliest, then longest wins on overlap).
func redactPatterns(s string, replace func(typ, text string) string) string {
	runes := []rune(s)
	var hits []hit
	for _, p := range patterns {
		m, _ := p.re.FindStringMatch(s)
		for m != nil {
			if p.check == nil || p.check(m.String()) {
				hits = append(hits, hit{m.Index, m.Index + m.Length, p.typ})
			}
			m, _ = p.re.FindNextMatch(m)
		}
	}
	if len(hits) == 0 {
		return s
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start {
			return hits[i].start < hits[j].start
		}
		return hits[i].end-hits[i].start > hits[j].end-hits[j].start
	})
	var b strings.Builder
	pos := 0
	for _, h := range hits {
		if h.start < pos {
			continue // overlaps an earlier, longer hit
		}
		b.WriteString(string(runes[pos:h.start]))
		b.WriteString(replace(h.typ, string(runes[h.start:h.end])))
		pos = h.end
	}
	b.WriteString(string(runes[pos:]))
	return b.String()
}

// --- entities ------------------------------------------------------------------------------------

var (
	placeholderRe = regexp.MustCompile(`\[[A-Z]+_\d+\]`)
	// Segments replaceEntities never touches: placeholders and URLs (they hold IDs and tokens).
	protectedSplit = regexp.MustCompile(`\[[A-Z]+_\d+\]|\bhttps?://[^\s"'<>]+`)
	nameTitles     = regexp.MustCompile(`(?i)^(dhr|mevr|mw|mr|mrs|ms|dr|prof|ing|ir|mr\.|herr|frau)\.?$`)
	companySuffix  = regexp.MustCompile(`(?i)\b(B\.?V\.?|N\.?V\.?|GmbH|Ltd\.?|Inc\.?|LLC|AS|AG|SA|BVBA|VOF|Holding|Group)$`)
	nameParticles  = map[string]bool{"van": true, "de": true, "der": true, "den": true, "het": true, "ter": true, "ten": true, "te": true, "von": true, "zu": true, "vom": true, "la": true, "le": true, "du": true, "da": true, "di": true, "del": true, "'t": true, "in": true, "op": true, "el": true, "al": true, "bin": true, "mc": true, "mac": true, "st.": true}
)

// replaceEntities replaces whole-word occurrences of each entity (longest first, as given),
// never inside a placeholder or URL.
func replaceEntities(s string, entities []Entity, replace func(Entity) string) string {
	out := s
	for _, e := range entities {
		re := re2(`(?<![\p{L}\p{N}])` + regexp2.Escape(e.Text) + `(?![\p{L}\p{N}])`)
		out = mapUnprotected(out, func(part string) string {
			r, err := re.ReplaceFunc(part, func(regexp2.Match) string { return replace(e) }, -1, -1)
			if err != nil {
				return part
			}
			return r
		})
	}
	return out
}

// mapUnprotected applies fn to the text between placeholders/URLs.
func mapUnprotected(s string, fn func(string) string) string {
	locs := protectedSplit.FindAllStringIndex(s, -1)
	if locs == nil {
		return fn(s)
	}
	var b strings.Builder
	pos := 0
	for _, l := range locs {
		b.WriteString(fn(s[pos:l[0]]))
		b.WriteString(s[l[0]:l[1]])
		pos = l[1]
	}
	b.WriteString(fn(s[pos:]))
	return b.String()
}

var llmTypes = map[string]bool{Person: true, Email: true, Phone: true, Address: true, Postcode: true, DOB: true}

var (
	urlish      = regexp.MustCompile(`(?i)https?://|www\.`)
	codeToken   = regexp.MustCompile(`^[\w-]+$`)
	hasDigit    = regexp.MustCompile(`\d`)
	phoneShape  = regexp.MustCompile(`^[+(\d][\d\s().\/-]+$`)
	postalShape = regexp.MustCompile(`^[A-Za-z0-9 -]{4,8}$`)
	nonDigit    = regexp.MustCompile(`\D`)
)

// filterDetected drops LLM hits that aren't personal data: IDs/codes/tokens, URLs, cities or
// companies on their own, lowercase phrases tagged as names, anything equal to a value under a
// city/company/product key, and hits whose text doesn't look like its type. Unique, longest first.
func filterDetected(entities []Entity, safeValues map[string]bool) []Entity {
	seen := map[string]bool{}
	var out []Entity
	for _, raw := range entities {
		e := Entity{Text: strings.TrimSpace(raw.Text), Type: strings.ToUpper(raw.Type)}
		if !llmTypes[e.Type] || utf8.RuneCountInString(e.Text) < 2 || placeholderRe.MatchString(e.Text) || safeValues[e.Text] {
			continue
		}
		if urlish.MatchString(e.Text) {
			continue
		}
		// Codes and IDs: one token mixing digits with letters (3EBFY1OeGRk6, TCK-8841), or digits only.
		if codeToken.MatchString(e.Text) && hasDigit.MatchString(e.Text) && e.Type != Postcode && e.Type != Phone {
			continue
		}
		// Each type must look like itself; models sometimes call an order code a PHONE or POSTCODE.
		switch e.Type {
		case Email:
			if !strings.Contains(e.Text, "@") {
				continue
			}
		case Phone:
			if !phoneShape.MatchString(e.Text) || len(nonDigit.ReplaceAllString(e.Text, "")) < 8 {
				continue
			}
		case Postcode:
			if !postalShape.MatchString(e.Text) || !hasDigit.MatchString(e.Text) {
				continue
			}
		case DOB:
			if !hasDigit.MatchString(e.Text) {
				continue
			}
		case Address:
			if !hasDigit.MatchString(e.Text) && !strings.Contains(e.Text, ",") { // "Utrecht"
				continue
			}
		case Person:
			if !looksLikeName(e.Text) {
				continue
			}
		}
		if !seen[e.Text] {
			seen[e.Text] = true
			out = append(out, e)
		}
	}
	sortLongestFirst(out)
	return out
}

func looksLikeName(s string) bool {
	if hasDigit.MatchString(s) || companySuffix.MatchString(s) {
		return false
	}
	n := 0
	for _, t := range strings.Fields(s) {
		if nameParticles[strings.ToLower(t)] || nameTitles.MatchString(t) {
			continue
		}
		n++
		if r, _ := utf8.DecodeRuneInString(t); !unicode.IsUpper(r) {
			return false
		}
	}
	return n > 0
}

// namePartsOf: "Jan de Vries" → "Jan", "Vries", "de Vries". Skips initials, titles and short parts.
func namePartsOf(entities []Entity) []Entity {
	parts := map[string]bool{}
	var order []string
	add := func(t string) {
		if !parts[t] {
			parts[t] = true
			order = append(order, t)
		}
	}
	full := map[string]bool{}
	for _, e := range entities {
		if e.Type != Person {
			continue
		}
		tokens := strings.Fields(e.Text)
		if len(tokens) < 2 {
			continue
		}
		full[e.Text] = true
		for i, t := range tokens {
			clean := strings.TrimRight(t, ",.")
			if r, _ := utf8.DecodeRuneInString(clean); utf8.RuneCountInString(clean) >= 3 && unicode.IsUpper(r) && !nameTitles.MatchString(clean) {
				add(clean)
			}
			// surname with its particles: "de Vries", "van der Berg"
			if i > 0 && !nameParticles[strings.ToLower(t)] && nameParticles[strings.ToLower(tokens[i-1])] {
				j := i - 1
				for j > 0 && nameParticles[strings.ToLower(tokens[j-1])] {
					j--
				}
				add(strings.Join(tokens[j:i+1], " "))
			}
		}
	}
	var out []Entity
	for _, t := range order {
		if !full[t] {
			out = append(out, Entity{Text: t, Type: Person})
		}
	}
	sortLongestFirst(out)
	return out
}

var numericish = regexp.MustCompile(`^[\d\s.,+-]+$`)

// expandKnown: key-rule values worth finding elsewhere — full values (≥ 3 chars) plus name parts.
func expandKnown(known []Entity) []Entity {
	seen := map[string]bool{}
	var out []Entity
	for _, e := range known {
		if utf8.RuneCountInString(e.Text) < 3 || (numericish.MatchString(e.Text) && e.Type != Phone) {
			continue
		}
		if e.Type == IP || e.Type == DOB { // regex handles these; short dates over-match
			continue
		}
		if nameParticles[strings.ToLower(e.Text)] { // a lone tussenvoegsel like "van"
			continue
		}
		if !seen[e.Text] {
			seen[e.Text] = true
			out = append(out, e)
		}
	}
	for _, p := range namePartsOf(out) {
		if !seen[p.Text] {
			seen[p.Text] = true
			out = append(out, p)
		}
	}
	sortLongestFirst(out)
	return out
}

func sortLongestFirst(es []Entity) {
	sort.SliceStable(es, func(i, j int) bool {
		return utf16Len(es[i].Text) > utf16Len(es[j].Text)
	})
}

// utf16Len matches JS string length so ordering equals the original implementation.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isPlaceholderOnly(s string) bool {
	return strings.TrimSpace(placeholderRe.ReplaceAllString(s, "")) == ""
}

var (
	letterRe   = regexp.MustCompile(`\pL`)
	identLower = regexp.MustCompile(`^[a-z0-9_./:\-]+$`)
	timestamp  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
	hexish     = regexp.MustCompile(`(?i)^[0-9a-f-]{16,}$`)
	bareURL    = regexp.MustCompile(`^https?://\S+$`)
)

// worthAsking skips strings that can't hold a name/address: identifiers, slugs, timestamps,
// hashes, URLs and codes.
func worthAsking(s string) bool {
	rest := strings.TrimSpace(placeholderRe.ReplaceAllString(s, ""))
	if utf8.RuneCountInString(rest) < 2 || !letterRe.MatchString(rest) {
		return false
	}
	if identLower.MatchString(rest) || timestamp.MatchString(rest) || hexish.MatchString(rest) || bareURL.MatchString(rest) {
		return false
	}
	if codeToken.MatchString(rest) && hasDigit.MatchString(rest) {
		return false
	}
	return true
}

// chunk batches detector items by their JSON size.
func chunk(items []DetectItem, maxChars int) [][]DetectItem {
	var out [][]DetectItem
	var cur []DetectItem
	size := 0
	for _, it := range items {
		b, _ := json.Marshal(it)
		if len(cur) > 0 && size+len(b) > maxChars {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, it)
		size += len(b)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func ibanValid(m string) bool {
	s := strings.ReplaceAll(m, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rem := 0
	for _, ch := range s[4:] + s[:4] {
		var v string
		if ch >= '0' && ch <= '9' {
			v = string(ch)
		} else {
			v = itoa(int(ch) - 55)
		}
		for _, d := range v {
			rem = (rem*10 + int(d-'0')) % 97
		}
	}
	return rem == 1
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

func luhnValid(m string) bool {
	d := nonDigit.ReplaceAllString(m, "")
	if len(d) < 13 || len(d) > 19 || strings.Count(d, d[:1]) == len(d) {
		return false
	}
	sum := 0
	for i := 0; i < len(d); i++ {
		n := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}
