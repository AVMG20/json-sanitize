package sanitizer

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func mustSanitize(t *testing.T, in string, d Detector) Result {
	t.Helper()
	r, err := Sanitize(in, d)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid {
		t.Fatalf("structure changed: %v", r.Diffs)
	}
	return r
}

func TestOrderRulesAndRegex(t *testing.T) {
	r := mustSanitize(t, `{
  "increment_id": "000001234",
  "created_at": "2024-03-01 12:30:00",
  "customer_email": "jan.devries@example.nl",
  "customer_firstname": "Jan",
  "customer_lastname": "de Vries",
  "remote_ip": "84.12.33.201",
  "grand_total": 59.950,
  "billing_address": {"street": ["Kerkstraat 12"], "postcode": "1012 AB", "city": "Amsterdam", "telephone": 612345678},
  "items": [{"name": "Blue Shirt", "sku": "blue-shirt-m", "qty": 1}],
  "comment": "Bel Jan de Vries op +31 6 12345678 of mail jan.devries@example.nl. IBAN NL91ABNA0417164300.",
  "notes": null
}`, nil)
	want := `{
  "increment_id": "000001234",
  "created_at": "2024-03-01 12:30:00",
  "customer_email": "[EMAIL_1]",
  "customer_firstname": "[PERSON_1]",
  "customer_lastname": "[PERSON_2]",
  "remote_ip": "[IP_1]",
  "grand_total": 59.950,
  "billing_address": {
    "street": [
      "[ADDRESS_1]"
    ],
    "postcode": "[POSTCODE_1]",
    "city": "Amsterdam",
    "telephone": 0
  },
  "items": [
    {
      "name": "Blue Shirt",
      "sku": "blue-shirt-m",
      "qty": 1
    }
  ],
  "comment": "Bel [PERSON_1] [PERSON_2] op [PHONE_1] of mail [EMAIL_1]. IBAN [IBAN_1].",
  "notes": null
}`
	if r.Output != want {
		t.Errorf("got\n%s", r.Output)
	}
}

func TestAddressBlockAndIDsPreserved(t *testing.T) {
	r := mustSanitize(t, `{"tracking_url":"https://track.routelogic.io/tr/3EBFY1OeGRk6","id":"dlv_1",
"recipient":{"name":"Thijs Verbeek"},
"address":{"street":"Schutterweg 81","house_number":"","postal_code":"1033XW","city":"Amsterdam","latitude":52.418155,
"full_address_line":"Schutterweg 81, 1033XW, Amsterdam","country":{"iso_code":"NL"}},
"note":"Thijs woont op Schutterweg 81."}`, nil)
	for _, s := range []string{`"https://track.routelogic.io/tr/3EBFY1OeGRk6"`, `"dlv_1"`, `"name": "[PERSON_1]"`, `"street": "[ADDRESS_1]"`,
		`"house_number": ""`, `"postal_code": "[POSTCODE_1]"`, `"city": "Amsterdam"`, `"latitude": 0`, `"full_address_line": "[ADDRESS_2]"`,
		`"note": "[PERSON_2] woont op [ADDRESS_1]."`} {
		if !strings.Contains(r.Output, s) {
			t.Errorf("missing %s in\n%s", s, r.Output)
		}
	}
}

func TestDetectorWholeWordAndUnmatched(t *testing.T) {
	var seen []string
	r := mustSanitize(t, `{"a":"Bel Jan de Vries","b":"Jan zegt hoi in January","sku":"abc-123","t":"2024-01-01","u":"https://x.nl/Jan"}`,
		func(items []DetectItem) ([]Entity, error) {
			for _, it := range items {
				seen = append(seen, it.Value)
			}
			return []Entity{{"Jan de Vries", "PERSON"}, {"Jan", "PERSON"}, {"Not In Input", "PERSON"}, {"3EBFY1OeGRk6", "PERSON"}}, nil
		})
	want := "{\n  \"a\": \"Bel [PERSON_1]\",\n  \"b\": \"[PERSON_2] zegt hoi in January\",\n  \"sku\": \"abc-123\",\n  \"t\": \"2024-01-01\",\n  \"u\": \"https://x.nl/Jan\"\n}"
	if r.Output != want {
		t.Errorf("got\n%s", r.Output)
	}
	if !reflect.DeepEqual(r.Unmatched, []string{"Not In Input"}) {
		t.Errorf("unmatched %v", r.Unmatched)
	}
	if !reflect.DeepEqual(seen, []string{"Bel Jan de Vries", "Jan zegt hoi in January"}) {
		t.Errorf("sent to detector: %v (ids, dates, urls must not be sent)", seen)
	}
}

func TestDetectorErrorAborts(t *testing.T) {
	_, err := Sanitize(`{"a":"Hello World"}`, func([]DetectItem) ([]Entity, error) { return nil, errors.New("boom") })
	if err == nil || err.Error() != "boom" {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestInvalidJSON(t *testing.T) {
	for _, in := range []string{``, `{`, `{"a":1}x`, `{"a":}`} {
		if _, err := Sanitize(in, nil); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestPrimitivesAndOddKeys(t *testing.T) {
	cases := map[string]string{
		`["a@b.co", 1, null]`:                    "[\n  \"[EMAIL_1]\",\n  1,\n  null\n]",
		`"call 0612345678"`:                      `"call [PHONE_1]"`,
		`42`:                                     `42`,
		`{"__proto__":{"email":"x@y.nl"}}`:       "{\n  \"__proto__\": {\n    \"email\": \"[EMAIL_1]\"\n  }\n}",
		`{"html":"<b>&</b>","e":{},"a":[]}`:      "{\n  \"html\": \"<b>&</b>\",\n  \"e\": {},\n  \"a\": []\n}",
		`{"big":12345678901234567890,"f":1.0e5}`: "{\n  \"big\": 12345678901234567890,\n  \"f\": 1.0e5\n}",
	}
	for in, want := range cases {
		if r := mustSanitize(t, in, nil); r.Output != want {
			t.Errorf("%s → %s, want %s", in, r.Output, want)
		}
	}
}

func TestKeyRuleType(t *testing.T) {
	cases := []struct{ key, parent, want string }{
		{"customer_email", "", Email}, {"email_sent", "", ""}, {"emailAddress", "", Email}, {"ip_address", "", IP},
		{"zip", "", Postcode}, {"name", "", ""}, {"product_name", "", ""}, {"shippingName", "", Person},
		{"address_type", "", ""}, {"hotel", "", ""}, {"phone_number", "", Phone}, {"first_name", "", Person},
		{"lastname", "", Person}, {"house_number_extension", "", Address}, {"full_address_line", "", Address},
		{"postal_code", "", Postcode}, {"latitude", "", Address}, {"telefoonnummer", "", Phone}, {"achternaam", "", Person},
		{"Straße", "", Address}, {"PLZ", "", Postcode}, {"username", "", ""}, {"customer_id", "", ""},
		{"name", "customer", Person}, {"name", "followers", Person}, {"name", "project", ""},
	}
	for _, c := range cases {
		if got := KeyRuleType(c.key, c.parent); got != c.want {
			t.Errorf("KeyRuleType(%q, %q) = %q, want %q", c.key, c.parent, got, c.want)
		}
	}
}

func TestRegexKeepsIDs(t *testing.T) {
	tag := func(typ, _ string) string { return "[" + typ + "]" }
	for _, s := range []string{"01-12-2024", "order 000001234", "NL00ABNA0417164301", "4111111111111112", "4111111111111111",
		"https://track.routelogic.io/tr/3EBFY1OeGRk6", "v0612345678.5"} {
		if got := redactPatterns(s, tag); got != s {
			t.Errorf("%q changed to %q", s, got)
		}
	}
	for in, want := range map[string]string{
		"card 4111 1111 1111 1111": "card [CARD]", "020-1234567": "[PHONE]", "bel 06-55501234.": "bel [PHONE].",
		"+31(0)20 123 4567": "[PHONE]", "Kerkstraat 12a, 1012 AB": "[ADDRESS], [POSTCODE]", "221B Baker Street": "[ADDRESS]",
	} {
		if got := redactPatterns(in, tag); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestFilterDetected(t *testing.T) {
	got := filterDetected([]Entity{
		{"3EBFY1OeGRk6", "PERSON"}, {"TCK-8841", "ADDRESS"}, {"https://track.routelogic.io/tr/3EBFY1OeGRk6", "ADDRESS"},
		{"Utrecht", "ADDRESS"}, {"Tulip Trading BV", "PERSON"}, {"Hosting plan Business", "PERSON"}, {"Rotterdam", "PERSON"},
		{"Something", "ID"}, {"Dorpsweg 5", "ADDRESS"}, {"Dhr. J. de Boer", "PERSON"}, {"1033XW", "POSTCODE"},
		{"3SABCD123456789", "PHONE"}, {"Domain example.nl renewal", "EMAIL"},
	}, map[string]bool{"Rotterdam": true})
	var texts []string
	for _, e := range got {
		texts = append(texts, e.Text)
	}
	sort.Strings(texts)
	if want := []string{"1033XW", "Dhr. J. de Boer", "Dorpsweg 5"}; !reflect.DeepEqual(texts, want) {
		t.Errorf("got %v, want %v", texts, want)
	}
}

func TestNameParts(t *testing.T) {
	var texts []string
	for _, e := range namePartsOf([]Entity{{"Jan van der Berg", Person}}) {
		texts = append(texts, e.Text)
	}
	sort.Strings(texts)
	if want := []string{"Berg", "Jan", "van der Berg"}; !reflect.DeepEqual(texts, want) {
		t.Errorf("got %v", texts)
	}
}

func TestDiffTrees(t *testing.T) {
	parse := func(s string) *Node { n, _ := Parse(s); return n }
	cases := []struct {
		a, b string
		want []string
	}{
		{`{"a":1,"b":[1,2]}`, `{"a":"1","b":[1]}`, []string{"$.a: type changed number → string", "$.b: array length 2 → 1"}},
		{`{"a":1,"b":2}`, `{"b":2,"a":1}`, []string{"$: key order changed"}},
		{`{"a":1}`, `{"a":1,"c":2}`, []string{"$.c: key added"}},
		{`{"a":true}`, `{"a":false}`, []string{"$.a: boolean value changed"}},
	}
	for _, c := range cases {
		if diffs, _ := DiffTrees(parse(c.a), parse(c.b), reasons{}); !reflect.DeepEqual(diffs, c.want) {
			t.Errorf("%s vs %s: %v", c.a, c.b, diffs)
		}
	}
}
