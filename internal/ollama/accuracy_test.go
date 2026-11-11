package ollama

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"json-sanitizer/internal/sanitizer"
)

// TestQwenAccuracy runs the real model over the 25 test payloads and reports recall (personal
// data removed) and keep-rate (other values untouched). Needs a running Ollama with qwen3:4b:
//
//	OLLAMA_IT=1 go test ./internal/ollama -run Qwen -v
func TestQwenAccuracy(t *testing.T) {
	if os.Getenv("OLLAMA_IT") == "" {
		t.Skip("set OLLAMA_IT=1 to run against the local Ollama")
	}
	b, err := os.ReadFile("../sanitizer/testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID    string             `json:"id"`
		Input string             `json:"input"`
		PII   []sanitizer.Entity `json:"pii"`
		Keep  []string           `json:"keep"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}

	model := os.Getenv("MODEL")
	if model == "" {
		model = "qwen3:4b"
	}
	c := New("http://127.0.0.1:11434", model, "1m")
	ctx := context.Background()
	if err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Unload(ctx)

	var caught, total, kept, keepTotal int
	for _, tc := range cases {
		r, err := sanitizer.Sanitize(tc.Input, c.Detector(ctx))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Valid {
			t.Errorf("%s: structure changed: %v", tc.ID, r.Diffs)
			continue
		}
		leaves := leafStrings(r.Output)
		appears := func(s string) bool {
			for _, l := range leaves {
				if strings.Contains(l, s) {
					return true
				}
			}
			return false
		}
		var missed, over []string
		for _, p := range tc.PII {
			if appears(p.Text) {
				missed = append(missed, p.Text)
			} else {
				caught++
			}
		}
		for _, k := range tc.Keep {
			if appears(k) {
				kept++
			} else {
				over = append(over, k)
			}
		}
		total, keepTotal = total+len(tc.PII), keepTotal+len(tc.Keep)
		if len(missed)+len(over) > 0 {
			t.Logf("%-24s missed=%q over=%q", tc.ID, missed, over)
		}
	}
	t.Logf("recall %.1f%% (%d/%d)  keep %.1f%% (%d/%d)",
		100*float64(caught)/float64(total), caught, total, 100*float64(kept)/float64(keepTotal), kept, keepTotal)
}

// leafStrings returns string leaves and number literals of a JSON document.
func leafStrings(doc string) []string {
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch v := tok.(type) {
		case string:
			out = append(out, v) // keys too; harmless for "is this text still there"
		case json.Number:
			out = append(out, v.String())
		}
	}
}
