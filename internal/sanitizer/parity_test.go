package sanitizer

import (
	"encoding/json"
	"os"
	"testing"
)

// testdata/cases.json holds 25 realistic payloads (Magento orders, webhooks, CRM notes, delivery
// address blocks, …) with the personal data each one contains (`pii`) and values that must
// survive (`keep`), plus reference outputs produced by the original TypeScript implementation:
// rules only, and with a fixed fake detector (so the LLM-side filtering is compared exactly).
type benchCase struct {
	ID           string   `json:"id"`
	Input        string   `json:"input"`
	PII          []Entity `json:"pii"`
	Keep         []string `json:"keep"`
	Fake         []Entity `json:"fake"`
	RulesOutput  string   `json:"rulesOutput"`
	RulesChanges int      `json:"rulesChanges"`
	FakeOutput   string   `json:"fakeOutput"`
	FakeChanges  int      `json:"fakeChanges"`
}

func loadCases(t *testing.T) []benchCase {
	t.Helper()
	b, err := os.ReadFile("testdata/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cs []benchCase
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestParityWithReference(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			r, err := Sanitize(c.Input, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Valid || r.Output != c.RulesOutput || len(r.Changes) != c.RulesChanges {
				t.Errorf("rules only: valid=%v changes=%d want %d\n--- got\n%s\n--- want\n%s", r.Valid, len(r.Changes), c.RulesChanges, r.Output, c.RulesOutput)
			}
			fake := c.Fake
			r, err = Sanitize(c.Input, func([]DetectItem) ([]Entity, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if !r.Valid || r.Output != c.FakeOutput || len(r.Changes) != c.FakeChanges {
				t.Errorf("fake detector: valid=%v changes=%d want %d\n--- got\n%s\n--- want\n%s", r.Valid, len(r.Changes), c.FakeChanges, r.Output, c.FakeOutput)
			}
		})
	}
}
