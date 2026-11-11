package sanitizer

// PII types. Scope is personal data only (names, addresses, contact details); IDs, codes,
// tokens, tracking numbers and URLs are always preserved.
const (
	Person   = "PERSON"
	Email    = "EMAIL"
	Phone    = "PHONE"
	Address  = "ADDRESS"
	Postcode = "POSTCODE"
	DOB      = "DOB"
	IP       = "IP"
	IBAN     = "IBAN"
	Card     = "CARD"
)

var piiTypes = []string{Person, Email, Phone, Address, Postcode, DOB, IP, IBAN, Card}

// Entity is a span of personal data reported by a detector.
type Entity struct {
	Text string `json:"text"`
	Type string `json:"type"`
}

// DetectItem is one string value (with its key as context) sent to the detector.
type DetectItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Detector lists PII spans in a batch of values (the LLM). It never rewrites JSON.
type Detector func(items []DetectItem) ([]Entity, error)

// Change is one leaf value that differs between input and output.
type Change struct {
	Path    string   `json:"path"`
	Before  string   `json:"before"` // JSON literal of the old value
	After   string   `json:"after"`  // JSON literal of the new value
	Reasons []string `json:"reasons"`
}

// Result of Sanitize. Output is pretty-printed JSON (2-space indent) with the input's key
// order and number literals preserved; it is empty when the structure check failed.
type Result struct {
	Output    string         `json:"output"`
	Valid     bool           `json:"valid"`
	Diffs     []string       `json:"diffs"` // structure problems; empty when the shape is identical
	Changes   []Change       `json:"changes"`
	Counts    map[string]int `json:"counts"` // unique values redacted per type
	Chunks    int            `json:"chunks"`
	Entities  int            `json:"entities"`
	Unmatched []string       `json:"unmatched"` // detector spans not found verbatim (ignored)
}
