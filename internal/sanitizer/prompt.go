package sanitizer

// SystemPrompt for the LLM pass. The model never rewrites JSON: it only lists PII spans,
// and the code replaces them, so the structure can't drift.
const SystemPrompt = `You find personal data about private individuals in values taken from a JSON document.

Input: a JSON array of {"key", "value"} items. "key" is context only; inspect "value".
Output: {"entities": [{"text": "...", "type": "..."}]} with every personal-data span found.

Types:
- PERSON: names of people (full, first or last name, initials with surname)
- ADDRESS: street with house number, or a full postal address
- POSTCODE
- EMAIL, PHONE
- DOB: dates of birth

Rules:
- "text" must be copied exactly, character for character, from a value.
- Check every item. A value that is just a name (e.g. key "author": "Maria Jansen") counts.
- List every form that appears: "Pieter Bakker" and later "Pieter" are two entities.
- Never list IDs, codes, tokens, tracking or order numbers, SKUs, URLs or dates other than birth dates.
- Never list companies, brands, products, shops, job titles, or cities and countries on their own.
- Ignore placeholders such as [PERSON_1]; they are already redacted.
- Nothing found: return {"entities": []}.`
