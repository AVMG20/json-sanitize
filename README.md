# JSON Sanitizer

A small macOS utility that strips personal data — names, addresses, emails, phone numbers, birth
dates, IPs, IBANs — from JSON, locally, using [Qwen3-4B](https://ollama.com/library/qwen3) via
Ollama. Paste JSON, hit **Sanitize** (⌘↵), and the editor content is replaced with the sanitized
version. The **Changes** tab lists every value that changed and why.

IDs, codes, tokens, tracking numbers and URLs are always preserved, and the output is checked to
have exactly the input's structure (same keys, key order, types and array lengths) before it is
shown. Nothing leaves your machine.

## Requirements

- macOS, [Ollama](https://ollama.com/download) and the model: `ollama pull qwen3:4b`
  (2.5 GB on disk, ~3 GB RAM while loaded)
- To build: Go 1.24+, Node/npm, and the Wails CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

## Build & run

```bash
wails build                      # → build/bin/JSON Sanitizer.app
ditto "build/bin/JSON Sanitizer.app" "/Applications/JSON Sanitizer.app"
wails dev                        # hot reload while developing
go test ./internal/...           # unit + parity tests (no model needed)
OLLAMA_IT=1 go test ./internal/ollama -run Qwen -v   # accuracy against the real model
```

## How it works

Only leaf values change, so the JSON structure can't drift:

1. **Key rules** — values under keys like `email`, `phone_number`, `first_name`, `achternaam`,
   `Straße`, `postal_code`, `latitude` are replaced outright (English/Dutch/German, any casing).
   A bare `name` only when the parent looks like a person (`customer.name`), not `items[].name`.
2. **Regex** — emails, phones, IPs, IBANs (checksum), grouped card numbers (Luhn), NL postcodes,
   streets with a house number.
3. **Known values** — names/addresses found in step 1 are also replaced in free text.
4. **Qwen** — lists remaining names and addresses as spans (structured output); the code filters
   out IDs, URLs, cities and companies, then replaces them, plus first/last names on their own.
   The model never rewrites the JSON itself.

The same value gets the same placeholder (`[PERSON_1]`) throughout the document. Key order and
number literals are preserved exactly.

On the 25 test payloads in `internal/sanitizer/testdata/cases.json` this catches 100% of the
personal data and leaves 98% of the other values untouched.

## Model lifecycle

The model loads when you paste, click **Load**, or sanitize. Ollama unloads it 30 seconds after the last use;
the header shows its state, RAM use and countdown. Quitting the app unloads it immediately.

| env            | default                  |
|----------------|--------------------------|
| `MODEL`        | `qwen3:4b`               |
| `IDLE_SECONDS` | `30`                     |
| `OLLAMA_HOST`  | `http://127.0.0.1:11434` |

## Layout

```
main.go, app.go           Wails entry point and the bound App (Sanitize, Status, Load, Unload)
internal/sanitizer        pure sanitizer: ordered JSON, rules, regex, filters, structure check
internal/ollama           Ollama client: lifecycle + span detector (/api/chat with JSON schema)
frontend/                 vanilla JS + Vite UI
build/appicon.svg         app icon source (appicon.png is the rendered 1024px version)
```
