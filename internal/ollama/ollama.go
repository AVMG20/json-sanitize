// Package ollama is a minimal client for the local Ollama server: model lifecycle
// (load/unload/ps) and the PII span detector over /api/chat with a JSON schema.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"json-sanitizer/internal/sanitizer"
)

// Must match between Load and Detect: a different num_ctx makes Ollama reload the model.
// 4096 fits a 2500-char chunk + prompt + answer and keeps RAM around 3 GB.
var options = map[string]any{"temperature": 0, "num_ctx": 4096}

var schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"entities": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{"type": "string"},
					"type": map[string]any{"type": "string", "enum": []string{"PERSON", "EMAIL", "PHONE", "ADDRESS", "POSTCODE", "DOB"}},
				},
				"required": []string{"text", "type"},
			},
		},
	},
	"required": []string{"entities"},
}

type Client struct {
	Host      string
	Model     string
	KeepAlive string // how long Ollama keeps the model in RAM after the last request, e.g. "5m"
	http      *http.Client
	serve     *exec.Cmd
}

func New(host, model, keepAlive string) *Client {
	return &Client{Host: host, Model: model, KeepAlive: keepAlive, http: &http.Client{Timeout: 5 * time.Minute}}
}

// PS is what Ollama currently holds in memory for this model.
type PS struct {
	Loaded    bool   `json:"loaded"`
	SizeBytes int64  `json:"sizeBytes"`
	ExpiresAt string `json:"expiresAt"` // RFC 3339, empty when not loaded
}

func (c *Client) Version(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var v struct{ Version string }
	if err := c.do(ctx, http.MethodGet, "/api/version", nil, &v); err != nil {
		return "", err
	}
	return v.Version, nil
}

// EnsureRunning starts `ollama serve` when nothing is listening. Only a server started here is
// stopped by StopServe.
func (c *Client) EnsureRunning(ctx context.Context) error {
	if _, err := c.Version(ctx); err == nil {
		return nil
	}
	bin, err := exec.LookPath("ollama")
	if err != nil {
		for _, p := range []string{"/usr/local/bin/ollama", "/opt/homebrew/bin/ollama", "/Applications/Ollama.app/Contents/Resources/ollama"} {
			if _, statErr := exec.LookPath(p); statErr == nil {
				bin = p
				break
			}
		}
	}
	if bin == "" {
		return fmt.Errorf("Ollama is not installed (https://ollama.com/download)")
	}
	c.serve = exec.Command(bin, "serve")
	if err := c.serve.Start(); err != nil {
		return fmt.Errorf("start ollama serve: %w", err)
	}
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		if _, err := c.Version(ctx); err == nil {
			return nil
		}
	}
	return fmt.Errorf("Ollama did not start on %s", c.Host)
}

func (c *Client) StopServe() {
	if c.serve != nil && c.serve.Process != nil {
		_ = c.serve.Process.Kill()
		_, _ = c.serve.Process.Wait()
		c.serve = nil
	}
}

func (c *Client) matches(name string) bool {
	return name == c.Model || (!strings.Contains(c.Model, ":") && name == c.Model+":latest")
}

func (c *Client) HasModel(ctx context.Context) (bool, error) {
	var tags struct{ Models []struct{ Name string } }
	if err := c.do(ctx, http.MethodGet, "/api/tags", nil, &tags); err != nil {
		return false, err
	}
	for _, m := range tags.Models {
		if c.matches(m.Name) {
			return true, nil
		}
	}
	return false, nil
}

// Load puts the model in RAM (or resets its idle timer). Ollama unloads it after KeepAlive.
func (c *Client) Load(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/generate", map[string]any{"model": c.Model, "keep_alive": c.KeepAlive, "options": options}, nil)
}

func (c *Client) Unload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/generate", map[string]any{"model": c.Model, "keep_alive": 0}, nil)
}

func (c *Client) PS(ctx context.Context) PS {
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var ps struct {
		Models []struct {
			Name      string `json:"name"`
			Size      int64  `json:"size"`
			ExpiresAt string `json:"expires_at"`
		}
	}
	if err := c.do(ctx, http.MethodGet, "/api/ps", nil, &ps); err != nil {
		return PS{}
	}
	for _, m := range ps.Models {
		if c.matches(m.Name) {
			return PS{Loaded: true, SizeBytes: m.Size, ExpiresAt: m.ExpiresAt}
		}
	}
	return PS{}
}

// Detector returns a sanitizer.Detector bound to ctx that asks the model for PII spans.
func (c *Client) Detector(ctx context.Context) sanitizer.Detector {
	return func(items []sanitizer.DetectItem) ([]sanitizer.Entity, error) {
		user, _ := json.Marshal(items)
		var resp struct {
			Message struct{ Content string } `json:"message"`
		}
		err := c.do(ctx, http.MethodPost, "/api/chat", map[string]any{
			"model":      c.Model,
			"stream":     false,
			"think":      false,
			"keep_alive": c.KeepAlive,
			"format":     schema,
			"options":    options,
			"messages": []map[string]string{
				{"role": "system", "content": sanitizer.SystemPrompt},
				{"role": "user", "content": string(user)},
			},
		}, &resp)
		if err != nil {
			return nil, err
		}
		var out struct{ Entities []sanitizer.Entity }
		if err := json.Unmarshal([]byte(resp.Message.Content), &out); err != nil {
			return nil, fmt.Errorf("model returned invalid JSON: %.200s", resp.Message.Content)
		}
		return out.Entities, nil
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Host+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 500))
		return fmt.Errorf("ollama %s %d: %s", path, res.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}
