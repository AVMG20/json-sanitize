package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"json-sanitizer/internal/ollama"
	"json-sanitizer/internal/sanitizer"
)

// App is bound to the frontend. Ollama owns the model's idle timer: every Load/Sanitize passes
// keep_alive, and Ollama frees the RAM once it runs out. Status just reports /api/ps.
type App struct {
	ctx         context.Context
	llm         *ollama.Client
	idleMinutes int

	mu        sync.Mutex
	ready     bool   // Ollama reachable and model pulled
	setupErr  string // why not ready
	loading   bool
	loadGroup *sync.WaitGroup
}

func NewApp() *App {
	idle := 5
	if v, err := strconv.Atoi(os.Getenv("IDLE_MINUTES")); err == nil && v > 0 {
		idle = v
	}
	host := envOr("OLLAMA_HOST", "http://127.0.0.1:11434")
	model := envOr("MODEL", "qwen3:4b")
	return &App{llm: ollama.New(host, model, fmt.Sprintf("%dm", idle)), idleMinutes: idle}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.boot()
}

// shutdown frees the model's RAM right away instead of waiting for the idle timeout.
func (a *App) shutdown(ctx context.Context) {
	if a.isReady() {
		uctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = a.llm.Unload(uctx)
		cancel()
	}
	a.llm.StopServe()
}

func (a *App) boot() {
	err := a.llm.EnsureRunning(a.ctx)
	if err == nil {
		var ok bool
		ok, err = a.llm.HasModel(a.ctx)
		if err == nil && !ok {
			err = fmt.Errorf("model %s not found — run: ollama pull %s", a.llm.Model, a.llm.Model)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.setupErr = err.Error()
		return
	}
	a.ready = true
}

func (a *App) isReady() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ready
}

// ModelStatus is polled by the header.
type ModelStatus struct {
	Model string `json:"model"`
	// starting | unavailable | unloaded | loading | loaded
	State       string `json:"state"`
	Error       string `json:"error"`
	SizeBytes   int64  `json:"sizeBytes"`
	ExpiresAt   string `json:"expiresAt"`
	IdleMinutes int    `json:"idleMinutes"`
}

func (a *App) Status() ModelStatus {
	a.mu.Lock()
	ready, setupErr, loading := a.ready, a.setupErr, a.loading
	a.mu.Unlock()

	s := ModelStatus{Model: a.llm.Model, IdleMinutes: a.idleMinutes, Error: setupErr}
	switch {
	case !ready && setupErr != "":
		s.State = "unavailable"
	case !ready:
		s.State = "starting"
	case loading:
		s.State = "loading"
	default:
		ps := a.llm.PS(a.ctx)
		s.SizeBytes, s.ExpiresAt = ps.SizeBytes, ps.ExpiresAt
		if ps.Loaded {
			s.State = "loaded"
		} else {
			s.State = "unloaded"
		}
	}
	return s
}

// Load puts the model in RAM (or resets its idle timer). Concurrent callers share one load.
func (a *App) Load() error {
	a.mu.Lock()
	if !a.ready && a.setupErr != "" {
		// Retry: Ollama may have been started or the model pulled since launch.
		a.setupErr = ""
		a.mu.Unlock()
		a.boot()
		a.mu.Lock()
	}
	if !a.ready {
		defer a.mu.Unlock()
		return a.notReady()
	}
	if a.loading {
		wg := a.loadGroup
		a.mu.Unlock()
		wg.Wait()
		return nil
	}
	a.loading = true
	wg := &sync.WaitGroup{}
	wg.Add(1)
	a.loadGroup = wg
	a.mu.Unlock()

	err := a.llm.Load(a.ctx)

	a.mu.Lock()
	a.loading = false
	a.mu.Unlock()
	wg.Done()
	return err
}

func (a *App) Unload() error {
	if !a.isReady() {
		return nil
	}
	return a.llm.Unload(a.ctx)
}

func (a *App) notReady() error {
	if a.setupErr != "" {
		return fmt.Errorf("%s", a.setupErr)
	}
	return fmt.Errorf("Ollama is still starting")
}

// SanitizeResponse is a sanitizer.Result plus timing.
type SanitizeResponse struct {
	sanitizer.Result
	Ms int64 `json:"ms"`
}

// Sanitize redacts personal data from a JSON document using key rules, regex and Qwen.
// The output has exactly the input's structure; if the check fails, Output is empty.
// Errors (invalid JSON, model unavailable) never return a half-sanitized document.
func (a *App) Sanitize(input string) (SanitizeResponse, error) {
	start := time.Now()
	if err := a.Load(); err != nil {
		return SanitizeResponse{}, err
	}
	res, err := sanitizer.Sanitize(input, a.llm.Detector(a.ctx))
	if err != nil {
		return SanitizeResponse{}, err
	}
	return SanitizeResponse{Result: res, Ms: time.Since(start).Milliseconds()}, nil
}
