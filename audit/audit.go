// Package audit provides a bounded, local-only privacy trace for protected
// requests. Records intentionally contain metadata only: raw request bodies,
// secret values, and secret hashes are never retained.
package audit

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Detection describes one value replaced before a request left the machine.
type Detection struct {
	SecretType        string `json:"secret_type"`
	PlaceholderID     string `json:"placeholder_id"`
	OriginalPrevented bool   `json:"original_prevented"`
}

// Trace is the privacy-safe record of one request/response exchange.
type Trace struct {
	RequestID            string      `json:"request_id"`
	Timestamp            time.Time   `json:"timestamp"`
	Method               string      `json:"method"`
	Path                 string      `json:"path"`
	ProxyLatencyMS       float64     `json:"proxy_latency_ms"`
	UpstreamStatus       int         `json:"upstream_status,omitempty"`
	Streaming            bool        `json:"streaming"`
	StreamingRestoration string      `json:"streaming_restoration"`
	RestoredItems        int         `json:"restored_items"`
	ResponseLeakBlocked  bool        `json:"response_leak_blocked"`
	Detections           []Detection `json:"detections"`
}

// Store retains only the newest limit traces in memory.
type Store struct {
	mu     sync.RWMutex
	limit  int
	traces []Trace
}

// NewStore creates a bounded trace store. Non-positive limits retain nothing.
func NewStore(limit int) *Store {
	return &Store{limit: limit}
}

// Add appends a trace and evicts the oldest entry when the store is full.
func (s *Store) Add(trace Trace) {
	if s == nil || s.limit <= 0 {
		return
	}
	trace.Detections = append([]Detection(nil), trace.Detections...)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.traces) == s.limit {
		copy(s.traces, s.traces[1:])
		s.traces[len(s.traces)-1] = trace
		return
	}
	s.traces = append(s.traces, trace)
}

// List returns a snapshot ordered newest first.
func (s *Store) List() []Trace {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Trace, len(s.traces))
	for i := range s.traces {
		trace := s.traces[len(s.traces)-1-i]
		trace.Detections = append([]Detection(nil), trace.Detections...)
		out[i] = trace
	}
	return out
}

// Handler exposes the local trace as JSON. Callers must wrap it in a
// loopback-only middleware; the package stays transport-policy agnostic.
func (s *Store) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(struct {
			Retention int     `json:"retention_limit"`
			Traces    []Trace `json:"traces"`
		}{Retention: s.limit, Traces: s.List()})
	}
}
