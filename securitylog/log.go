// Package securitylog emits privacy-safe, machine-readable security events.
package securitylog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

type record struct {
	Timestamp string         `json:"timestamp"`
	Component string         `json:"component"`
	Level     string         `json:"level"`
	RequestID string         `json:"request_id,omitempty"`
	Event     string         `json:"event"`
	Message   string         `json:"message,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func NewRequestID() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return "req_" + hex.EncodeToString(buf[:])
	}
	return fmt.Sprintf("req_%x", time.Now().UnixNano())
}

// Event writes one JSON object. Callers must only pass privacy-safe metadata;
// request/response bodies, credentials, hashes, and authentication headers are
// intentionally unsupported by the API.
func Event(component, level, requestID, event, message string, fields map[string]any) {
	payload, err := json.Marshal(record{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Component: component,
		Level:     level,
		RequestID: requestID,
		Event:     event,
		Message:   message,
		Fields:    fields,
	})
	if err != nil {
		log.Printf("[%s][error] structured log encoding failed: %v", component, err)
		return
	}
	log.Print(string(payload))
}
