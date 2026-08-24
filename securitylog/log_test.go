package securitylog

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestEventIsJSONAndCorrelated(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })

	Event("proxy", "error", "req_test", "response_blocked", "unsafe response", map[string]any{"status": 502})
	line := output.String()
	start := strings.IndexByte(line, '{')
	if start < 0 {
		t.Fatalf("JSON record missing: %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line[start:])), &got); err != nil {
		t.Fatalf("invalid JSON log: %v", err)
	}
	if got["request_id"] != "req_test" || got["event"] != "response_blocked" {
		t.Fatalf("uncorrelated record: %#v", got)
	}
}
