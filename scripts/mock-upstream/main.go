// mock-upstream is a tiny stand-in for an AI provider used by the headless
// E2E test and Codex / Claude Code experiments. It logs every incoming
// request body to stderr (so the caller can assert the firewall masked
// secrets before forwarding) and echoes the received body inside an
// Anthropic- or OpenAI-shaped response, so the caller can also assert the
// client received the original secret back after unmasking.
//
// Run:    go run scripts/mock-upstream --port 19999
// Health: GET /ping
// Echo:   POST * (anything else). Detects OpenAI vs Anthropic by path.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	port := flag.String("port", "19999", "listen port")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ping":"ok"}`))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		log.Printf("REQ  %s %s", r.Method, r.URL.Path)
		log.Printf("HDR  x-api-key=%q anthropic-version=%q authorization=%q",
			r.Header.Get("x-api-key"),
			r.Header.Get("anthropic-version"),
			r.Header.Get("Authorization"))
		log.Printf("BODY %s", string(body))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respond(r.URL.Path, string(body))))
	})

	addr := "127.0.0.1:" + *port
	log.SetOutput(os.Stderr)
	log.Printf("mock-upstream listening on http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// respond returns an OpenAI-shaped response for /v1/chat/completions and
// an Anthropic-shaped response for /v1/messages. For anything else it
// returns a tiny generic JSON. The body is echoed inside the assistant
// message so a client can verify round-trip unmasking.
func respond(path, body string) string {
	jsonEsc := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch r {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	echo := "echo: " + jsonEsc(body)

	switch {
	case strings.HasPrefix(path, "/v1/chat/completions"):
		// OpenAI chat completion shape
		return `{"id":"mock","object":"chat.completion","created":` +
			time.Now().Format("1136214245") +
			`,"model":"mock","choices":[{"index":0,"message":{"role":"assistant","content":"` +
			echo + `"},"finish_reason":"stop"}]}`
	case strings.HasPrefix(path, "/v1/messages"):
		// Anthropic messages shape
		return `{"id":"mock","type":"message","role":"assistant","content":[{"type":"text","text":"` +
			echo + `"}],"model":"claude-3-5-haiku-20241022","stop_reason":"end_turn"}`
	default:
		return `{"echo":` + `"` + echo + `"}`
	}
}
