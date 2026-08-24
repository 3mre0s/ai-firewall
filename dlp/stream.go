package dlp

import (
	"log"
	"strings"

	"github.com/3mre0s/ai-firewall/masker"
)

const (
	MaxStreamBufferBytes  = 512 * 1024
	StreamInspectionBytes = 64 * 1024
	credentialTailBytes   = 512
)

// StreamProcessor restores placeholders while retaining enough state to
// detect labels and raw credentials split across arbitrary network reads.
type StreamProcessor struct {
	masker         *masker.Masker
	buf            strings.Builder
	leakDetected   bool
	inspectionTail string // exact request-owned values retain the full 64 KiB window
	credentialTail string // format-specific credentials need only a short prefix window
	restored       int
}

func NewStreamProcessor(m *masker.Masker) *StreamProcessor {
	return &StreamProcessor{masker: m}
}

func (sp *StreamProcessor) LeakDetected() bool { return sp.leakDetected }
func (sp *StreamProcessor) RestoredCount() int { return sp.restored }

func (sp *StreamProcessor) Process(chunk []byte) string {
	sp.buf.Write(chunk)
	if sp.buf.Len() > MaxStreamBufferBytes {
		content := sp.buf.String()
		sp.buf.Reset()
		if !sp.inspectAndRemember(content) {
			log.Printf("[stream][error] secret detected in stream output — terminating")
			return ""
		}
		unmasked, restored := sp.masker.UnmaskWithCount(content)
		sp.restored += restored
		return unmasked
	}

	current := sp.buf.String()
	cutpoint := SafeCutpoint(current)
	if cutpoint == 0 {
		return ""
	}
	safe, tail := current[:cutpoint], current[cutpoint:]
	sp.buf.Reset()
	sp.buf.WriteString(tail)
	if !sp.inspectAndRemember(safe) {
		log.Printf("[stream][error] secret detected in stream output — terminating")
		return ""
	}
	unmasked, restored := sp.masker.UnmaskWithCount(safe)
	sp.restored += restored
	return unmasked
}

func (sp *StreamProcessor) Flush() string {
	remaining := sp.buf.String()
	sp.buf.Reset()
	if remaining == "" {
		return ""
	}
	if !sp.inspectAndRemember(remaining) {
		log.Printf("[stream][error] secret detected in stream tail — terminating")
		return ""
	}
	unmasked, restored := sp.masker.UnmaskWithCount(remaining)
	sp.restored += restored
	return unmasked
}

func (sp *StreamProcessor) inspectAndRemember(raw string) bool {
	credentialWindow := sp.credentialTail + raw
	if sp.masker.HasCredentialSecrets(credentialWindow) ||
		containsPrivateKeyStart(credentialWindow) {
		sp.leakDetected = true
		return false
	}
	if sp.masker.HasOriginals() {
		exactWindow := sp.inspectionTail + raw
		if sp.masker.ContainsOriginal(exactWindow) {
			sp.leakDetected = true
			return false
		}
		if len(exactWindow) > StreamInspectionBytes {
			exactWindow = exactWindow[len(exactWindow)-StreamInspectionBytes:]
		}
		sp.inspectionTail = exactWindow
	}
	if len(credentialWindow) > credentialTailBytes {
		credentialWindow = credentialWindow[len(credentialWindow)-credentialTailBytes:]
	}
	sp.credentialTail = credentialWindow
	return true
}

func containsPrivateKeyStart(text string) bool {
	const begin = "-----BEGIN "
	for offset := 0; ; {
		index := strings.Index(text[offset:], begin)
		if index < 0 {
			return false
		}
		start := offset + index + len(begin)
		if end := strings.Index(text[start:], "PRIVATE KEY-----"); end >= 0 && end <= 16 {
			return true
		}
		offset = start
	}
}

func SafeCutpoint(text string) int {
	lastOpen := strings.LastIndex(text, "[[")
	if lastOpen == -1 {
		if strings.HasSuffix(text, "[") {
			return len(text) - 1
		}
		return len(text)
	}
	if strings.Contains(text[lastOpen:], "]]") {
		if strings.HasSuffix(text, "[") {
			return len(text) - 1
		}
		return len(text)
	}
	return lastOpen
}
