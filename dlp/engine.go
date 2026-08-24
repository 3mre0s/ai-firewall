// Package dlp contains the transport-independent request/response inspection
// lifecycle shared by the explicit HTTP proxy and the TLS MITM proxy.
package dlp

import (
	"errors"
	"io"

	"github.com/3mre0s/ai-firewall/masker"
)

var (
	ErrVaultFull        = errors.New("vault capacity exceeded")
	ErrResponseTooLarge = errors.New("upstream response too large")
	ErrUnsafeResponse   = errors.New("unsafe upstream response")
)

// Engine creates request-scoped exchanges from a process-scoped masker.
type Engine struct {
	root                *masker.Masker
	maxStandardResponse int64
}

// Exchange owns all secret state for exactly one request/response pair.
type Exchange struct {
	Masker *masker.Masker
	Mask   masker.MaskResult
}

// StandardResult is a fully inspected non-streaming response.
type StandardResult struct {
	Body     []byte
	Restored int
}

func NewEngine(root *masker.Masker, maxStandardResponse int64) *Engine {
	return &Engine{root: root, maxStandardResponse: maxStandardResponse}
}

// Prepare masks a request and returns an isolated exchange. Call Close after
// the response finishes, including all error paths.
func (e *Engine) Prepare(body []byte) (*Exchange, error) {
	scope := e.root.NewScope()
	result := scope.Mask(string(body))
	exchange := &Exchange{Masker: scope, Mask: result}
	if result.VaultEvictions > 0 {
		return exchange, ErrVaultFull
	}
	return exchange, nil
}

func (e *Exchange) Close() {
	if e != nil && e.Masker != nil {
		e.Masker.Reset()
	}
}

// RestoreStandard buffers, bounds, scans, and restores a normal response.
func (e *Engine) RestoreStandard(exchange *Exchange, body io.Reader) (StandardResult, error) {
	raw, err := io.ReadAll(io.LimitReader(body, e.maxStandardResponse+1))
	if err != nil {
		return StandardResult{}, err
	}
	if int64(len(raw)) > e.maxStandardResponse {
		return StandardResult{}, ErrResponseTooLarge
	}
	text := string(raw)
	if exchange.Masker.ContainsOriginal(text) || exchange.Masker.HasCredentialSecrets(text) {
		return StandardResult{}, ErrUnsafeResponse
	}
	unmasked, restored := exchange.Masker.UnmaskWithCount(text)
	return StandardResult{Body: []byte(unmasked), Restored: restored}, nil
}
