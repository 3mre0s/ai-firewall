package dlp

import (
	"errors"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
)

func testEngine(limit int, responseLimit int64) *Engine {
	cfg := config.LoadForTest()
	cfg.VaultSizeLimit = limit
	return NewEngine(masker.New(vault.New(limit), cfg), responseLimit)
}

func TestExchangeIsRequestScoped(t *testing.T) {
	engine := testEngine(10, 1024)
	first, err := engine.Prepare([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	label := first.Mask.Detections[0].PlaceholderID

	second, err := engine.Prepare([]byte("safe"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	result, err := engine.RestoreStandard(second, strings.NewReader(label))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != label {
		t.Fatalf("cross-request placeholder restored: %q", result.Body)
	}
}

func TestPrepareAndRestoreFailClosed(t *testing.T) {
	engine := testEngine(1, 5)
	exchange, err := engine.Prepare([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij sk-proj-abcdefghijklmnopqrstuvwxyz123456"))
	if !errors.Is(err, ErrVaultFull) {
		t.Fatalf("Prepare error = %v, want ErrVaultFull", err)
	}
	exchange.Close()

	exchange, err = engine.Prepare([]byte("safe"))
	if err != nil {
		t.Fatal(err)
	}
	defer exchange.Close()
	if _, err := engine.RestoreStandard(exchange, strings.NewReader("123456")); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
	scanEngine := testEngine(1, 1024)
	scanExchange, err := scanEngine.Prepare([]byte("safe"))
	if err != nil {
		t.Fatal(err)
	}
	defer scanExchange.Close()
	if _, err := scanEngine.RestoreStandard(scanExchange, strings.NewReader("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")); !errors.Is(err, ErrUnsafeResponse) {
		t.Fatalf("unsafe response error = %v", err)
	}
}

func TestStreamBlocksSplitPrivateKeyMarker(t *testing.T) {
	engine := testEngine(10, 1024)
	exchange, err := engine.Prepare([]byte("safe"))
	if err != nil {
		t.Fatal(err)
	}
	defer exchange.Close()
	processor := NewStreamProcessor(exchange.Masker)
	_ = processor.Process([]byte("prefix -----BEGIN RSA PRI"))
	_ = processor.Process([]byte("VATE KEY-----\nbody"))
	if !processor.LeakDetected() {
		t.Fatal("split private-key marker was not blocked")
	}
}
