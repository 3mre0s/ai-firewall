package masker

import (
	"fmt"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/vault"
)

func BenchmarkMaskBodySizes(b *testing.B) {
	for _, size := range []int{1 << 10, 1 << 20, 32 << 20} {
		b.Run(fmt.Sprintf("bytes_%d", size), func(b *testing.B) {
			body := strings.Repeat("safe payload ", size/13+1)[:size]
			cfg := config.LoadForTest()
			cfg.MaskPaths = false
			cfg.MaskEmails = false
			root := New(vault.New(cfg.VaultSizeLimit), cfg)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scope := root.NewScope()
				_ = scope.Mask(body)
				scope.Reset()
			}
		})
	}
}

func BenchmarkMaskSecretCounts(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("secrets_%d", count), func(b *testing.B) {
			var body strings.Builder
			for i := 0; i < count; i++ {
				fmt.Fprintf(&body, "ghp_%036d ", i)
			}
			cfg := config.LoadForTest()
			cfg.VaultSizeLimit = count + 10
			root := New(vault.New(cfg.VaultSizeLimit), cfg)
			payload := body.String()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scope := root.NewScope()
				result := scope.Mask(payload)
				if result.MaskedCount != count {
					b.Fatalf("masked %d, want %d", result.MaskedCount, count)
				}
				scope.Reset()
			}
		})
	}
}
