package dlp

import (
	"fmt"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
)

func BenchmarkStreamProcessorChunkSizes(b *testing.B) {
	// A 64 KiB window exposes small-chunk look-behind costs without making a
	// single benchmark iteration dominate CI for minutes.
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = 'x'
	}
	for _, chunkSize := range []int{64, 4096, 64 << 10} {
		b.Run(fmt.Sprintf("chunk_%d", chunkSize), func(b *testing.B) {
			cfg := config.LoadForTest()
			root := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scope := root.NewScope()
				processor := NewStreamProcessor(scope)
				for start := 0; start < len(payload); start += chunkSize {
					end := min(start+chunkSize, len(payload))
					_ = processor.Process(payload[start:end])
				}
				_ = processor.Flush()
				scope.Reset()
			}
		})
	}
}
