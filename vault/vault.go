// Package vault implements a thread-safe (iş parçacığı güvenli) in-memory key-value store
// that maps generated labels back to their original sensitive values.
//
// Design decisions (tasarım kararları):
//   - sync.RWMutex lets many goroutines (iş parçacıkları) read concurrently while
//     writes are exclusive. This is important because unmasking in a streaming
//     response can trigger dozens of concurrent reads per second.
//   - Atomic (atomik) hit-count increments avoid locking on every read.
//   - A hard size limit prevents unbounded (sınırsız) memory growth during
//     long AI sessions.
package vault

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/3mre0s/ai_firewall/metrics"
)

var (
	ErrLimitReached = errors.New("vault limit reached")
	ErrLabelExists  = errors.New("vault label already exists")
)

// Entry is a single record inside the Vault.
// (Vault içindeki tek bir kayıt.)
type Entry struct {
	Label    string // the placeholder sent to the cloud (buluta gönderilen yer tutucu)
	Original string // the sensitive value kept locally (yerel olarak saklanan hassas değer)

	// hitCount tracks how many times this entry was unmasked.
	// int64 pointer so atomic operations work correctly on 32-bit platforms.
	// (Bu girişin kaç kez maskesinin kaldırıldığını izler.)
	hitCount int64
}

// Vault is the central, process-lifetime store for all masked values.
// One Vault instance is shared across all concurrent proxy requests.
// (Tüm maskelenmiş değerler için merkezi, süreç-ömürlü depo.
//
//	Tek bir Vault örneği, tüm eş zamanlı proxy istekleri arasında paylaşılır.)
type Vault struct {
	mu      sync.RWMutex      // guards entries map (giriş haritasını korur)
	entries map[string]*Entry // label → *Entry
	limit   int               // maximum number of entries (maksimum giriş sayısı)
}

// New creates a Vault with the provided size limit.
// (Sağlanan boyut limiti ile bir Vault oluşturur.)
func New(limit int) *Vault {
	if limit <= 0 {
		limit = 1000
	}
	return &Vault{
		entries: make(map[string]*Entry, limit),
		limit:   limit,
	}
}

// Store saves an original sensitive value under a generated label.
// Returns an error when the Vault has reached its limit — the caller
// must then skip masking and forward the value as-is rather than lose data.
//
// (Üretilen bir etiket altına orijinal hassas değeri kaydeder.
//
//	Vault limitine ulaşıldığında hata döner — çağıran, veri kaybını önlemek için
//	maskelemeyi atlayıp değeri olduğu gibi iletmek zorundadır.)
func (v *Vault) Store(label, original string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.entries[label]; exists {
		return fmt.Errorf("%w: %s", ErrLabelExists, label)
	}

	if len(v.entries) >= v.limit {
		return fmt.Errorf("%w: %d/%d", ErrLimitReached, len(v.entries), v.limit)
	}

	v.entries[label] = &Entry{
		Label:    label,
		Original: original,
	}
	return nil
}

// Retrieve looks up the original value for a given label.
// The second return value is false when the label is not found.
// (Verilen etiket için orijinal değeri arar.
//
//	Etiket bulunamadığında ikinci dönüş değeri false olur.)
func (v *Vault) Retrieve(label string) (string, bool) {
	// Read lock (okuma kilidi) — allows concurrent access (eş zamanlı erişime izin verir)
	v.mu.RLock()
	entry, ok := v.entries[label]
	v.mu.RUnlock()

	if !ok {
		return "", false
	}

	// Atomic increment (atomik artış) — no write lock needed for a counter
	// (sayaç için yazma kilidi gerekmez)
	atomic.AddInt64(&entry.hitCount, 1)
	return entry.Original, true
}

// Reset wipes all entries, freeing memory.
// Call this at the end of a session or when context changes.
// (Tüm girişleri siler, belleği serbest bırakır.
//
//	Oturum sonunda veya bağlam değiştiğinde çağırın.)
func (v *Vault) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries = make(map[string]*Entry, v.limit)
}

// Stats returns a snapshot of current usage for monitoring/logging.
// It satisfies the metrics.VaultStatsProvider interface.
// (İzleme/loglama için mevcut kullanımın anlık görüntüsünü döner.
//
//	metrics.VaultStatsProvider arayüzünü karşılar.)
func (v *Vault) Stats() metrics.VaultStats {
	v.mu.RLock()
	defer v.mu.RUnlock()

	s := metrics.VaultStats{
		Current: len(v.entries),
		Limit:   v.limit,
	}
	for _, e := range v.entries {
		s.TotalHits += atomic.LoadInt64(&e.hitCount)
	}
	return s
}
