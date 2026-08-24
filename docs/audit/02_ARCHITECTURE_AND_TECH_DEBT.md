# Mimari ve Teknik Borç Denetimi

## Sistem mimarisi

### Bileşen haritası

| Bileşen | Sorumluluk | Temel bağımlılıklar |
|---|---|---|
| `main.go`, `codex.go`, `demo.go` | CLI, süreç yaşam döngüsü, dinleyiciler | config, proxy, mitm, metrics, audit |
| `config/` | Ortam değişkenlerini okuyup yapılandırma üretme | standart kütüphane |
| `patterns/` | Hassas veri regex/validator kayıt defteri | standart kütüphane |
| `vault/` | Yer tutucu → özgün değer eşlemesi | metrics |
| `masker/` | Tarama, maskeleme, geri açma, istek scope'u | patterns, vault, config, metrics |
| `providers/` | Sağlayıcı tespiti, kimlik başlığı ve stream semantiği | `net/http` |
| `proxy/` | Açık HTTP proxy ve SSE geri açma | masker, provider, audit, metrics |
| `mitm/` | CA, sertifika üretimi, CONNECT/TLS proxy | masker, proxy, config |
| `audit/`, `metrics/` | Sınırlı yerel metadata ve sayaçlar | standart kütüphane |
| `extensions/` | IDE'den ikili süreç yönetimi | VS Code API / IntelliJ API |

Paketleme genel olarak tek yönlüdür; ancak `vault -> metrics` bağımlılığı depolama çekirdeğini gözlemlenebilirlik modeline bağlar (`vault/vault.go:19`, `vault/vault.go:130-141`). Global metrik singleton'ı (`metrics.Global`) proxy, masker ve ana süreç arasında gizli paylaşılan durum oluşturur.

## Veri akışı

1. `main` ortamdan yapılandırmayı yükler, kök vault/masker, audit store ve proxy oluşturur (`main.go:68-103`).
2. Proxy, her AI isteğinde `NewScope()` ile bağımsız bir vault yaratır ve handler sonunda sıfırlar (`proxy/proxy.go:160-161`, `masker/masker.go:51-60`).
3. İstek gövdesi 32 MiB ile sınırlandırılıp tamamen okunur (`proxy/proxy.go:105-111`, `proxy/proxy.go:163-180`).
4. `patterns.Registry` sırayla uygulanır; değer vault'a yazılır ve rastgele yer tutucuyla değiştirilir (`masker/masker.go:123-155`, `masker/masker.go:160-188`). Vault dolarsa istek 507 ile fail-closed engellenir (`proxy/proxy.go:199-217`).
5. Sağlayıcı adaptörü kimlik başlığını hazırlar; istek sabit yapılandırılmış upstream'e gönderilir (`proxy/proxy.go:222-254`).
6. Standart yanıt bütünüyle belleğe alınır; stream yanıtı 4 KiB parçalarla işlenir (`proxy/proxy.go:319-417`).
7. Audit store yalnızca istek kimliği, tip, yer tutucu ve durum gibi metadata'yı 200 kayıtlık halkada saklar (`audit/audit.go:35-89`, `main.go:81`).

MITM modu aynı iş akışını ikinci kez uygular: CONNECT hedefini izin listesiyle doğrular, TLS sonlandırır, gövdeyi maskeler, başlıkları iletir ve yanıtı açar (`mitm/proxy.go:182-214`, `mitm/proxy.go:228-509`). Bu paralel uygulama, güvenlik düzeltmelerinin iki yerde eş zamanlı yapılmasını gerektirir.

## Modül bazlı teknik borç haritası

| Dosya / satır | Borç tipi | Etki | Bulgusal kanıt |
|---|---|---:|---|
| `proxy/proxy.go:100-309` | Büyük, çok sorumluluklu handler | Yüksek | Yöntem doğrulama, limit, maskeleme, upstream, log, audit ve yanıt akışı tek fonksiyonda. |
| `mitm/proxy.go:228-509` | Büyük fonksiyon ve `goto` tabanlı keep-alive döngüsü | Yüksek | TLS, HTTP ayrıştırma, DLP ve yanıt framing tek fonksiyonda; `goto readRequest` satır 507. |
| `proxy/proxy.go` + `mitm/proxy.go` | Yinelenen güvenlik hattı | Yüksek | Gövde limiti, maskeleme, vault-full, upstream, response leak kontrolü iki ayrı uygulamada. |
| `codex.go:309-355` | Güvenlik yapılandırması ile argüman birleştirme iç içe | Yüksek | Override sırası ve eksik yasak listesi koruma iddiasını zayıflatıyor. |
| `extensions/vscode/src/extension.js:88-152,284-345` | Süreç/secret/path/UI tek modülde | Yüksek | 475 satırlık testsiz dosya; güven sınırı UI yardımcılarıyla karışık. |
| `metrics/metrics.go` | Kod içine gömülü 300+ satır HTML/CSS/JS | Orta | Backend metriği ile dashboard sunumu aynı Go dosyasında. |
| `vault/vault.go:19,130-141` | Katman ters bağımlılığı | Düşük | Vault, stats DTO için metrics paketine bağımlı. |
| `config/config.go:186-221` | Sessiz parse fallback | Orta | Hatalı int/bool değerleri uyarısız varsayılana döner; operasyonel yanlış yapılandırma gizlenir. |
| İzlenen `.go` dosyaları | Biçim standardı | Giderildi | Düzeltme sonrasında `gofmt -l` çıktı vermedi. |
| Kök çalışma dizini | Türetilmiş/kopya ağaçlar ve çok sayıda ikili | Orta | `ai-firewall-main/`, `release-clean/`, `Only-Codes/`, çoklu `.exe` dosyaları yerel ağacı belirsizleştiriyor; çoğu `.gitignore` ile hariç. |

## Refactoring önerileri

### 1. Tek bir DLP exchange servisi

`proxy` ve `mitm` için ortak, transporttan bağımsız bir `Exchange` katmanı çıkarılmalı:

```go
type Exchange struct {
    MaskedBody []byte
    Scope      *masker.Masker
    Trace      *audit.Trace
}

func (e *Engine) PrepareRequest(body []byte) (*Exchange, error)
func (e *Engine) RestoreStandard(ex *Exchange, body io.Reader) ([]byte, error)
func (e *Engine) RestoreStream(ex *Exchange, src io.Reader, dst io.Writer) error
```

Böylece limit, fail-closed ve audit kuralları tek yerde test edilir; HTTP ve MITM yalnız framing/transport adaptörü olur.

### 2. Güvenli upstream değeri nesnesi

`string` yerine yükleme sırasında doğrulanan bir `url.URL` saklanmalı. Uzak host için HTTPS zorunlu, loopback HTTP için açık geliştirme politikası uygulanmalı. Provider tespiti de ayrıştırılmış host üzerinden yapılmalı.

### 3. IDE process launcher güven sınırı

İkili keşfi, bütünlük doğrulaması ve secret aktarımı ayrı bir modüle taşınmalı. Çalışma alanı ikilisi ancak açık kullanıcı seçimi ve hash onayıyla kabul edilmeli. Eklenti bundle'ı ya da güvenilir kurulum dizini öncelikli olmalı.

### 4. Metrik/audit bağımlılıklarının tersine çevrilmesi

Vault kendi `Stats` tipini döndürmeli veya callback/event arayüzü kullanmalı. Global sayaç yerine uygulama kökünden enjekte edilen bir recorder, test izolasyonu ve çoklu server örneklerini iyileştirir.

### 5. Dashboard varlığını ayırma

HTML/CSS/JS `embed` edilen ayrı dosyalara taşınmalı. Bu, backend değişikliklerini UI değişikliklerinden ayırır ve dashboard için lint/test olanağı sağlar.

## Ölçeklenme ve performans darboğazları

- Her istek tüm desenleri ardışık uygular ve her regex metnin yeni kopyalarını üretebilir (`masker/masker.go:133-146`, `regexp.ReplaceAllStringFunc`). Desen sayısı ve 32 MiB gövdelerde CPU/alloc maliyeti yaklaşık `O(P × N)` büyür.
- `ContainsOriginal` tüm vault girdilerinde `strings.Contains` çalıştırır (`vault/vault.go:101-111`); stream başına çok kez çağrıldığı için kötü durumda `O(chunks × secrets × text)` olur.
- Standart upstream yanıtında boyut sınırı yoktur (`proxy/proxy.go:321-340`, `mitm/proxy.go:430`); kötü/bozuk upstream yüksek bellek tüketimine yol açabilir.
- Audit halkası dolduğunda her eklemede slice kopyalar (`audit/audit.go:54-61`). Limit 200 iken kabul edilebilir, ancak konfigüre edilebilir büyümede gerçek ring index kullanılmalı.
- MITM leaf certificate cache'inin sınırı ve rotasyonu `mitm/ca.go:276-360` içinde değerlendirilmelidir; izin listesi sınırlı olsa da Azure alt alanları cache kardinalitesini artırabilir.
- 5-6 dakikalık istek süreleri eşzamanlı bağlantıların dosya tanımlayıcılarını uzun süre tutar (`proxy/proxy.go:78-86`, `main.go:105-111`). Bağlantı/istek eşzamanlılık limiti yoktur.

## Mimari olumlu noktalar

- Dinleyiciler açıkça `127.0.0.1` adresine bağlanır (`main.go:201-206`, `codex.go:228-230`).
- Her açık proxy isteği için izole vault kullanılır ve reset edilir (`proxy/proxy.go:160-161`).
- Başlıklar açık proxy'de izin listesiyle taşınır (`proxy/proxy.go:424-489`).
- HTTP istemcisi yeniden kullanılır ve redirect takip etmez (`proxy/proxy.go:73-87`).
- Gövde ve stream tampon sınırları vardır (`proxy/proxy.go:111`, `proxy/proxy.go:561-570`).
