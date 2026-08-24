# Kod Kalitesi ve Test Denetimi

## Çalıştırılan kontroller

| Kontrol | Sonuç | Not |
|---|---|---|
| `go test ./... -cover` | Geçti | Tüm Go paketleri başarılı. |
| `go vet ./...` | Geçti | Kod bulgusu üretmedi. Go telemetri token yazımı sandbox tarafından reddedildi; analiz yine tamamlandı. |
| `gofmt -l <tracked go files>` | Geçti | Düzeltme sonrasında çıktı vermedi. |
| `npm audit --audit-level=high` | Geçti | VSCE 3.9.2 yükseltmesi ve transitif yamalar sonrasında 283 paket, 0 açık. |
| `govulncheck ./...` | Geçti | Yerel Go 1.26.4'te bulunan 6 çağrılabilir standart kütüphane açığı nedeniyle CI Go 1.26.6'ya sabitlendi; aynı tarama yamalı toolchain ile bulgu vermedi. |
| VS Code Node testleri | Geçti | Binary trust, health fail-closed/timeout ve process lifecycle/stale-child dahil 10/10 test geçti. |
| JetBrains Gradle testleri | CI'da tanımlı | Resolver testleri eklendi; yerel ortamda Gradle kurulumu olmadığı için burada çalıştırılmadı. |
| `go test ./... -race` | Çalıştırılamadı | Bu Windows ortamında `-race` CGO gerektiriyor ve CGO kapalı. CI Linux'ta race çalıştırıyor. |

## Paket bazlı test kapsamı

| Paket | Statement kapsamı | Değerlendirme |
|---|---:|---|
| kök `main` | 38,9% | CLI, süreç ve OS entegrasyonu zayıf kapsanıyor. |
| `audit` | 92,0% | Güçlü. |
| `config` | 88,6% | Güçlü; fakat URL güvenlik politikası testi yok. |
| `masker` | 66,4% | Çok sayıda fixture var; kalan dallar ve performans testleri gerekli. |
| `metrics` | 87,5% | Handler/sayaç iyi; dashboard JS ayrı test edilmiyor. |
| `mitm` | 76,1% | CONNECT/TLS, keep-alive, stream, limit, framing ve trust-store dalları kapsanıyor. |
| `patterns` | 0,0% | Pattern tanımları statement metriğine yansımıyor; davranış testleri `patterns_test`/masker'da var, yine de rapor aracı yanıltıcı. |
| `providers` | 71,6% | Orta-iyi. |
| `proxy` | 88,9% | En kritik açık proxy hattında güçlü. |
| `scripts/mock-upstream` | 0,0% | Test yardımcı uygulaması. |
| `scripts/verify-codex-fail-closed` | 9,7% | Fail-closed doğrulama aracının çoğu testsiz. |
| `vault` | 77,4% | İyi. |

## Karmaşıklık ve sürdürülebilirlik

Harici cyclomatic complexity aracı projede tanımlı değildir; aşağıdaki değerlendirme kontrol akışı ve fonksiyon boyutuna dayalı statik incelemedir.

- MITM bağlantı döngüsü ve istek yaşam döngüsü ayrıldı; `handleMITMRequest` her request'in DLP scope/body cleanup'ını deterministik kapatıyor. TLS/framing kodu yine yüksek riskli bir sınır olduğu için entegrasyon testleri korunmalıdır.
- `proxy.(*Server).ServeHTTP` yaklaşık 210 satırdır (`proxy/proxy.go:100-309`) ve en az beş ana faz ile çok sayıda erken dönüş içerir.
- `runCodex` 130+ satırda argüman, auth, server ve child process yaşam döngüsünü birleştirir (`codex.go:49-185`).
- VS Code binary discovery, health probe ve child-process lifecycle saf modüllere ayrıldı; UI/command orchestration ana eklenti modülünde kalıyor.
- `metrics/metrics.go` 504 satırdır; büyük kısmı gömülü frontend varlığıdır. Derleyici tip kontrolü içindeki JavaScript'i doğrulamaz.
- `masker.Mask`, registry'deki her pattern için metni tekrar tarar (`masker/masker.go:123-147`). İş mantığı anlaşılır ancak pattern etkileşimleri/nesting karmaşıklaşmaktadır.

### DRY ve anti-pattern bulguları

- Açık proxy ve MITM request scope, mask/fail-close, bounded standard response ve stream restore için ortak `dlp.Engine` kullanır.
- Provider/header politikası açık proxy'de merkezî izin listesi, MITM'de genel kopyalama biçiminde ayrışmıştır (`proxy/proxy.go:424-489`, `mitm/proxy.go:365-386`).
- Metrikler server başına `metrics.Recorder` olarak enjekte edilir; vault metrics paketinden bağımsızdır.
- Konfigürasyon parse hataları değişken adıyla startup'ı durdurur; `doctor` ve `--check-config` listener açmadan doğrulama yapar.

## Biçim ve kod standardı

İlk denetimde `gofmt -l` 21 izlenen dosyayı raporladı:

`config/config.go`, `config/config_test.go`, `main.go`, `main_test.go`, `masker/masker.go`, `masker/masker_test.go`, `metrics/metrics.go`, `mitm/install.go`, `mitm/proxy.go`, `mitm/proxy_test.go`, `patterns/patterns.go`, `providers/openai_compat.go`, `providers/provider.go`, `providers/provider_test.go`, `proxy/handler_test.go`, `proxy/proxy.go`, `proxy/proxy_test.go`, `proxy/stream_forceflush_test.go`, `proxy/stream_test.go`, `vault/vault.go`, `vault/vault_test.go`.

Bu biçim sapmaları dağıtım hazırlığı sırasında giderildi. Güncel `gofmt -l` çıktısı boştur; CI format kapısı artık bu nedenle engellenmez.

## Eksik kritik test senaryoları

1. **Safe Session config override:** `model_provider`, `base_url`, WebSocket ve compression anahtarlarını tüm CLI yazım biçimleriyle geçersiz kılma denemesi. Mevcut test sadece apps override'ını reddediyor (`main_test.go:130-147`).
2. **Stream ham sır byte-boundary matrisi:** Her credential'ın her byte sınırında bölünmesi. Mevcut test odağı yer tutucu sınırlarıdır (`proxy/stream_test.go`, `proxy/stream_forceflush_test.go`).
3. **IDE lifecycle:** Binary trust/resolver ve VS Code health timeout testlidir; başlat/durdur, stale PID, autoStart güven değişimi ve secret'ın güvenilmeyen child'a verilmemesi için host/lifecycle testleri eksiktir.
4. **MITM genişletilmiş entegrasyon:** Gerçek CONNECT + TLS, iki keep-alive istek, response limit, stream, header/framing ve trust-store dalları testlidir; bozuk chunked framing ve yarıda bağlantı kesilmesi eklenebilir.
5. **Uzak HTTP upstream reddi:** Config yüklemede `http://public-host`, userinfo, fragment, malformed URL ve loopback istisnası.
6. **Response bellek profili:** Açık proxy ve MITM limit +1 reddi testlidir; maksimum heap bütçesi CI eşiğine bağlanmalıdır.
7. **CA KDF migration:** Eski SHA-256 zarfını okuma ve yeni Argon2id/scrypt zarfını yazma/yanlış parola.
8. **Kötü `Content-Length`, chunked ve bağlantı kesintisi:** Response header yazıldıktan sonraki hata semantiği ve client-visible durum.
9. **Eşzamanlılık:** `metrics.Global`, audit ring, vault ve aynı anda shutdown; yerel CI'da race çalışmaması nedeniyle Linux CI kanıtı saklanmalı.
10. **Fuzz:** `SafeCutpoint`, provider response ayrıştırma, URL oluşturma, regex validator ve MITM HTTP framing.

## Hata yakalama ve loglama

### Olumlu

- Açık proxy handler panic recovery uygular (`proxy/proxy.go:113-126`).
- HTTP istemcisinde timeout ve redirect reddi vardır (`proxy/proxy.go:78-86`).
- Sunucular kontrollü shutdown kullanır (`main.go:159-198`, `codex.go:358-362`).
- Secret değerler normal loglara yazılmıyor; maskeleme logu yalnız adet/tip içeriyor (`proxy/proxy.go:190-196`).
- Vault-full fail-closed davranışı açık ve test edilebilir hata koduna sahiptir (`proxy/proxy.go:199-217`).

### Sorunlar

- `handleStandard` okuma/leak hatasında body yazmadan döner, fakat upstream status header'ı önceden yazılmıştır (`proxy/proxy.go:282-305`, `321-341`). İstemci 200 + boş/truncated body görebilir; güvenlik olayı protokol düzeyinde ayırt edilemez.
- `w.Write`, `Flush`, `resp.Write` gibi çeşitli yazma hataları yok sayılıyor veya yalnız loglanıyor (`proxy/proxy.go:340`, `388-411`; `mitm/proxy.go:339-347`).
- MITM handler'da panic recovery yoktur; `net/http` sunucusu panic'i bağlantı bazında yakalasa da güvenlik/audit kaydı tutarlı değildir.
- Loglar yapılandırılmış JSON değil; request ID çoğu hata satırına eklenmiyor. Olay korelasyonu zor.
- Config parse hataları sessiz fallback olur; başlangıçta operatöre yanlış değer bildirilmez.
- Audit encoder hatası bilerek yok sayılır (`audit/audit.go:86`).

## Önerilen kalite kapıları

- `gofmt`, `go vet`, `go test -race -coverprofile`, minimum kritik paket kapsamı (`proxy >= 90`, `mitm >= 75`, root >= 65`).
- `govulncheck ./...` ve `npm ci && npm audit --audit-level=high`.
- VS Code için unit test + Extension Host smoke test; JetBrains için Gradle test.
- Fuzz hedefleri ve en az bir gerçek TLS MITM entegrasyon testi.
- `golangci-lint` sürümünü sabitleme; complexity, errcheck, bodyclose ve noctx kontrolleri.
- Coverage ve race raporlarını CI artefact'ı olarak saklama.
