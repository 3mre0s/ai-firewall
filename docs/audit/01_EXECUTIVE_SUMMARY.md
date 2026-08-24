# Proje Denetimi: Yönetici Özeti

**Denetim tarihi:** 12 Ağustos 2026
**İncelenen kapsam:** Git tarafından izlenen ana ürün kaynakları, yapılandırma, testler, CI/CD, Docker ve IDE eklentileri. `dist/`, `.release-dist/`, `node_modules/`, `ai-firewall-main/`, `release-clean/` ve `Only-Codes/` türetilmiş/kopya içerik olarak kaynak denetiminin dışında tutulmuş; depo hijyeni açısından ayrıca değerlendirilmiştir.
**Yöntem:** Statik kaynak incelemesi, satır bazlı kanıt, `go test ./... -cover`, `go vet ./...`, `gofmt -l` ve `npm audit --json`. İnternet tabanlı bir penetrasyon testi yapılmamıştır.

## Projenin amacı ve iş mantığı

Anonmyz (eski uyumluluk adıyla Local AI Firewall), AI istemcisi ile bulut model sağlayıcısı arasına yerleşen yerel bir DLP geçididir. İstek gövdesini desen kayıt defterine göre tarar, bulunan hassas değerleri kriptografik rastgele yer tutucularla değiştirir, yalnızca o istek için bellekte tutulan kasaya kaydeder, temizlenmiş isteği sağlayıcıya iletir ve yanıttaki yer tutucuları yerelde geri açar (`README.md:3`, `README.md:48-60`, `proxy/proxy.go:91-100`).

İki trafik modu vardır:

- Açık ters proxy: loopback HTTP dinleyicisi, sağlayıcı adaptörleri ve izin listeli başlık aktarımı (`main.go:83-111`, `proxy/proxy.go:424-489`).
- İsteğe bağlı şeffaf MITM: izin listeli AI alan adları için yerel CA ile TLS sonlandırma (`main.go:123-156`, `mitm/proxy.go:97-169`, `mitm/proxy.go:182-214`).

Ek olarak Codex Safe Session başlatıcısı (`codex.go:49-185`), yerel metrik/audit uçları (`main.go:88-103`), VS Code eklentisi ve beta JetBrains eklentisi bulunur.

## Teknoloji yığını

| Alan | Teknoloji | Kanıt |
|---|---|---|
| Çekirdek servis | Go 1.22, yalnızca standart kütüphane | `go.mod:1-3` |
| HTTP/TLS | `net/http`, `crypto/tls`, ECDSA P-256 CA | `proxy/proxy.go`, `mitm/ca.go:167-203` |
| Gizli veri tespiti | Go `regexp`, semantik doğrulayıcılar | `masker/masker.go:123-155`, `patterns/patterns.go` |
| Geçici kasa | Bellek içi `map`, `sync.RWMutex`, atomikler | `vault/vault.go:39-43`, `vault/vault.go:65-142` |
| Gözlemlenebilirlik | Bellek içi sayaçlar, JSON ve gömülü HTML | `audit/audit.go:35-90`, `metrics/metrics.go` |
| VS Code eklentisi | Node.js/CommonJS, VS Code API | `extensions/vscode/package.json`, `extensions/vscode/src/extension.js` |
| JetBrains eklentisi | Kotlin, IntelliJ Platform | `extensions/jetbrains/build.gradle.kts`, `FirewallPlugin.kt` |
| CI / yayın | GitHub Actions, GoReleaser v2 | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.goreleaser.yml` |
| Konteyner | Çok aşamalı Alpine imajı, non-root kullanıcı | `Dockerfile:2-30` |

## Genel sağlık skoru

**Genel skor: 66/100 — işlevsel ve iyi test edilmiş çekirdek, fakat güvenlik ürünü için yayın engelleyici sınır ihlalleri var.**

Puanlar kodda gözlenen kontroller, doğrulama çıktıları ve bulguların etkisine göre verilmiştir; üretim trafiği veya harici altyapı gözlemi içermeyen statik bir sağlık göstergesidir.

| Boyut | Puan | Kısa gerekçe |
|---|---:|---|
| Mimari ve modülerlik | 72 | Paket sınırları açık; açık proxy/MITM akışları önemli ölçüde yineleniyor. |
| Güvenlik ve gizlilik | 49 | Loopback, gövde limiti ve istek kasası güçlü; IDE ikili güveni ve Safe Session override açıkları kritik. |
| Kod kalitesi ve sürdürülebilirlik | 63 | Açık isimlendirme/testler var; büyük fonksiyonlar, 20 biçimsiz Go dosyası ve iki ayrı proxy hattı bakım yükü yaratıyor. |
| Performans ve kaynak yönetimi | 67 | Paylaşılan istemci ve sınırlı istek/stream tamponu iyi; standart yanıtlar sınırsız belleğe alınıyor. |
| Test kapsamı ve güvenilirlik | 70 | Çekirdek proxy kapsamı yüksek; MITM ve ana komut düşük, iki IDE eklentisi testsiz. |
| Bağımlılık ve altyapı sağlığı | 72 | Go harici bağımlılıksız ve npm audit temiz; imaj/Action sürümleri digest/SHA ile sabit değil. |
| Dokümantasyon ve DX | 69 | README, mimari ve tehdit modeli güçlü; güvenlik iddiaları bazı fiili davranışlarla çelişiyor. |

## En kritik 5 teknik risk

1. **Yüksek — VS Code eklentisi güvenilmeyen çalışma alanı ikilisini API anahtarıyla çalıştırabilir.** Çözümleme zinciri çalışma alanını kurulu/bundle konumlarından önce seçer (`extension.js:299-307`); seçilen dosya SecretStorage anahtarı ortam değişkeniyle verilerek başlatılır (`extension.js:94-118`). `autoStart` açıksa açılışta kullanıcı etkileşimi olmadan gerçekleşir (`extension.js:66-73`).
2. **Yüksek — Codex Safe Session koruma seçenekleri sonradan geçersiz kılınabilir.** Güvenli `-c` değerleri kullanıcı argümanlarından önce eklenir (`codex.go:309-331`); doğrulama sadece `features.apps` anahtarını yasaklar (`codex.go:334-355`). Kullanıcı/otomasyon `model_provider`, `base_url`, `supports_websockets` veya `features.enable_request_compression` değerlerini sonda yeniden tanımlayabilir.
3. **Yüksek — Normal sunucu modu API anahtarını düz HTTP upstream'e gönderebilir.** `UPSTREAM_URL` yalnızca sondaki `/` karakterinden arındırılır, şema/host/TLS politikası doğrulanmaz (`config/config.go:101-133`); sonra sağlayıcı kimlik bilgisi bu URL'ye eklenir (`proxy/proxy.go:231-254`).
4. **Yüksek — Akış yanıtında chunk sınırına bölünen ham sır algılamayı aşabilir.** Tampon yalnızca eksik `[[...]]` yer tutucusunu tutar (`proxy/proxy.go:679-706`); ham anahtarın ilk parçası hemen istemciye yazılabilir (`proxy/proxy.go:375-390`) ve sonraki parça tek başına desene uymayabilir.
5. **Orta — CA anahtar parolası hızlı SHA-256 ile türetiliyor.** Kod çevrimdışı parola denemelerine karşı yavaş KDF olmadığını açıkça kabul eder (`mitm/ca.go:387-411`); uygulama doğrudan `sha256.Sum256` kullanır (`mitm/ca.go:411-446`).

## En acil 5 iyileştirme fırsatı

1. VS Code/JetBrains ikili çözümlemesinde çalışma alanını varsayılan aday olmaktan çıkar; yalnızca imzalı bundle/kurulu yol veya açık kullanıcı onayı + SHA-256 doğrulaması kullan.
2. Safe Session argümanlarını izin listesine al veya güvenlik override'larını argüman listesinin en sonuna taşı; tüm rota/transport anahtarlarının kullanıcı tarafından tekrar tanımlanmasını reddet.
3. `UPSTREAM_URL` için ayrıştırılmış URL doğrulaması ekle: uzak hostlarda yalnızca HTTPS, userinfo/query/fragment yasağı; düz HTTP yalnızca açıkça izin verilen loopback geliştirme hedeflerinde.
4. Stream işlemcisine ham sır desenleri için en uzun gerekli eşleşme önekini tutan güvenlik penceresi ekle; her byte sınırında bölme testleri yaz.
5. MITM, CLI ve IDE eklentileri için test tabanını genişlet; CI'da sabit linter sürümü, `npm ci` + audit, SBOM/provenance ve digest/SHA pinleme kullan.

## Doğrulama özeti

- `go test ./... -cover`: tüm paketler geçti.
- `go vet ./...`: bulgu yok.
- `npm audit --json`: 185 geliştirme bağımlılığı, 0 bilinen zafiyet.
- `gofmt -l`: düzeltme sonrasında çıktı vermedi.
- `go test -race`: bu Windows ortamında CGO kapalı olduğundan çalıştırılamadı; CI Linux üzerinde `-race` çalıştıracak şekilde yapılandırılmıştır (`.github/workflows/ci.yml:29-30`).
