# Önceliklendirilmiş Eylem Planı

Zorluk ölçeği: **S** (≤1 gün), **M** (2-4 gün), **L** (1-2 hafta). Süreler tek deneyimli geliştirici için kaba teknik tahmindir; yalnız kod tabanında görülen kapsama dayanır.

## Faz 1 — Acil güvenlik ve çökme düzeltmeleri

### 1.1 IDE ikili güven zincirini kapat

- **Öncelik:** P0
- **Zorluk:** M
- **Kapsam:** `extensions/vscode/src/extension.js:284-345`, `FirewallPlugin.kt:61-112`
- **İş:** Workspace-root otomatik seçimini kaldır; bundle/kurulu binary'yi doğrula; manuel seçimde hash/onay sakla; güven kaynağı değiştiğinde autoStart'ı durdur.
- **Kabul kriteri:** Kötü amaçlı fixture repo içindeki `ai-firewall(.exe)` hiçbir kullanıcı onayı olmadan çalıştırılamaz ve `FORWARD_API_KEY` alamaz. VS Code ve JetBrains otomatik testleri bunu kanıtlar.

### 1.2 Safe Session override bypass'ını kapat

- **Öncelik:** P0
- **Zorluk:** S
- **Kapsam:** `codex.go:309-355`, `main_test.go`
- **İş:** Protected config anahtarlarının tamamını reddet; zorunlu override'ları en sona koy; CLI yazım varyantlarını normalize et.
- **Kabul kriteri:** `model_provider`, `base_url`, `wire_api`, `supports_websockets`, `requires_openai_auth`, compression ve apps değerleri hiçbir aktarılan argüman biçimiyle değiştirilemez. Negatif test matrisi geçer.

### 1.3 Upstream TLS politikasını zorunlu kıl

- **Öncelik:** P0
- **Zorluk:** S
- **Kapsam:** `config/config.go:94-162`, config testleri
- **İş:** URL parse/normalize; uzak HTTP, userinfo, query/fragment ve şemasız URL'leri reddet; loopback geliştirme istisnasını açık politika yap.
- **Kabul kriteri:** Gerçek API anahtarı uzak bir `http://` hedefe hiçbir koşulda gönderilemez; tablo testleri tüm sınırları doğrular.

### 1.4 Stream chunk-sınırı DLP açığını kapat

- **Öncelik:** P0
- **Zorluk:** L
- **Kapsam:** `proxy/proxy.go:506-707`, MITM stream yolu
- **İş:** Ham secret look-behind/event buffer tasarla; latency/bellek limitini belirle; tüm patternler için byte-boundary test matrisi ekle.
- **Kabul kriteri:** Desteklenen her credential fixture'ı her olası iki-parça bölünmede istemciye ham byte vermeden engellenir. Açık proxy ve MITM aynı çekirdek implementasyonu kullanır.

### 1.5 Standart response limiti ve doğru hata semantiği

- **Öncelik:** P1
- **Zorluk:** M
- **Kapsam:** `proxy/proxy.go:282-341`, `mitm/proxy.go:390-450`
- **İş:** Header'ı güvenlik taraması bitmeden yazma; konfigüre response body limiti ekle; client'a tutarlı 502 ve audit sonucu üret.
- **Kabul kriteri:** Limit +1 gövde sınırlı bellekle reddedilir; unsafe response 200 + boş gövde olarak görünmez.

### 1.6 CA KDF'ini güçlendir

- **Öncelik:** P1
- **Zorluk:** M
- **Kapsam:** `mitm/ca.go:387-468`
- **İş:** Argon2id/scrypt + salt + parametreli sürümlü zarf; geriye dönük okuma/migration.
- **Kabul kriteri:** Yeni anahtar dosyasında salt/KDF parametreleri bulunur; yanlış parola ve legacy migration testleri geçer; düz anahtar modu için açık risk onayı/dokümanı vardır.

## Faz 2 — Mimari refactoring ve test güvenilirliği

### 2.1 Ortak DLP exchange motoru çıkar

- **Öncelik:** P1
- **Zorluk:** L
- **İş:** Açık proxy ve MITM'nin mask/forward/restore/fail-close kararlarını tek transport-bağımsız serviste birleştir.
- **Kabul kriteri:** Aynı güvenlik davranışı iki mod için tek test suite ile doğrulanır; header/framing dışındaki yinelenen kod kaldırılır.
- **Durum:** Tamamlandı — `dlp.Engine` request scope, vault-full kararı, standart response limiti/sızıntı kontrolü ve stream reassembly davranışını iki taşıma için ortaklaştırıyor.

### 2.2 MITM handler'ı yapılandırılmış loop ve küçük fonksiyonlara böl

- **Öncelik:** P1
- **Zorluk:** M
- **İş:** `goto` kaldır; connection-scope ve request-scope lifecycle'ı ayır; her request sonunda deterministik close/reset uygula.
- **Kabul kriteri:** İki keep-alive istekli entegrasyon testinde önceki istek sırrı ikinci istekte restore edilemez; leak/race testi geçer.
- **Durum:** Tamamlandı — `goto` kaldırıldı; her istek `handleMITMRequest` içinde kapanıyor ve gerçek TLS keep-alive testi önceki placeholder'ın ikinci istekte inert kaldığını doğruluyor.

### 2.3 MITM kapsamını yükselt

- **Öncelik:** P1
- **Zorluk:** L
- **İş:** CONNECT/TLS, izin listesi, Azure suffix, header policy, büyük body/response, stream ve keep-alive entegrasyon testleri.
- **Kabul kriteri:** `mitm` statement kapsamı en az %75; kritik güvenlik dalları branch testleriyle kapsanır.
- **Durum:** Tamamlandı — gerçek CONNECT/TLS, iki istekli keep-alive, stream, response limiti, header/framing, leaf sertifika cache'i ve üç işletim sistemi trust-store dalları test edildi; `mitm` statement kapsamı %76,1.

### 2.4 IDE eklentilerini modülerleştir ve test et

- **Öncelik:** P1
- **Zorluk:** L
- **İş:** discovery, verification, secret resolution, process lifecycle ve UI'ı ayır; VS Code unit/host ve JetBrains Gradle testleri ekle.
- **Kabul kriteri:** Başlat/durdur, health timeout, stale PID, binary trust ve secret aktarımı otomatik testlidir.
- **Durum:** Büyük ölçüde tamamlandı — VS Code binary discovery, health probe ve child-process lifecycle ayrı modüllerde. Workspace override reddi, yalnız 200 health, timeout, tek aktif child, SIGTERM stop, spawn error, shutdown ve eski child'ın geç olayının yeni süreci bozamaması 10 Node testiyle doğrulanıyor. JetBrains resolver proje kökünü dışlayan saf bir modülde ve Gradle CI testine sahip. Extension Host seviyesinde autoStart testi açık.

### 2.5 Global metrik durumunu enjekte edilebilir yap

- **Öncelik:** P2
- **Zorluk:** M
- **İş:** `metrics.Global` yerine recorder arayüzü; vault'un metrics tipine bağımlılığını kaldır.
- **Kabul kriteri:** Paralel testler birbirinin sayaçlarını etkilemez; bir süreçte iki server bağımsız ölçülür.
- **Durum:** Tamamlandı — `metrics.Recorder` enjekte ediliyor, üretim yolları bağımsız `Counters` kullanıyor ve vault metrics paketinden bağımsız.

### 2.6 Hata ve log standardı

- **Öncelik:** P2
- **Zorluk:** M
- **İş:** Request ID'li yapılandırılmış loglar, sınıflı güvenlik olayları, tüm write/encode hatalarının politikası.
- **Kabul kriteri:** Her upstream/restore/block olayı request ID ile korele edilir; hiçbir kritik I/O hatası sessizce yutulmaz.
- **Durum:** Tamamlandı — explicit ve MITM yolları request/upstream/restore/block olaylarını aynı request ID ile JSON olarak yayıyor; client yanıtında `X-Anonmyz-Request-Id` bulunuyor.

## Faz 3 — Altyapı, performans ve DX iyileştirmeleri

### 3.1 CI ve format borcunu temizle

- **Öncelik:** P1
- **Zorluk:** S
- **İş:** 20+ biçim sapmasını `gofmt` ile düzelt; yerel pre-commit/Make hedefi; CI parity komutu.
- **Kabul kriteri:** `gofmt -l` boş; `go vet`, `go test -race` ve cross-build yeşil.

### 3.2 Tedarik zincirini sabitle

- **Öncelik:** P2
- **Zorluk:** M
- **İş:** Docker base imajlarını digest'e, Actions'ı commit SHA'ya, golangci-lint'i belirli sürüme sabitle; SBOM, provenance ve imza üret.
- **Kabul kriteri:** Aynı tag aynı dependency graph'i üretir; release artefact'ında checksum + SBOM + doğrulanabilir provenance bulunur.
- **Durum:** Tamamlandı — GitHub Actions tam commit SHA'larına, golangci-lint ve GoReleaser belirli sürümlere, Docker builder/runtime imajları resmî manifest digestlerine sabitlendi. Dependabot bu referansları izliyor; release arşivleri SPDX SBOM, SHA-256 checksum ve GitHub/Sigstore provenance üretiyor.

### 3.3 Bağımlılık güvenlik kapıları

- **Öncelik:** P2
- **Zorluk:** S
- **İş:** CI'a `govulncheck`, `npm ci`, `npm audit --audit-level=high`; sonuçları artefact yap.
- **Kabul kriteri:** High/critical bulgu release'i engeller; istisnalar süreli ve belgeli olur.
- **Durum:** Tamamlandı — VS Code CI işi `npm ci` ve high/critical npm audit kapısını, Go işi sabitlenmiş `govulncheck` kapısını kullanıyor. Go işleri taramada bulunan standart kütüphane açıklarının düzeltildiği 1.26.6 sürümüne sabitlendi.

### 3.4 Performans bütçeleri ve benchmark

- **Öncelik:** P2
- **Zorluk:** M
- **İş:** 1 KiB/1 MiB/32 MiB gövde, 10/100/1000 secret ve stream chunk boyutları için benchmark; allocation profili.
- **Kabul kriteri:** P95 latency ve maksimum heap bütçesi belgelenir; regresyon eşikleri CI'da izlenir.
- **Durum:** Kısmen tamamlandı — istenen gövde/secret/chunk benchmark matrisi ve CI artefact'ı eklendi. 64-byte chunk yolu yaklaşık 66 kat hızlandı. Eşleşmesiz 32 MiB gövde tek-geçiş özellik filtresiyle yaklaşık 14,4 saniyeden 1,32 saniyeye, allocation yaklaşık 1,07 GiB'den 21 KiB'ye indirildi; 1 MiB güvenli gövde için 2 MiB allocation bütçesi test kapısıdır. Platformlar arası kararlı P95 eşiği henüz tanımlı değil.

### 3.5 Config doğrulama ve operatör geri bildirimi

- **Öncelik:** P2
- **Zorluk:** S
- **İş:** Hatalı int/bool için sessiz fallback yerine açık hata; `anonmyz doctor`/`--check-config` ekle.
- **Kabul kriteri:** Typo'lu ortam değişkeni startup'ı açıklayıcı hatayla durdurur; secret değeri loglanmaz.
- **Durum:** Tamamlandı — parse hataları değişken adını içeren açık hata döndürüyor; listener çakışması, vault kapasitesi ve log seviyesi doğrulanıyor; `doctor` ile `--check-config` listener açmadan ve credential yazdırmadan kontrol sağlıyor.

### 3.6 Dokümantasyon doğruluk kapısı

- **Öncelik:** P2
- **Zorluk:** S
- **İş:** README/THREAT_MODEL güvenlik garantilerini executable testlere bağla; encoding bozulmalarını düzelt; kapsam tablosunu CI'dan üret.
- **Kabul kriteri:** “Safe Session bypass edilemez”, “request-scoped”, “stream fail-closed” iddialarının her biri isimlendirilmiş bir testle eşlenir.

## İlerleme kontrol listesi

### Faz 1

- [x] Workspace binary otomatik yürütmesi kaldırıldı.
- [x] Safe Session korumalı config anahtarları override edilemiyor.
- [x] Uzak HTTP upstream reddediliyor.
- [x] Ham stream secret byte-boundary testleri geçiyor.
- [x] Standart response boyut limiti ve tarama öncesi header geciktirmesi eklendi; unsafe response istemciye tutarlı 502 dönüyor.
- [x] Yeni CA anahtarları salt'lı PBKDF2-HMAC-SHA-256 ile şifreleniyor; legacy okuma korunuyor.

### Faz 2

- [x] Açık proxy ve MITM ortak DLP motorunu kullanıyor.
- [x] MITM `goto` kaldırıldı ve request lifecycle testli.
- [x] MITM kapsamı ≥ %75.
- [x] VS Code ve JetBrains otomatik testleri var.
- [x] Global metrics kaldırıldı/enjekte ediliyor.
- [x] Request ID'li yapılandırılmış log standardı uygulandı.

### Faz 3

- [ ] `gofmt -l` çıktı vermiyor.
- [ ] Race/vet/test/cross-build CI yeşil.
- [x] Actions ve container base'leri immutable referansla sabit.
- [x] `govulncheck` ve `npm audit` release kapısı.
- [x] SBOM, checksum ve provenance yayınlanıyor.
- [ ] Performans bütçeleri ve benchmark regresyonları izleniyor.
- [x] Hatalı config değerleri fail-closed reddediliyor ve `doctor`/`--check-config` kullanılabiliyor.
- [ ] Doküman güvenlik iddiaları testlere izlenebilir.

## Önerilen teslim sırası

İlk release engeli olarak 1.1-1.4 birlikte ele alınmalıdır; bunlar ürünün “yerel güvenlik sınırı” iddiasını doğrudan etkiler. Ardından 1.5-1.6 ve 2.1 ile iki proxy hattı birleştirilmeli; güvenlik düzeltmeleri yinelenen kod üzerinde ayrı ayrı taşınmamalıdır. Format ve CI sabitleme küçük işler olsa da ilk güvenlik PR'larıyla eş zamanlı tamamlanabilir.
