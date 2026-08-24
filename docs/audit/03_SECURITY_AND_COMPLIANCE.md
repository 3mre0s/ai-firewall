# Güvenlik ve Uyumluluk Denetimi

## Düzeltme durumu — 12 Ağustos 2026

Dağıtım hazırlığı kapsamında SEC-01–SEC-06 için düzeltmeler uygulandı ve tam Go test/vet/build kapıları geçti: IDE'lerde workspace/project binary otomatik seçimi kaldırıldı; Safe Session rota/transport anahtarları kilitlendi; uzak HTTP upstream reddedildi; stream credential look-behind ve standart response limitleri eklendi; yeni CA anahtarları salt'lı PBKDF2-HMAC-SHA-256 (210.000 iterasyon) kullanıyor. SEC-07–SEC-08 savunma-derinliği iyileştirmeleri olarak açık kalmaktadır. Bu bölüm ilk denetim kanıtlarını tarihsel olarak değiştirmez.

## Kapsam ve güven modeli

Ürün, yanlışlıkla AI sağlayıcısına gönderilen desteklenen sır desenlerini maskelemeyi amaçlıyor; kötü amaçlı yerel süreç, proxy'yi atlayan trafik ve tanınmayan sır formatları kapsam dışıdır (`THREAT_MODEL.md:41-53`, `README.md:355-367`). Bu denetim OWASP sınıflarını yerel proxy/IDE eklentisi bağlamına uyarlamıştır. Resmî bir mevzuat sertifikasyonu veya canlı penetrasyon testi değildir.

## Bulgular

### SEC-01 — Yüksek — Çalışma alanı ikilisi secret ile yürütülüyor

**Konum:** `extensions/vscode/src/extension.js:66-73`, `94-118`, `299-307`
**Sınıf:** CWE-426 / CWE-829, tedarik zinciri ve güvenilmeyen arama yolu
**Etki:** Kötü amaçlı veya ele geçirilmiş bir repo köke `ai-firewall.exe` / `ai-firewall` koyarsa, eklenti bunu kurulu güvenilir ikiliden önce seçer. `autoStart` etkin kullanıcıda açılışta çalışır ve gerçek API anahtarı `FORWARD_API_KEY` olarak bu sürece verilir. Sonuç, yerel kod yürütme yetkisine ek olarak doğrudan secret ifşasıdır.

**İlgili kod:**

```js
for (const folder of vscode.workspace.workspaceFolders ?? []) {
    const p = path.join(folder.uri.fsPath, name);
    if (fs.existsSync(p)) return p;
}
// ...
proc = cp.spawn(binary, [], { env, stdio: ['ignore', 'pipe', 'pipe'] });
```

**Düzeltme:** Workspace aramasını kaldırın veya varsayılan olarak reddedin. Bundle/kurulu yolu önceleyin; açıkça seçilen ikili için gerçek yol, dosya sahibi/izinleri ve yayın checksum/imzasını doğrulayın. `autoStart`, güven kaynağı değiştiğinde yeniden onay istemeli.

**Güvenli örnek:**

```js
const bundled = path.resolve(ctx.extensionPath, name);
if (await verifyPublishedChecksum(bundled)) return bundled;
throw new Error('No verified firewall binary is installed');
```

JetBrains eklentisi de proje kökünü ilk aday yapar (`FirewallPlugin.kt:72-75`) ve API anahtarını child ortama geçirir (`FirewallPlugin.kt:29-46`); aynı politika orada da uygulanmalıdır.

### SEC-02 — Yüksek — Safe Session korumaları argümanlarla aşılabilir

**Konum:** `codex.go:309-331`, `codex.go:334-355`
**Sınıf:** CWE-15, güvenlik açısından kritik yapılandırmanın dışarıdan değiştirilmesi
**Etki:** Güvenlik override'ları kullanıcıdan aktarılan argümanlardan önce eklenir. Doğrulama yalnız `features.apps` anahtarını engeller. Sonda verilen `-c model_provider=...`, `-c model_providers.anonmyz.base_url=...`, `-c model_providers.anonmyz.supports_websockets=true` veya `-c features.enable_request_compression=true` Codex'in son-değer-kazanır semantiğinde trafiği inceleme hattının dışına çıkarabilir. Bu, README'deki “request compression disabled” ve “local proxy routing” garantisini bozar (`README.md:79-83`).

**İlgili kod:**

```go
args = append(args, "-c", `features.enable_request_compression=false`)
args = append(args, "-c", `features.apps=false`)
return append(args, forwarded...)
```

**Düzeltme:** Aktarılan argümanlarda tüm rota/transport config anahtarlarını reddedin ve zorunlu override'ları en sona ekleyin. En güvenlisi, yalnız işlevsel Codex komut/flag izin listesi kullanmaktır.

```go
if isProtectedKey(key) {
    return fmt.Errorf("cannot override protected setting %q", key)
}
return append(forwarded, mandatorySecurityOverrides(baseURL)...), nil
```

Kabul testi; her `-c`, `--config`, birleşik ve büyük/küçük harf varyantında base URL, provider, WebSocket, compression ve apps override denemelerini reddetmelidir.

### SEC-03 — Yüksek — API anahtarı düz HTTP upstream'e gönderilebilir

**Konum:** `config/config.go:101-133`, `proxy/proxy.go:231-254`, `providers/*.go`
**Sınıf:** CWE-319, hassas bilginin açık metin aktarımı
**Etki:** `UPSTREAM_URL=http://remote-host` geçerli kabul edilir. Açık proxy, sağlayıcı adaptörünün hazırladığı `Authorization`, `x-api-key` veya eşdeğer gerçek kimlik bilgisini bu hedefe yollar. Kullanıcı hatası, kötü ortam enjeksiyonu veya yanlış dokümantasyon doğrudan credential ifşasına dönüşür.

**Düzeltme:** URL'yi `url.ParseRequestURI`/`url.Parse` ile bir kez yüklemede doğrulayın. Uzak hedeflerde yalnız `https`; `http` yalnız `localhost`, `127.0.0.0/8` ve `::1` için açık bir `ALLOW_INSECURE_LOOPBACK_UPSTREAM` geliştirme politikasıyla kabul edilmeli. Userinfo, fragment ve beklenmeyen query reddedilmeli.

```go
u, err := url.Parse(raw)
if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" { return errInvalid }
if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
    return errors.New("remote upstream must use HTTPS")
}
```

### SEC-04 — Yüksek — Ham stream sırrı chunk sınırında algılanmayabilir

**Konum:** `proxy/proxy.go:375-390`, `proxy/proxy.go:582-636`, `proxy/proxy.go:679-706`; MITM aynı işlemciyi kullanır (`mitm/proxy.go:528-579`)
**Sınıf:** CWE-200 / CWE-770, eksik veri sınırı doğrulaması
**Etki:** `SafeCutpoint` yalnız `[[` ile başlayan yer tutucu parçalarını bekletir. Upstream ham bir credential'ı örneğin `sk-proj-ABC` ve `DEF...` olarak iki ağ okumasına bölerse ilk parça desen tamamlanmadan istemciye flush edilir; ikinci parça da tek başına eşleşmeyebilir. “Sır içeren chunk bastırılır” güvencesi, sır tek read içinde kaldığında geçerlidir.

**Düzeltme:** Yer tutucu tamponundan bağımsız bir DLP look-behind penceresi tutun. Tüm credential desenleri için güvenli maksimum önek uzunluğunu belirleyin veya stream'i SSE event sınırında tamponlayıp event tamamlanınca tarayın. Bellek sınırı ve gecikme açıkça tanımlanmalı.

```go
combined := tail + string(chunk)
emitAt := safeSecretBoundary(combined)
candidate, tail = combined[:emitAt], combined[emitAt:]
if masker.HasCredentialSecrets(candidate + tail) { return ErrLeak }
```

Testler her desteklenen credential biçimini her byte sınırında bölmeli; yalnız yer tutucu bölme testleri yeterli değildir.

### SEC-05 — Orta — CA parola türetimi brute-force'a dirençsiz

**Konum:** `mitm/ca.go:387-446`
**Sınıf:** CWE-916, yetersiz parola tabanlı anahtar türetimi
**Etki:** Çalınan şifreli `ca.key`, hızlı SHA-256 parola denemelerine açıktır. Bu CA herhangi bir alan adı için sertifika imzalayabildiğinden anahtarın açılması yüksek güven sınırı etkisine sahiptir.

**Düzeltme:** Rastgele salt ile Argon2id veya scrypt kullanın; KDF parametrelerini sürümlü dosya zarfında saklayın. Mevcut format için migration okuyucusu bırakın, yeni yazımlarda güçlü KDF kullanın.

```go
salt := make([]byte, 16)
rand.Read(salt)
key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 2, 32)
```

### SEC-06 — Orta — Standart upstream yanıt boyutu sınırsız

**Konum:** `proxy/proxy.go:321-340`, `mitm/proxy.go:430`
**Sınıf:** CWE-400, kontrolsüz kaynak tüketimi
**Etki:** Upstream veya yerel kötü niyetli sağlayıcı sınırsız yanıtla sürecin belleğini tüketir. Dinleyici loopback olsa da upstream güven sınırının dışındadır.

**Düzeltme:** Konfigüre edilebilir yanıt limiti uygulayın; `Content-Length` erken kontrolü ve `io.LimitReader(max+1)` kullanın. Limit aşımında gövdeyi istemciye yazmadan 502/413 benzeri fail-closed hata üretin.

### SEC-07 — Orta — MITM başlık politikası açık proxy ile tutarsız

**Konum:** `proxy/proxy.go:424-489`, `mitm/proxy.go:365-386`
**Sınıf:** CWE-441 / savunma tutarsızlığı
**Etki:** Açık proxy yalnız izin listeli başlıkları aktarırken MITM tüm uçtan uca başlıkları kopyalayıp yalnız hop-by-hop listesini siler. Yeni/özel istemci başlıkları beklenmeden upstream'e taşınabilir ve cihaz/oturum metadata'sı sızdırabilir.

**Düzeltme:** İki modda ortak bir header policy kullanın. Auth passthrough gerekli başlıkları açıkça modele ekleyin; varsayılan reddetme yaklaşımını koruyun.

### SEC-08 — Düşük — HTTP güvenlik başlıkları ve yöntem politikası eksik

**Konum:** `main.go:93-103`, `audit/audit.go:82-90`, `metrics/metrics.go:425-501`
**Etki:** Loopback sınırı riski düşürür; yine de dashboard için `Content-Security-Policy`, `X-Content-Type-Options` ve açık yöntem kontrolü yoktur. Yerel kötü amaçlı web içeriği loopback uçlarına cross-origin istek başlatabilir; SOP yanıt okumayı sınırlasa da yan etkisiz GET yüzeyi gereksiz geniştir.

**Düzeltme:** Gözlemlenebilirlik uçlarında yalnız GET/HEAD, `Cache-Control: no-store`, CSP ve `X-Content-Type-Options: nosniff` uygulayın; gerekirse rastgele oturum token'ı kullanın.

## Hassas veri ve hardcoded secret sonucu

- Git tarafından izlenen metinlerde yapılan desen taraması gerçek olduğuna dair kanıt bulunan credential göstermedi.
- `.env.example`, demo ve testlerdeki değerler açıkça `REPLACE`, `FAKE`, `EXAMPLE` veya test fixture niteliğinde (`.env.example:15-21`, `demo.go:52-53`, `main_test.go:98`). Bunlar gerçek sır olarak sınıflandırılmadı.
- VS Code, anahtarı SecretStorage'dan alır (`extension.js:179-190`) fakat child sürece ortam değişkeniyle geçirir (`extension.js:103-118`). JetBrains yalnız ortamdan okur (`FirewallPlugin.kt:29-46`). Child process'in güvenilirliği bu nedenle kritik kontrol noktasıdır.
- Audit kaydı ham değer veya hash saklamaz; yalnız tip ve yer tutucu metadata'sı tutar (`audit/audit.go:15-32`, `masker/masker.go:94-102`).
- Açık proxy, istek başlığındaki authentication değerini passthrough modunda bilerek aktarır (`proxy/proxy.go:428-461`); ürün request body DLP'sidir, auth header kasası değildir.

## Mevcut güçlü kontroller

- Her iki dinleyici loopback'e bağlanır (`main.go:105-106`, `main.go:143-145`).
- Gözlem uçları ayrıca uzak adres kontrolü uygular (`main.go:208-238`).
- İstek gövdesi 32 MiB ile sınırlıdır; sıkıştırılmış istek reddedilir (`proxy/proxy.go:105-111`, `proxy/proxy.go:173-176`).
- Redirect otomatik takip edilmez (`proxy/proxy.go:82-86`).
- MITM hedefi izin listesi ve gerçek suffix kontrolü kullanır (`mitm/proxy.go:132-169`).
- MITM upstream TLS 1.2+ ve sertifika doğrulaması kullanır (`mitm/proxy.go:78-86`).
- CA dizini `0700`, özel anahtar `0600` yazılır (`mitm/ca.go:239-258`).
- Vault-full halinde plaintext göndermek yerine istek engellenir (`proxy/proxy.go:199-217`).

## Uyumluluk değerlendirmesi

| Alan | Durum | Açıklama |
|---|---|---|
| Veri minimizasyonu | Kısmen güçlü | Ham sır audit'e yazılmıyor; yalnız process memory'de request scope. |
| Saklama sınırlaması | Güçlü | Audit 200 kayıtla sınırlı, vault response sonunda sıfırlanıyor. |
| Aktarım güvenliği | Eksik | Uzak `http://` upstream normal modda reddedilmiyor (SEC-03). |
| Erişim kontrolü | Kısmen güçlü | Loopback bağlama var; yerel kullanıcı/process sınırı güvenilir kabul edilmiş. |
| Tedarik zinciri | Eksik | IDE workspace ikilisi doğrulanmıyor; CI action/image digest pinleri yok. |
| Denetlenebilirlik | Orta | Güvenli metadata var; güvenlik olay formatı ve kalıcı, kullanıcı kontrollü export politikası yok. |

GDPR, KVKK, SOC 2 veya ISO 27001 uyumluluğu yalnız bu kodla ileri sürülemez; veri sorumlusu süreçleri, hukuki dayanak, saklama politikası, erişim kayıtları ve operasyonel kontroller ayrıca kanıtlanmalıdır.
