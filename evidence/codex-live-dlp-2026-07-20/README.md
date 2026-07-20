# Codex canlı DLP doğrulama kanıtı

## Sonuç

Anonmyz, ChatGPT abonelik kimlik doğrulaması kullanan canlı Codex trafiğinde başarıyla doğrulandı. İstekteki sahte GitHub Personal Access Token (classic/v1) upstream'e gönderilmeden yerel olarak maskelendi. Upstream `200` yanıtı sonrasında placeholder yerel olarak geri yüklendi ve yanıt güvenlik filtresi tarafından bloklanmadı.

Bu testte gerçek bir secret kullanılmadı. ChatGPT oturumuna ait kimlik doğrulama başlıkları kaydedilmedi.

## Test ortamı

| Alan | Değer |
|---|---|
| Test tarihi | 2026-07-20 20:02 TRT (UTC+03:00) |
| Kanıt kayıt zamanı | 2026-07-20T20:05:03.653+03:00 |
| İşletim sistemi | Windows Home 25H2, build 26200.8875, x64 |
| Windows API ürün adı | Windows 10 Home |
| Codex | OpenAI Codex / `codex-cli 0.137.0` |
| Anonmyz | `anonmyz dev (ai-firewall compatible)` |
| Git tanımı | `v0.1.0-1-g925cdec-dirty` |
| HEAD commit SHA | `925cdecbd6f77ff97d9af355188aa86f7ecb0bf6` |
| Test edilen executable | `anonmyz-fixed.exe` |
| Executable SHA-256 | `C061DF8C793712C9D67EA0A3E3177AD7ADE9D20AFB427DA21A371C6BD8F37C16` |
| Kimlik doğrulama | ChatGPT subscription |
| Upstream | `https://chatgpt.com/backend-api/codex` |
| Sahte credential türü | GitHub Personal Access Token classic/v1 (`ghp_…` biçimi) |

> Not: Çalışma ağacı test sırasında kirliydi. HEAD commit SHA yalnızca temel commit'i gösterir; test edilen yerel binary'yi kesin olarak tanımlayan değer executable SHA-256 özetidir.

## Başarı ölçütleri ve gözlenen değerler

| Ölçüt | Gözlenen | Sonuç |
|---|---:|---|
| İstek proxy üzerinden geçti | `POST /responses` | Başarılı |
| Upstream yanıtı | `status=200` | Başarılı |
| Hassas değer algılandı | `detections=1` | Başarılı |
| Orijinal değer upstream öncesi engellendi | `prevented=true` | Başarılı |
| Yerel geri yükleme yapıldı | `restored=3` | Başarılı |
| Yanıt güvenlik filtresince bloklandı | `response_blocked=false` | Başarılı |
| Uçtan uca doğrulama | `VERIFIED` | Başarılı |

`restored=3`, tek algılanan placeholder'ın Codex'in yapılandırılmış yanıtında üç konumda geri yüklenmesini ifade eder; üç farklı credential algılandığı anlamına gelmez.

## Kanıt dosyaları

- `terminal-session.masked.txt`: Başarılı terminal oturumunun maskelenmiş kaydı.
- `audit-summary.masked.json`: Terminal sonu session evidence verisinden oluşturulan, ham değer içermeyen audit özeti.
- `executable.sha256.txt`: Test edilen executable'ın SHA-256 özeti.

## Sınırlamalar

- Test girdisi kasıtlı olarak tamamen sahteydi; gerçek credential ile test yapılmadı ve yapılmamalıdır.
- `unknown variant max` mesajı Codex `0.137.0` model önbelleği uyumluluk uyarısıdır. Model isteği ve DLP doğrulaması başarılı tamamlandığı için test sonucunu etkilememiştir.
- Audit kaydı ham credential değerini içermez; yalnızca secret türü, placeholder kimliği ve güvenlik sonucu tutulur.
