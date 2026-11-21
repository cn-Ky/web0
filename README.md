# Web0

Türkçe, terminal tabanlı, **yalnızca bilgi toplayan** web güvenliği keşif ve
denetim aracı. Rust ile yazılmıştır; Windows, macOS ve Linux'ta tek bir
bağımsız (standalone) çalıştırılabilir dosya olarak çalışır.

> **Bu araç saldırı, exploit çalıştırma, brute-force veya parola deneme
> özelliği İÇERMEZ ve içermeyecektir.** Yalnızca pasif/aktif *keşif* yapar:
> DNS, WHOIS, TLS sertifikası, HTTP güvenlik başlıkları, çerez/CORS
> yapılandırması, teknoloji parmak izi, `robots.txt`/`sitemap.xml`,
> bilinen hassas dosya/yol kontrolü, yaygın port tarama ve alt alan adı
> keşfi (crt.sh).
>
> **Sorumluluk tamamen kullanıcıya aittir.** Bu aracı yalnızca sahibi
> olduğunuz veya yazılı test izni aldığınız sistemlerde kullanın.

## Özellikler

- Daktilo efektli açılış animasyonu ve ASCII-art logo
- Tamamen Türkçe komutlar ve çıktı
- DNS kayıtları (A/AAAA/NS/MX/TXT/CAA/SOA), SPF/DMARC/CAA eksiklik kontrolü
- WHOIS (ham soket sorgusu, harici servis gerekmez)
- TLS sertifika detayları (konu, veren, SAN, kalan gün, protokol)
- HTTP güvenlik başlıkları (HSTS, CSP, X-Frame-Options vb.) + 100 üzerinden skor
- Çerez bayrak kontrolü (Secure/HttpOnly/SameSite)
- CORS yanlış yapılandırma testi (keyfi origin yansıtma)
- Sayfa analizi: başlık, harici scriptler, SRI eksikliği, karışık içerik, e-postalar
- Teknoloji parmak izi (WordPress, Next.js, React, Laravel, Supabase vb.)
  + bilgilendirici CVE sınıfı notları (exploit kodu değil)
- `robots.txt` / `sitemap.xml` / `security.txt` kontrolü
- ~35 bilinen hassas yol/dosya kontrolü (`.git`, `.env`, yedek dosyaları,
  Swagger, actuator, Adminer vb.) — yalnızca durum kodunu değil, içeriği
  doğrulayarak yanlış pozitifleri azaltır
- Yaygın port tarama (22 port) ve riskli (internete açık olmaması gereken)
  portların işaretlenmesi
- crt.sh üzerinden pasif alt alan adı keşfi
- JSON ve görsel HTML rapor çıktısı

## Kullanım

```bash
web0 example.com
web0 example.com --altalanlar
web0 example.com --derin --onay
web0 example.com --portlar --onay
web0 example.com --tumu --onay --json rapor.json --html rapor.html
web0 example.com --sessiz --renksiz   # animasyonsuz, sade çıktı
```

| Bayrak         | Açıklama                                         |
|----------------|---------------------------------------------------|
| `--altalanlar` | crt.sh ile alt alan adı keşfi (pasif)             |
| `--derin`      | Hassas dosya/yol kontrolü (aktif)                 |
| `--portlar`    | Yaygın port tarama (aktif)                        |
| `--tumu`       | Tüm modülleri çalıştırır                          |
| `--onay`       | Aktif modüller için izin onayını atlar            |
| `--guvensiz`   | TLS sertifika doğrulamasını atlar                 |
| `--json DOSYA` | Sonuçları JSON olarak kaydeder                    |
| `--html DOSYA` | Sonuçları görsel HTML rapor olarak kaydeder        |
| `--sessiz`     | Açılış animasyonunu atlar                          |
| `--renksiz`    | Renkli çıktıyı kapatır                             |

## Lisans

MIT — lisans ve kullanım sorumluluğu tamamen size aittir.
