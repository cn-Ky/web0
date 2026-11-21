use crate::modules::{Sonuclar, YAYGIN_PORTLAR};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn renk(skor: u32) -> &'static str {
    if skor >= 80 {
        "#22c55e"
    } else if skor >= 50 {
        "#eab308"
    } else {
        "#ef4444"
    }
}

fn liste_html(baslik: &str, ogeler: &[String]) -> String {
    if ogeler.is_empty() {
        return String::new();
    }
    let maddeler: String = ogeler.iter().map(|o| format!("<li>{}</li>", esc(o))).collect();
    format!("<h3>{}</h3><ul>{}</ul>", esc(baslik), maddeler)
}

pub fn html_rapor_uret(sonuc: &Sonuclar) -> String {
    let skor = sonuc.http.as_ref().map(|h| h.baslik_skoru).unwrap_or(0);
    let mut s = String::new();
    s.push_str(&format!(
        r#"<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<title>Web0 Raporu — {hedef}</title>
<style>
:root{{color-scheme: light dark;}}
body{{font-family: 'Segoe UI', system-ui, sans-serif; max-width: 920px; margin: 40px auto; padding: 0 20px;
background:#0b1220; color:#e5e7eb;}}
h1{{font-size: 28px;}} h2{{border-bottom:1px solid #334155; padding-bottom:6px; margin-top:34px;}}
.kart{{background:#111827; border:1px solid #1f2937; border-radius:10px; padding:16px 20px; margin:14px 0;}}
.skor{{display:inline-block; font-size:34px; font-weight:800; color:{renk};}}
ul{{margin:6px 0 14px 20px;}} li{{margin:3px 0;}}
.etiket{{display:inline-block; background:#1f2937; color:#93c5fd; border-radius:6px; padding:2px 8px; margin:2px;}}
footer{{margin-top:40px; color:#6b7280; font-size:12px;}}
</style></head><body>
<h1>Web0 Guvenlik Raporu</h1>
<p><b>Hedef:</b> {hedef} &nbsp;|&nbsp; <b>Zaman:</b> {zaman}</p>
<div class="kart"><span class="skor">{skor}/100</span> &nbsp;guvenlik basligi skoru</div>"#,
        hedef = esc(&sonuc.hedef),
        zaman = esc(&sonuc.zaman),
        renk = renk(skor),
        skor = skor
    ));

    if let Some(dns) = &sonuc.dns {
        s.push_str("<div class=\"kart\"><h2>DNS</h2>");
        s.push_str(&liste_html("A", &dns.a));
        s.push_str(&liste_html("AAAA", &dns.aaaa));
        s.push_str(&liste_html("NS", &dns.ns));
        s.push_str(&liste_html("MX", &dns.mx));
        s.push_str(&liste_html("TXT", &dns.txt));
        s.push_str(&liste_html("CAA", &dns.caa));
        if let Some(ip) = &dns.cozumlenen_ip {
            s.push_str(&format!("<p><b>Cozumlenen IP:</b> {}</p>", esc(ip)));
        }
        s.push_str("</div>");
    }

    if let Some(tls) = &sonuc.tls {
        s.push_str(&format!(
            r#"<div class="kart"><h2>TLS / Sertifika</h2>
            <p><b>Konu:</b> {konu}<br>
            <b>Veren:</b> {veren}<br>
            <b>Kalan gun:</b> {kalan}<br>
            <b>Protokol:</b> {protokol}</p></div>"#,
            konu = esc(tls.konu_cn.as_deref().unwrap_or("-")),
            veren = esc(tls.veren.as_deref().unwrap_or("-")),
            kalan = tls.kalan_gun.map(|d| d.to_string()).unwrap_or("-".into()),
            protokol = esc(tls.protokol.as_deref().unwrap_or("-"))
        ));
    }

    if let Some(h) = &sonuc.http {
        let eksikler: String = h
            .eksik_basliklar
            .iter()
            .map(|e| format!("<span class=\"etiket\">{}</span>", esc(e)))
            .collect();
        let teknolojiler: String = h
            .teknolojiler
            .iter()
            .map(|t| format!("<span class=\"etiket\">{}</span>", esc(t)))
            .collect();
        let cve_liste: Vec<String> = h
            .cve_notlari
            .iter()
            .map(|(ad, not_)| format!("{}: {}", ad, not_))
            .collect();
        s.push_str(&format!(
            r#"<div class="kart"><h2>HTTP &amp; Basliklar</h2>
            <p><b>Durum:</b> {durum} &nbsp; <b>Baslik:</b> {baslik}</p>
            <p><b>Eksik guvenlik basliklari:</b><br>{eksikler}</p>
            <p><b>Tespit edilen teknolojiler:</b><br>{teknolojiler}</p>
            {cve}
            </div>"#,
            durum = h.durum.map(|d| d.to_string()).unwrap_or("-".into()),
            baslik = esc(if h.sayfa_basligi.is_empty() { "-" } else { &h.sayfa_basligi }),
            eksikler = if eksikler.is_empty() { "—".into() } else { eksikler },
            teknolojiler = if teknolojiler.is_empty() { "—".into() } else { teknolojiler },
            cve = liste_html("CVE / bilgi notlari", &cve_liste)
        ));
    }

    if !sonuc.dosyalar.is_empty() {
        s.push_str(&format!(
            "<div class=\"kart\"><h2>Robots / Sitemap</h2>{}</div>",
            liste_html("Bulunan dosyalar", &sonuc.dosyalar)
        ));
    }

    if !sonuc.hassas_yollar.is_empty() {
        let liste: Vec<String> = sonuc
            .hassas_yollar
            .iter()
            .map(|(y, d, n)| format!("{} [{}] {}", y, d, n))
            .collect();
        s.push_str(&format!(
            "<div class=\"kart\"><h2>Hassas Yol Taramasi</h2>{}</div>",
            liste_html("Bulgular", &liste)
        ));
    }

    if !sonuc.portlar.is_empty() {
        let liste: Vec<String> = sonuc
            .portlar
            .iter()
            .map(|p| {
                let ad = YAYGIN_PORTLAR.iter().find(|(pp, _)| pp == p).map(|(_, a)| *a).unwrap_or("?");
                format!("{}/tcp - {}", p, ad)
            })
            .collect();
        s.push_str(&format!(
            "<div class=\"kart\"><h2>Acik Portlar</h2>{}</div>",
            liste_html("Portlar", &liste)
        ));
    }

    if !sonuc.altalanlar.is_empty() {
        let kisitli: Vec<String> = sonuc.altalanlar.iter().take(150).cloned().collect();
        s.push_str(&format!(
            "<div class=\"kart\"><h2>Alt Alan Adlari ({})</h2>{}</div>",
            sonuc.altalanlar.len(),
            liste_html("Liste", &kisitli)
        ));
    }

    s.push_str(&format!(
        r#"<footer>Web0 v{surum} tarafindan uretildi. Bu rapor yalnizca bilgilendirme amaclidir;
        sahibi olunan veya yazili izinli sistemler disinda kullanilmamalidir.</footer></body></html>"#,
        surum = crate::SURUM
    ));
    s
}
