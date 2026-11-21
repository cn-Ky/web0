use crate::banner::{bilgi, bolum, hata, kv, tamam, uyari};
use crate::netutil::{self, baslik_degeri, tum_baslik_degerleri, TlsBilgisi};
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Serialize, Default)]
pub struct Sonuclar {
    pub hedef: String,
    pub zaman: String,
    pub arac: String,
    pub dns: Option<DnsSonuc>,
    pub whois: Vec<String>,
    pub tls: Option<TlsBilgisi>,
    pub http: Option<HttpSonuc>,
    pub dosyalar: Vec<String>,
    pub hassas_yollar: Vec<(String, u16, String)>,
    pub portlar: Vec<u16>,
    pub altalanlar: Vec<String>,
}
impl Sonuclar {
    pub fn yeni(hedef: &str) -> Self {
        Sonuclar {
            hedef: hedef.to_string(),
            zaman: chrono_benzeri_zaman(),
            arac: format!("web0 {}", crate::SURUM),
            ..Default::default()
        }
    }
}

fn chrono_benzeri_zaman() -> String {
    // Harici tarih/saat crate'i olmadan basit bir UNIX zaman damgasi.
    let simdi = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}", simdi.as_secs())
}

#[derive(Serialize, Default)]
pub struct DnsSonuc {
    pub a: Vec<String>,
    pub aaaa: Vec<String>,
    pub ns: Vec<String>,
    pub mx: Vec<String>,
    pub txt: Vec<String>,
    pub caa: Vec<String>,
    pub soa: Vec<String>,
    pub cozumlenen_ip: Option<String>,
}

pub fn mod_dns(host: &str, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("DNS KAYITLARI", renkli);
    let mut d = DnsSonuc::default();
    d.a = netutil::doh_sorgula(host, "A");
    d.aaaa = netutil::doh_sorgula(host, "AAAA");
    d.ns = netutil::doh_sorgula(host, "NS");
    d.mx = netutil::doh_sorgula(host, "MX");
    d.txt = netutil::doh_sorgula(host, "TXT");
    d.caa = netutil::doh_sorgula(host, "CAA");
    d.soa = netutil::doh_sorgula(host, "SOA");
    for (ad, deger) in [
        ("A", &d.a),
        ("AAAA", &d.aaaa),
        ("NS", &d.ns),
        ("MX", &d.mx),
        ("TXT", &d.txt),
        ("CAA", &d.caa),
        ("SOA", &d.soa),
    ] {
        for v in deger {
            kv(ad, &v.chars().take(150).collect::<String>(), renkli);
        }
    }
    let tum_txt = d.txt.join(" ");
    if !tum_txt.contains("v=spf1") {
        uyari("SPF kaydi bulunamadi (e-posta sahteciligi riski)", renkli);
    }
    let dmarc = netutil::doh_sorgula(&format!("_dmarc.{}", host), "TXT");
    if dmarc.is_empty() {
        uyari("DMARC kaydi bulunamadi", renkli);
    }
    if d.caa.is_empty() {
        bilgi("CAA kaydi yok (sertifika yetkilisi kisitlamasi tanimli degil)", renkli);
    }
    if let Some(ip) = netutil::dns_coz(host, 80) {
        kv("Cozumlenen IP", &ip.to_string(), renkli);
        d.cozumlenen_ip = Some(ip.to_string());
    } else {
        hata("Host cozumlenemedi", renkli);
    }
    sonuc.dns = Some(d);
}

pub fn mod_whois(host: &str, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("WHOIS", renkli);
    match whois_sorgula("whois.iana.org", host) {
        Ok(ilk) => {
            let mut metin = ilk;
            if let Some(yakalama) = Regex::new(r"refer:\s*(\S+)").unwrap().captures(&metin) {
                let sunucu = yakalama.get(1).unwrap().as_str().to_string();
                if let Ok(detay) = whois_sorgula(&sunucu, host) {
                    metin = detay;
                }
            }
            let anahtarlar = [
                "registrar", "creation", "created", "expir", "updated", "name server",
                "status", "organization", "org", "country", "dnssec",
            ];
            let mut gorulen = HashSet::new();
            let mut out = Vec::new();
            for satir in metin.lines() {
                if let Some(idx) = satir.find(':') {
                    let anahtar_kucuk = satir[..idx].to_lowercase();
                    if anahtarlar.iter().any(|a| anahtar_kucuk.contains(a)) {
                        let temiz = satir.trim().to_string();
                        if gorulen.insert(temiz.clone()) {
                            out.push(temiz);
                        }
                    }
                }
            }
            for satir in out.iter().take(20) {
                println!("  {}", satir);
            }
            sonuc.whois = out;
        }
        Err(e) => uyari(&format!("WHOIS alinamadi: {}", e), renkli),
    }
}

fn whois_sorgula(sunucu: &str, sorgu: &str) -> Result<String, String> {
    let adres = format!("{}:43", sunucu);
    let mut akis = TcpStream::connect(&adres).map_err(|e| e.to_string())?;
    akis.set_read_timeout(Some(Duration::from_secs(8))).ok();
    akis.set_write_timeout(Some(Duration::from_secs(8))).ok();
    use std::io::Write as _;
    akis.write_all(format!("{}\r\n", sorgu).as_bytes())
        .map_err(|e| e.to_string())?;
    let mut veri = Vec::new();
    akis.read_to_end(&mut veri).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&veri).to_string())
}

pub fn mod_tls(host: &str, port: u16, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("TLS / SERTIFIKA", renkli);
    let bilgi_sonuc = netutil::tls_bilgisi_al(host, port);
    if let Some(e) = &bilgi_sonuc.hata {
        uyari(&format!("TLS baglantisi kurulamadi: {}", e), renkli);
    } else {
        kv("Konu (CN)", bilgi_sonuc.konu_cn.as_deref().unwrap_or("-"), renkli);
        kv("Veren", bilgi_sonuc.veren.as_deref().unwrap_or("-"), renkli);
        kv(
            "Gecerlilik",
            &format!(
                "{} -> {}  ({} gun kaldi)",
                bilgi_sonuc.gecerlilik_baslangic.as_deref().unwrap_or("-"),
                bilgi_sonuc.gecerlilik_bitis.as_deref().unwrap_or("-"),
                bilgi_sonuc.kalan_gun.map(|d| d.to_string()).unwrap_or("-".into())
            ),
            renkli,
        );
        if !bilgi_sonuc.san.is_empty() {
            kv("SAN", &bilgi_sonuc.san.join(", "), renkli);
        }
        kv("Protokol", bilgi_sonuc.protokol.as_deref().unwrap_or("-"), renkli);
        if let Some(kalan) = bilgi_sonuc.kalan_gun {
            if kalan < 0 {
                hata("Sertifikanin SURESI DOLMUS", renkli);
            } else if kalan < 21 {
                uyari("Sertifika 21 gunden kisa surede dolacak", renkli);
            } else {
                tamam("Sertifika gecerli", renkli);
            }
        }
    }
    sonuc.tls = Some(bilgi_sonuc);
}

const GUVENLIK_BASLIKLARI: &[(&str, &str)] = &[
    ("strict-transport-security", "HSTS yok (HTTPS dusurme saldirilarina acik)"),
    ("content-security-policy", "CSP yok (XSS etkisini azaltacak katman yok)"),
    ("x-frame-options", "X-Frame-Options yok (clickjacking riski)"),
    ("x-content-type-options", "X-Content-Type-Options yok (MIME sniffing)"),
    ("referrer-policy", "Referrer-Policy yok"),
    ("permissions-policy", "Permissions-Policy yok"),
];
const SIZINTI_BASLIKLARI: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "via",
    "x-runtime",
];
const TEKNOLOJI_IMZALARI: &[(&str, &str)] = &[
    (r"wp-content|wp-includes", "WordPress"),
    (r"Drupal|sites/default/files", "Drupal"),
    (r"Joomla", "Joomla"),
    (r"cdn\.shopify\.com", "Shopify"),
    (r"__NEXT_DATA__|/_next/", "Next.js"),
    (r"__NUXT__|/_nuxt/", "Nuxt"),
    (r"ng-version|ng-app", "Angular"),
    (r"data-reactroot|react", "React"),
    (r"vue(\.min)?\.js|data-v-", "Vue.js"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"cloudflare", "Cloudflare"),
    (r"gtag\(|googletagmanager", "Google Analytics/GTM"),
    (r"supabase", "Supabase"),
    (r"firebase", "Firebase"),
    (r"laravel_session|csrf-token", "Laravel (olasi)"),
    (r"csrfmiddlewaretoken", "Django (olasi)"),
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java"),
    (r"ASP\.NET", "ASP.NET"),
    (r"nginx", "Nginx"),
    (r"Apache", "Apache"),
];
const CVE_REFERANS: &[(&str, &str)] = &[
    ("WordPress", "Eklenti/tema kaynakli CVE'ler sik gorulur - surum ve eklenti listesini kontrol edin."),
    ("Drupal", "CVE-2018-7600 (Drupalgeddon2) gibi RCE gecmisi var - guncel surum kontrolu onerilir."),
    ("Apache", "Surume bagli olarak path traversal CVE gecmisi - surum basligini kontrol edin."),
    ("Nginx", "Belirli surumlerde bilinen DoS/parse zafiyetleri olmustur - surumu NVD'de dogrulayin."),
    ("Laravel", "Yanlis yapilandirilmis .env / APP_DEBUG=true RCE'ye yol acabilir."),
    ("Joomla", "Eklenti kaynakli SQLi/RCE gecmisi yaygindir - surum ve eklenti denetimi onerilir."),
];

#[derive(Serialize, Default)]
pub struct HttpSonuc {
    pub durum: Option<u16>,
    pub son_url: Option<String>,
    pub baslik_skoru: u32,
    pub eksik_basliklar: Vec<String>,
    pub cerezler: Vec<String>,
    pub cors_aco: Option<String>,
    pub sayfa_basligi: String,
    pub harici_scriptler: Vec<String>,
    pub epostalar: Vec<String>,
    pub teknolojiler: Vec<String>,
    pub cve_notlari: Vec<(String, String)>,
}

pub fn mod_http(base: &str, dogrula: bool, sonuc: &mut Sonuclar, renkli: bool) -> Option<()> {
    bolum("HTTP YANITI", renkli);
    let (zincir, yanit) = netutil::zincir_takip(base, dogrula, 8);
    for adim in &zincir {
        let durum_metni = adim
            .durum
            .map(|d| d.to_string())
            .or_else(|| adim.hata.clone())
            .unwrap_or_default();
        kv("Yonlendirme", &format!("{} -> {}", adim.url, durum_metni), renkli);
    }
    let r = yanit?;
    let basliklar = &r.basliklar;
    let govde = String::from_utf8_lossy(&r.govde).to_string();
    kv("Durum", &r.durum.to_string(), renkli);
    kv("Son URL", &r.url, renkli);

    let mut out = HttpSonuc {
        durum: Some(r.durum),
        son_url: Some(r.url.clone()),
        ..Default::default()
    };

    bolum("GUVENLIK BASLIKLARI", renkli);
    let mut eksik = Vec::new();
    for (ad, mesaj) in GUVENLIK_BASLIKLARI {
        if let Some(deger) = baslik_degeri(basliklar, ad) {
            tamam(&format!("{}: {}", ad, &deger.chars().take(90).collect::<String>()), renkli);
        } else {
            hata(mesaj, renkli);
            eksik.push(ad.to_string());
        }
    }
    let skor = (100 * (GUVENLIK_BASLIKLARI.len() - eksik.len()) / GUVENLIK_BASLIKLARI.len()) as u32;
    kv("Baslik skoru", &format!("{}/100", skor), renkli);
    out.baslik_skoru = skor;
    out.eksik_basliklar = eksik;
    for h in SIZINTI_BASLIKLARI {
        if let Some(deger) = baslik_degeri(basliklar, h) {
            uyari(&format!("Bilgi sizintisi -> {}: {}", h, deger), renkli);
        }
    }

    bolum("CEREZLER", renkli);
    let cerezler = tum_baslik_degerleri(basliklar, "Set-Cookie");
    if cerezler.is_empty() {
        bilgi("Cerez ayarlanmiyor", renkli);
    }
    for ck in &cerezler {
        let ad = ck.split('=').next().unwrap_or("?");
        let kucuk = ck.to_lowercase();
        let mut eksik_bayrak = Vec::new();
        if !kucuk.contains("secure") {
            eksik_bayrak.push("Secure");
        }
        if !kucuk.contains("httponly") {
            eksik_bayrak.push("HttpOnly");
        }
        if !kucuk.contains("samesite") {
            eksik_bayrak.push("SameSite");
        }
        if eksik_bayrak.is_empty() {
            tamam(&format!("{}: tum bayraklar mevcut", ad), renkli);
        } else {
            uyari(&format!("{}: eksik bayrak -> {}", ad, eksik_bayrak.join(", ")), renkli);
        }
    }
    out.cerezler = cerezler;

    bolum("CORS", renkli);
    match netutil::tek_istek(base, "GET", dogrula, &[("Origin", "https://kotuamacli.ornek")]) {
        Ok(cors_yanit) => {
            let aco = baslik_degeri(&cors_yanit.basliklar, "Access-Control-Allow-Origin");
            match aco.as_deref() {
                Some("*") => uyari("Access-Control-Allow-Origin: * (herkese acik)", renkli),
                Some("https://kotuamacli.ornek") => {
                    let acc = baslik_degeri(&cors_yanit.basliklar, "Access-Control-Allow-Credentials");
                    hata(
                        &format!("Keyfi Origin yansitiliyor (credentials={})", acc.unwrap_or("?".into())),
                        renkli,
                    );
                }
                _ => tamam("Keyfi origin yansitilmiyor", renkli),
            }
            out.cors_aco = aco;
        }
        Err(e) => bilgi(&format!("CORS testi basarisiz: {}", e), renkli),
    }

    bolum("SAYFA ANALIZI", renkli);
    let baslik_re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap();
    let sayfa_basligi = baslik_re
        .captures(&govde)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    kv("Baslik", if sayfa_basligi.is_empty() { "-" } else { &sayfa_basligi }, renkli);

    let script_re = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
    let host = netutil::url_ayristir(base).map(|u| u.host).unwrap_or_default();
    let mut harici: HashSet<String> = HashSet::new();
    for c in script_re.captures_iter(&govde) {
        let src = &c[1];
        if src.starts_with("http") && !src.contains(&host) {
            if let Some(u) = netutil::url_ayristir(src) {
                harici.insert(u.host);
            }
        }
    }
    let mut harici_vec: Vec<String> = harici.into_iter().collect();
    harici_vec.sort();
    if !harici_vec.is_empty() {
        kv("Harici script kaynaklari", &harici_vec.join(", "), renkli);
    }
    if !harici_vec.is_empty() && !govde.contains("integrity=") {
        uyari("Harici scriptlerde SRI (integrity) kullanilmiyor", renkli);
    }

    let eposta_re = Regex::new(r"[\w.+-]+@[\w-]+\.[\w.-]+").unwrap();
    let mut epostalar: Vec<String> = eposta_re
        .find_iter(&govde)
        .map(|m| m.as_str().to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    epostalar.sort();
    epostalar.truncate(10);
    if !epostalar.is_empty() {
        kv("E-postalar", &epostalar.join(", "), renkli);
    }

    if r.url.starts_with("https") {
        let karisik_re = Regex::new(r#"(?i)(?:src|href)=["']http://[^"']+"#).unwrap();
        let adet = karisik_re.find_iter(&govde).count();
        if adet > 0 {
            uyari(&format!("Karisik icerik (HTTP kaynaklari): {} adet", adet), renkli);
        }
    }

    out.sayfa_basligi = sayfa_basligi;
    out.harici_scriptler = harici_vec;
    out.epostalar = epostalar;

    bolum("TEKNOLOJI PARMAK IZI", renkli);
    let mut blob = govde.clone();
    for (k, v) in basliklar {
        blob.push_str(&format!(" {}:{}", k, v));
    }
    let mut teknolojiler: Vec<String> = Vec::new();
    for (rx, ad) in TEKNOLOJI_IMZALARI {
        if Regex::new(&format!("(?i){}", rx)).unwrap().is_match(&blob) {
            teknolojiler.push(ad.to_string());
        }
    }
    for h in ["server", "x-powered-by"] {
        if let Some(deger) = baslik_degeri(basliklar, h) {
            teknolojiler.push(format!("{}={}", h, deger));
        }
    }
    teknolojiler.sort();
    teknolojiler.dedup();
    for t in &teknolojiler {
        tamam(t, renkli);
    }
    if teknolojiler.is_empty() {
        bilgi("Belirgin teknoloji tespit edilemedi", renkli);
    }

    let mut cve_notlari = Vec::new();
    for t in &teknolojiler {
        for (bilinen, not_) in CVE_REFERANS {
            if t.to_lowercase().contains(&bilinen.to_lowercase()) {
                bilgi(&format!("[Bilgi/CVE] {}: {}", bilinen, not_), renkli);
                cve_notlari.push((bilinen.to_string(), not_.to_string()));
            }
        }
    }
    out.teknolojiler = teknolojiler;
    out.cve_notlari = cve_notlari;

    sonuc.http = Some(out);
    Some(())
}

pub fn mod_dosyalar(base: &str, dogrula: bool, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("ROBOTS / SITEMAP / SECURITY.TXT", renkli);
    let mut bulunan = Vec::new();
    for p in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt"] {
        let url = format!("{}{}", base.trim_end_matches('/'), p);
        match netutil::tek_istek(&url, "GET", dogrula, &[]) {
            Ok(r) if r.durum == 200 && !r.govde.get(..300.min(r.govde.len())).map(|s| s.to_ascii_lowercase().windows(5).any(|w| w == b"<html")).unwrap_or(false) => {
                tamam(&format!("{} bulundu", p), renkli);
                bulunan.push(p.to_string());
                if p == "/robots.txt" {
                    let metin = String::from_utf8_lossy(&r.govde).to_string();
                    let yasakli: Vec<&str> = metin
                        .lines()
                        .filter(|l| l.to_lowercase().starts_with("disallow:"))
                        .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim()))
                        .filter(|v| !v.is_empty())
                        .collect();
                    if !yasakli.is_empty() {
                        kv("Disallow yollari", &yasakli.join(", "), renkli);
                    }
                }
            }
            _ => {
                if p.ends_with("security.txt") {
                    uyari(&format!("{} yok", p), renkli);
                } else {
                    bilgi(&format!("{} yok", p), renkli);
                }
            }
        }
    }
    sonuc.dosyalar = bulunan;
}

// (yol, dogrulama_anahtar_kelimesi) -- Some ise govdede bu alt dizi aranir.
const HASSAS_YOLLAR: &[(&str, Option<&str>)] = &[
    ("/.git/HEAD", Some("ref:")),
    ("/.git/config", Some("[core]")),
    ("/.env", Some("=")),
    ("/.env.bak", Some("=")),
    ("/.htaccess", Some("RewriteEngine")),
    ("/wp-config.php.bak", Some("DB_PASSWORD")),
    ("/config.php.bak", Some("<?php")),
    ("/backup.sql", Some("CREATE TABLE")),
    ("/db.sql", Some("CREATE TABLE")),
    ("/dump.sql", Some("CREATE TABLE")),
    ("/phpinfo.php", Some("phpinfo()")),
    ("/server-status", Some("Apache Server Status")),
    ("/actuator/env", Some("propertySources")),
    ("/actuator/health", Some("status")),
    ("/swagger.json", Some("swagger")),
    ("/openapi.json", Some("openapi")),
    ("/admin", None),
    ("/administrator", None),
    ("/wp-admin/", None),
    ("/wp-login.php", None),
    ("/phpmyadmin/", None),
    ("/login", None),
    ("/wp-json/wp/v2/users", Some("slug")),
    ("/package.json", Some("name")),
    ("/composer.json", Some("require")),
    ("/Dockerfile", Some("FROM ")),
    ("/docker-compose.yml", Some("services")),
    ("/.aws/credentials", Some("aws_access_key_id")),
    ("/id_rsa", Some("PRIVATE KEY")),
    ("/web.config", Some("<configuration")),
    ("/graphql", Some("data")),
    ("/debug", None),
    ("/.npmrc", Some("registry")),
];

pub fn mod_derin(base: &str, dogrula: bool, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("HASSAS DOSYA / YOL KONTROLU (aktif)", renkli);
    let bulunanlar: Mutex<Vec<(String, u16, String)>> = Mutex::new(Vec::new());
    std::thread::scope(|kapsam| {
        let mut tutamaclar = Vec::new();
        for (yol, anahtar) in HASSAS_YOLLAR {
            let base = base.to_string();
            let bulunanlar = &bulunanlar;
            tutamaclar.push(kapsam.spawn(move || {
                let url = format!("{}{}", base.trim_end_matches('/'), yol);
                if let Ok(r) = netutil::tek_istek(&url, "GET", dogrula, &[]) {
                    if r.durum == 200 || r.durum == 401 || r.durum == 403 {
                        let govde_str = String::from_utf8_lossy(&r.govde);
                        let sonuc_satir = match anahtar {
                            None => Some((yol.to_string(), r.durum, "panel/arayuz erisilebilir".to_string())),
                            Some(a) if r.durum == 200 && govde_str.contains(a) => {
                                Some((yol.to_string(), 200, "ICERIK DOGRULANDI".to_string()))
                            }
                            _ => None,
                        };
                        if let Some(s) = sonuc_satir {
                            bulunanlar.lock().unwrap().push(s);
                        }
                    }
                }
            }));
        }
        for t in tutamaclar {
            t.join().ok();
        }
    });
    let mut bulunan = bulunanlar.into_inner().unwrap();
    bulunan.sort();
    for (yol, durum, not_) in &bulunan {
        if not_ == "ICERIK DOGRULANDI" {
            hata(&format!("{}  [{}]  {}", yol, durum, not_), renkli);
        } else {
            bilgi(&format!("{}  [{}]  {}", yol, durum, not_), renkli);
        }
    }
    if bulunan.is_empty() {
        tamam("Bilinen hassas yollarda bulgu yok", renkli);
    }
    sonuc.hassas_yollar = bulunan;
}

pub const YAYGIN_PORTLAR: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"),
    (110, "POP3"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (3000, "Gelistirme"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
    (5900, "VNC"), (6379, "Redis"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"), (9200, "Elasticsearch"),
    (27017, "MongoDB"),
];
const RISKLI_PORTLAR: &[u16] = &[21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017];

pub fn mod_portlar(host: &str, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("PORT TARAMASI (aktif, yaygin portlar)", renkli);
    let ip = match netutil::dns_coz(host, 80) {
        Some(ip) => ip,
        None => {
            hata("IP cozumlenemedi", renkli);
            return;
        }
    };
    let acik: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    std::thread::scope(|kapsam| {
        let mut tutamaclar = Vec::new();
        for (port, _) in YAYGIN_PORTLAR {
            let acik = &acik;
            let port = *port;
            tutamaclar.push(kapsam.spawn(move || {
                if netutil::tcp_acik_mi(ip, port, 1500) {
                    acik.lock().unwrap().push(port);
                }
            }));
        }
        for t in tutamaclar {
            t.join().ok();
        }
    });
    let mut acik_portlar = acik.into_inner().unwrap();
    acik_portlar.sort();
    for p in &acik_portlar {
        let ad = YAYGIN_PORTLAR.iter().find(|(pp, _)| pp == p).map(|(_, a)| *a).unwrap_or("?");
        if RISKLI_PORTLAR.contains(p) {
            uyari(&format!("{}/tcp acik - {}  (internete acik olmamali)", p, ad), renkli);
        } else {
            tamam(&format!("{}/tcp acik - {}", p, ad), renkli);
        }
    }
    if acik_portlar.is_empty() {
        bilgi("Taranan portlarda acik port bulunamadi", renkli);
    }
    sonuc.portlar = acik_portlar;
}

pub fn mod_altalanlar(domain: &str, sonuc: &mut Sonuclar, renkli: bool) {
    bolum("ALT ALAN ADLARI (crt.sh - pasif)", renkli);
    let url = format!("https://crt.sh/?q=%25.{}&output=json", netutil::urlencode(domain));
    match netutil::tek_istek(&url, "GET", true, &[]) {
        Ok(r) => {
            if let Ok(veri) = serde_json::from_slice::<serde_json::Value>(&r.govde) {
                if let Some(liste) = veri.as_array() {
                    let mut altlar: HashSet<String> = HashSet::new();
                    for e in liste {
                        if let Some(nv) = e.get("name_value").and_then(|v| v.as_str()) {
                            for satir in nv.lines() {
                                let s = satir.trim().trim_start_matches("*.");
                                if s.ends_with(domain) {
                                    altlar.insert(s.to_string());
                                }
                            }
                        }
                    }
                    let mut altlar: Vec<String> = altlar.into_iter().collect();
                    altlar.sort();
                    for s in altlar.iter().take(80) {
                        println!("  {}", s);
                    }
                    if altlar.len() > 80 {
                        bilgi(&format!("... ve {} tane daha (JSON ciktisinda tamami)", altlar.len() - 80), renkli);
                    }
                    kv("Toplam", &altlar.len().to_string(), renkli);
                    sonuc.altalanlar = altlar;
                    return;
                }
            }
            uyari("crt.sh yaniti ayristirilamadi", renkli);
        }
        Err(e) => uyari(&format!("crt.sh sorgusu basarisiz: {}", e), renkli),
    }
}
