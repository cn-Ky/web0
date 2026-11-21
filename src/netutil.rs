use std::collections::HashMap;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const UA: &str = "Web0/2.0.0 (+guvenlik-denetimi)";

#[derive(Debug, Clone)]
pub struct AyristirilmisUrl {
    pub sema: String,
    pub host: String,
    pub port: u16,
    pub yol: String,
}
impl AyristirilmisUrl {
    pub fn taban(&self) -> String {
        format!("{}://{}", self.sema, self.host_port())
    }
    fn host_port(&self) -> String {
        let varsayilan = if self.sema == "https" { 443 } else { 80 };
        if self.port == varsayilan {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Basit bir URL ayristirici (harici crate kullanmadan): sema://host[:port][/yol]
pub fn url_ayristir(u: &str) -> Option<AyristirilmisUrl> {
    let (sema, geri_kalan) = u.split_once("://")?;
    let sema = sema.to_lowercase();
    let (host_port, yol) = match geri_kalan.find('/') {
        Some(i) => (&geri_kalan[..i], geri_kalan[i..].to_string()),
        None => (geri_kalan, "/".to_string()),
    };
    let (host, port) = if host_port.starts_with('[') {
        (host_port.to_string(), if sema == "https" { 443 } else { 80 })
    } else if let Some(i) = host_port.rfind(':') {
        if let Ok(p) = host_port[i + 1..].parse::<u16>() {
            (host_port[..i].to_string(), p)
        } else {
            (host_port.to_string(), if sema == "https" { 443 } else { 80 })
        }
    } else {
        (host_port.to_string(), if sema == "https" { 443 } else { 80 })
    };
    if host.is_empty() {
        return None;
    }
    Some(AyristirilmisUrl { sema, host, port, yol })
}

pub fn ip_adresi_mi(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[derive(Debug, Clone)]
pub struct HttpYanit {
    pub durum: u16,
    pub basliklar: Vec<(String, String)>,
    pub govde: Vec<u8>,
    pub url: String,
}

fn baslik_al<'a>(basliklar: &'a [(String, String)], ad: &str) -> Option<&'a str> {
    basliklar
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(ad))
        .map(|(_, v)| v.as_str())
}
pub fn baslik_degeri(basliklar: &[(String, String)], ad: &str) -> Option<String> {
    baslik_al(basliklar, ad).map(|s| s.to_string())
}
pub fn tum_baslik_degerleri(basliklar: &[(String, String)], ad: &str) -> Vec<String> {
    basliklar
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(ad))
        .map(|(_, v)| v.clone())
        .collect()
}

fn agent_olustur(dogrula: bool) -> ureq::Agent {
    let mut tls_kurucu = native_tls::TlsConnector::builder();
    if !dogrula {
        tls_kurucu.danger_accept_invalid_certs(true);
        tls_kurucu.danger_accept_invalid_hostnames(true);
    }
    let baglayici = tls_kurucu
        .build()
        .expect("TLS baglayicisi olusturulamadi");
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .tls_connector(std::sync::Arc::new(baglayici))
        .build()
}

/// Tek bir HTTP istegi atar; yonlendirmeleri KENDISI takip etmez
/// (zincir_takip fonksiyonu bunu yapar).
pub fn tek_istek(
    url: &str,
    yontem: &str,
    dogrula: bool,
    ek_basliklar: &[(&str, &str)],
) -> Result<HttpYanit, String> {
    let agent = agent_olustur(dogrula);
    let mut istek = agent.request(yontem, url).set("User-Agent", UA);
    for (k, v) in ek_basliklar {
        istek = istek.set(k, v);
    }
    let sonuc = istek.call();
    let yanit = match sonuc {
        Ok(r) => r,
        Err(ureq::Error::Status(_kod, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let durum = yanit.status();
    let son_url = yanit.get_url().to_string();
    let mut basliklar = Vec::new();
    for ad in yanit.headers_names() {
        if let Some(deger) = yanit.header(&ad) {
            basliklar.push((ad.clone(), deger.to_string()));
        }
    }
    let mut govde = Vec::new();
    if yontem != "HEAD" {
        use std::io::Read;
        let mut okuyucu = yanit.into_reader().take(400_000);
        okuyucu.read_to_end(&mut govde).ok();
    }
    Ok(HttpYanit { durum, basliklar, govde, url: son_url })
}

pub struct YonlendirmeAdimi {
    pub url: String,
    pub durum: Option<u16>,
    pub hata: Option<String>,
}

pub fn zincir_takip(baslangic: &str, dogrula: bool, maks: usize) -> (Vec<YonlendirmeAdimi>, Option<HttpYanit>) {
    let mut zincir = Vec::new();
    let mut mevcut = baslangic.to_string();
    for _ in 0..maks {
        match tek_istek(&mevcut, "GET", dogrula, &[]) {
            Ok(r) => {
                zincir.push(YonlendirmeAdimi { url: mevcut.clone(), durum: Some(r.durum), hata: None });
                if (300..400).contains(&r.durum) {
                    if let Some(loc) = baslik_degeri(&r.basliklar, "Location") {
                        mevcut = birlesik_url(&mevcut, &loc);
                        continue;
                    }
                }
                return (zincir, Some(r));
            }
            Err(e) => {
                zincir.push(YonlendirmeAdimi { url: mevcut.clone(), durum: None, hata: Some(e) });
                return (zincir, None);
            }
        }
    }
    (zincir, None)
}

fn birlesik_url(taban: &str, hedef: &str) -> String {
    if hedef.starts_with("http://") || hedef.starts_with("https://") {
        return hedef.to_string();
    }
    if let Some(u) = url_ayristir(taban) {
        if hedef.starts_with('/') {
            return format!("{}://{}{}", u.sema, u.host_port(), hedef);
        }
        return format!("{}://{}/{}", u.sema, u.host_port(), hedef);
    }
    hedef.to_string()
}

#[derive(Debug, Default, serde::Serialize)]
pub struct TlsBilgisi {
    pub konu_cn: Option<String>,
    pub veren: Option<String>,
    pub gecerlilik_baslangic: Option<String>,
    pub gecerlilik_bitis: Option<String>,
    pub kalan_gun: Option<i64>,
    pub san: Vec<String>,
    pub protokol: Option<String>,
    pub hata: Option<String>,
}

pub fn tls_bilgisi_al(host: &str, port: u16) -> TlsBilgisi {
    let adres = format!("{}:{}", host, port);
    let akis = match TcpStream::connect(&adres) {
        Ok(s) => s,
        Err(e) => return TlsBilgisi { hata: Some(e.to_string()), ..Default::default() },
    };
    akis.set_read_timeout(Some(Duration::from_secs(8))).ok();
    akis.set_write_timeout(Some(Duration::from_secs(8))).ok();

    let baglayici = match native_tls::TlsConnector::new() {
        Ok(c) => c,
        Err(e) => return TlsBilgisi { hata: Some(e.to_string()), ..Default::default() },
    };
    let tls_akisi = match baglayici.connect(host, akis) {
        Ok(s) => s,
        Err(e) => return TlsBilgisi { hata: Some(e.to_string()), ..Default::default() },
    };

    let mut bilgi = TlsBilgisi::default();
    bilgi.protokol = Some("TLS (native-tls)".to_string());

    match tls_akisi.peer_certificate() {
        Ok(Some(sertifika)) => {
            if let Ok(der) = sertifika.to_der() {
                if let Ok((_, sert)) = x509_parser::parse_x509_certificate(&der) {
                    bilgi.konu_cn = sert
                        .subject()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok())
                        .map(|s| s.to_string());
                    bilgi.veren = sert
                        .issuer()
                        .iter_organization()
                        .next()
                        .and_then(|o| o.as_str().ok())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            sert.issuer()
                                .iter_common_name()
                                .next()
                                .and_then(|cn| cn.as_str().ok())
                                .map(|s| s.to_string())
                        });
                    let gecerlilik = sert.validity();
                    bilgi.gecerlilik_baslangic = Some(gecerlilik.not_before.to_string());
                    bilgi.gecerlilik_bitis = Some(gecerlilik.not_after.to_string());
                    let simdi = x509_parser::time::ASN1Time::now();
                    bilgi.kalan_gun = Some((gecerlilik.not_after.timestamp() - simdi.timestamp()) / 86400);
                    if let Ok(Some(san)) = sert.subject_alternative_name() {
                        for genel_ad in san.value.general_names.iter() {
                            if let x509_parser::extensions::GeneralName::DNSName(ad) = genel_ad {
                                bilgi.san.push(ad.to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(None) => {
            bilgi.hata = Some("Sunucu sertifikasi alinamadi".to_string());
        }
        Err(e) => {
            bilgi.hata = Some(e.to_string());
        }
    }
    bilgi
}

pub fn dns_coz(host: &str, port: u16) -> Option<IpAddr> {
    format!("{}:{}", host, port).to_socket_addrs().ok()?.next().map(|s| s.ip())
}

pub fn tcp_acik_mi(ip: IpAddr, port: u16, zaman_asimi_ms: u64) -> bool {
    let adres = std::net::SocketAddr::new(ip, port);
    TcpStream::connect_timeout(&adres, Duration::from_millis(zaman_asimi_ms)).is_ok()
}

/// dns.google DNS-over-HTTPS JSON sorgulari.
pub fn doh_sorgula(ad: &str, tip: &str) -> Vec<String> {
    let url = format!("https://dns.google/resolve?name={}&type={}", urlencode(ad), tip);
    match tek_istek(&url, "GET", true, &[("Accept", "application/dns-json")]) {
        Ok(r) => {
            if let Ok(deger) = serde_json::from_slice::<serde_json::Value>(&r.govde) {
                if let Some(cevap) = deger.get("Answer").and_then(|v| v.as_array()) {
                    return cevap
                        .iter()
                        .filter_map(|e| e.get("data").and_then(|d| d.as_str()))
                        .map(|s| s.to_string())
                        .collect();
                }
            }
            Vec::new()
        }
        Err(_) => Vec::new(),
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[allow(dead_code)]
pub fn basliklar_map(basliklar: &[(String, String)]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (k, v) in basliklar {
        m.insert(k.clone(), v.clone());
    }
    m
}
