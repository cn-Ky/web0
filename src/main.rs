// Web0 - Turkce web guvenligi kesif ve denetim araci
// Platform: Windows / macOS / Linux
//
// ONEMLI: Bu arac YALNIZCA bilgi toplar (pasif/aktif KESIF) ve yapilandirma
// zayifliklarini raporlar. Saldiri, exploit calistirma, brute-force veya
// parola deneme OZELLIGI BULUNMAZ.
//
// Sorumluluk: Bu araci yalnizca sahibi oldugunuz veya yazili test izni
// aldiginiz sistemlerde kullanin.

mod banner;
mod netutil;
mod modules;
mod report;

use clap::Parser;
use std::io::Write;

pub const SURUM: &str = "2.0.0";

#[derive(Parser, Debug)]
#[command(
    name = "web0",
    version = SURUM,
    about = "Web0 - Turkce web guvenligi kesif/denetim araci",
    long_about = "Web0: DNS, WHOIS, TLS, HTTP guvenlik basliklari, teknoloji parmak izi,\n\
                  hassas dosya/yol kontrolu, port tarama ve alt alan adi kesfi yapan,\n\
                  yalnizca bilgi toplayan bir denetim aracidir."
)]
struct Argumanlar {
    /// Alan adi veya URL (ornek: example.com)
    hedef: String,

    /// crt.sh ile alt alan adi kesfi (pasif)
    #[arg(long)]
    altalanlar: bool,

    /// Hassas dosya/yol kontrolu (aktif)
    #[arg(long)]
    derin: bool,

    /// Yaygin port tarama (aktif)
    #[arg(long)]
    portlar: bool,

    /// Tum modulleri calistir
    #[arg(long)]
    tumu: bool,

    /// Test izniniz oldugunu onaylar (aktif moduller icin sorulmaz)
    #[arg(long)]
    onay: bool,

    /// TLS dogrulamasini atla
    #[arg(long)]
    guvensiz: bool,

    /// Sonuclari JSON olarak kaydet
    #[arg(long, value_name = "DOSYA")]
    json: Option<String>,

    /// Sonuclari HTML rapor olarak kaydet
    #[arg(long, value_name = "DOSYA")]
    html: Option<String>,

    /// Acilis animasyonunu atla
    #[arg(long)]
    sessiz: bool,

    /// Renkli ciktiyi kapat
    #[arg(long)]
    renksiz: bool,
}

fn main() {
    let mut a = Argumanlar::parse();
    if a.tumu {
        a.altalanlar = true;
        a.derin = true;
        a.portlar = true;
    }

    let renkli = !a.renksiz && banner::terminal_mi();
    banner::acilis_efekti(a.sessiz, renkli);

    let hedef_url = if a.hedef.contains("://") {
        a.hedef.clone()
    } else {
        format!("https://{}", a.hedef)
    };

    let ayristirilmis = match netutil::url_ayristir(&hedef_url) {
        Some(u) => u,
        None => {
            eprintln!("Gecersiz hedef: {}", a.hedef);
            std::process::exit(1);
        }
    };

    println!(
        "\n{}",
        banner::rnk(&format!(">> Hedef: {}", ayristirilmis.host), "1;37", renkli)
    );

    if (a.derin || a.portlar) && !a.onay {
        println!(
            "{}",
            banner::rnk(
                "\nAktif moduller hedefe dogrudan istek/baglanti gonderir.",
                "33",
                renkli
            )
        );
        print!("Bu sistemi test etme yetkiniz oldugunu onayliyor musunuz? (evet/hayir): ");
        std::io::stdout().flush().ok();
        let mut cevap = String::new();
        std::io::stdin().read_line(&mut cevap).ok();
        let cevap = cevap.trim().to_lowercase();
        if !["evet", "e", "yes", "y"].contains(&cevap.as_str()) {
            println!("Iptal edildi.");
            std::process::exit(0);
        }
    }

    let mut sonuc = modules::Sonuclar::yeni(&ayristirilmis.host);
    let dogrula = !a.guvensiz;
    let ip_mi = netutil::ip_adresi_mi(&ayristirilmis.host);

    if !ip_mi {
        modules::mod_dns(&ayristirilmis.host, &mut sonuc, renkli);
        modules::mod_whois(&ayristirilmis.host, &mut sonuc, renkli);
    }
    if ayristirilmis.sema == "https" {
        modules::mod_tls(&ayristirilmis.host, ayristirilmis.port, &mut sonuc, renkli);
    }
    let yanit = modules::mod_http(&ayristirilmis.taban(), dogrula, &mut sonuc, renkli);
    if yanit.is_some() {
        modules::mod_dosyalar(&ayristirilmis.taban(), dogrula, &mut sonuc, renkli);
    }
    if a.altalanlar && !ip_mi {
        let parcalar: Vec<&str> = ayristirilmis.host.split('.').collect();
        let kok = if parcalar.len() > 2 {
            parcalar[parcalar.len() - 2..].join(".")
        } else {
            ayristirilmis.host.clone()
        };
        modules::mod_altalanlar(&kok, &mut sonuc, renkli);
    }
    if a.derin {
        modules::mod_derin(&ayristirilmis.taban(), dogrula, &mut sonuc, renkli);
    }
    if a.portlar {
        modules::mod_portlar(&ayristirilmis.host, &mut sonuc, renkli);
    }

    if let Some(yol) = &a.json {
        match serde_json::to_string_pretty(&sonuc) {
            Ok(metin) => {
                if std::fs::write(yol, metin).is_ok() {
                    println!(
                        "  {} JSON rapor kaydedildi: {}",
                        banner::rnk("[+]", "32", renkli),
                        yol
                    );
                } else {
                    eprintln!("JSON dosyasi yazilamadi: {}", yol);
                }
            }
            Err(e) => eprintln!("JSON uretilemedi: {}", e),
        }
    }
    if let Some(yol) = &a.html {
        let icerik = report::html_rapor_uret(&sonuc);
        if std::fs::write(yol, icerik).is_ok() {
            println!(
                "  {} HTML rapor kaydedildi: {}",
                banner::rnk("[+]", "32", renkli),
                yol
            );
        } else {
            eprintln!("HTML dosyasi yazilamadi: {}", yol);
        }
    }
    println!();
}
