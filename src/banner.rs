use std::io::{IsTerminal, Write};
use std::thread::sleep;
use std::time::Duration;

const LOGO: &str = r#"
 __    __  _______  _______    ______
|  \  |  \|       \|       \  /      \
| $$  | $$| $$$$$$$\ $$$$$$$\|  $$$$$$\
| $$  | $$| $$__/ $$ $$__/ $$| $$  | $$
| $$  | $$| $$    $$ $$    $$| $$  | $$
| $$  | $$| $$$$$$$\ $$$$$$$\| $$  | $$
| $$__/ $$| $$__/ $$ $$__/ $$| $$__/ $$
 \$$    $$| $$    $$ $$    $$ \$$    $$
  \$$$$$$  \$$$$$$$ \$$$$$$$  \$$$$$$
"#;

/// Windows konsolunda ANSI/VT100 kacis dizilerini etkinlestirir.
/// Modern Windows Terminal ve Windows 10 1909+ cmd.exe zaten destekler,
/// ancak eski konsol kullanan sistemler icin acikca etkinlestiriyoruz.
#[cfg(windows)]
fn ansi_etkinlestir() {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
fn ansi_etkinlestir() {}

pub fn terminal_mi() -> bool {
    ansi_etkinlestir();
    std::io::stdout().is_terminal()
}

/// Metni verilen ANSI renk koduyla sarar (renkli=false ise duz metin doner).
pub fn rnk(metin: &str, kod: &str, renkli: bool) -> String {
    if renkli {
        format!("\x1b[{}m{}\x1b[0m", kod, metin)
    } else {
        metin.to_string()
    }
}

fn yaz_gecikmeli(s: &str, gecikme_ms: u64) {
    for ch in s.chars() {
        print!("{}", ch);
        std::io::stdout().flush().ok();
        if gecikme_ms > 0 {
            sleep(Duration::from_millis(gecikme_ms));
        }
    }
    println!();
}

pub fn acilis_efekti(sessiz: bool, renkli: bool) {
    let interaktif = std::io::stdout().is_terminal();
    if sessiz || !interaktif {
        println!("{}", rnk(LOGO, "1;36", renkli));
        println!(
            "{}",
            rnk(
                &format!("  WEB0 v{}  —  web guvenligi kesif & denetim araci", crate::SURUM),
                "1;37",
                renkli
            )
        );
        return;
    }

    let genislik = term_genisligi();
    let cizgi = "=".repeat(genislik.min(60));
    println!("{}", rnk(&cizgi, "36", renkli));

    let renk_kodlari = ["1;36", "1;36", "1;34", "1;34", "1;35", "1;35", "1;36", "1;36", "1;34"];
    for (i, satir) in LOGO.trim_matches('\n').lines().enumerate() {
        println!("{}", rnk(satir, renk_kodlari[i % renk_kodlari.len()], renkli));
        sleep(Duration::from_millis(30));
    }
    sleep(Duration::from_millis(150));

    yaz_gecikmeli(
        &rnk(&format!("  >> WEB0 v{} baslatiliyor...", crate::SURUM), "1;37", renkli),
        10,
    );
    for etiket in [
        "cekirdek moduller yukleniyor",
        "ag arayuzu hazirlaniyor",
        "tarayici motoru hazir",
    ] {
        print!("  [{}] {}", rnk("•", "32", renkli), etiket);
        std::io::stdout().flush().ok();
        for _ in 0..3 {
            sleep(Duration::from_millis(80));
            print!(".");
            std::io::stdout().flush().ok();
        }
        println!(" {}", rnk("tamam", "32", renkli));
    }
    println!("{}", rnk(&cizgi, "36", renkli));
    println!(
        "{}",
        rnk(
            "  Yalnizca sahibi oldugunuz / yazili izniniz olan sistemlerde kullanin.",
            "33",
            renkli
        )
    );
    println!("{}\n", rnk(&cizgi, "36", renkli));
}

fn term_genisligi() -> usize {
    // Harici crate kullanmadan basit bir tahmin; COLUMNS ortam degiskenine bakar,
    // yoksa makul bir varsayilan kullanir.
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(80)
}

pub fn bolum(baslik: &str, renkli: bool) {
    println!(
        "\n{}{}",
        rnk(&format!("-- {} ", baslik), "1;36", renkli),
        rnk(&"-".repeat((60usize).saturating_sub(baslik.len()).max(2)), "36", renkli)
    );
}
pub fn kv(k: &str, v: &str, renkli: bool) {
    println!("  {} {}", rnk(&format!("{}:", k), "1", renkli), v);
}
pub fn tamam(t: &str, renkli: bool) {
    println!("  {} {}", rnk("[+]", "32", renkli), t);
}
pub fn uyari(t: &str, renkli: bool) {
    println!("  {} {}", rnk("[!]", "33", renkli), t);
}
pub fn hata(t: &str, renkli: bool) {
    println!("  {} {}", rnk("[-]", "31", renkli), t);
}
pub fn bilgi(t: &str, renkli: bool) {
    println!("  {} {}", rnk("[*]", "34", renkli), t);
}
