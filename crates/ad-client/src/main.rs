//! `ad-client` — klient pro připojení do naší domény.
//!
//! Fáze 1: zatím jen ohlásí verzi a plán. Nic nemění v systému.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("ad-client {} (protokol {})", ad_core::VERZE, ad_core::proto::PROTO_VERZE);
        }
        Some("--help") | Some("-h") | None => napoveda(),
        Some(jine) => {
            eprintln!("neznámý přepínač: {jine}");
            napoveda();
            std::process::exit(2);
        }
    }
}

fn napoveda() {
    println!(
        "ad-client {verze} — připojení počítače do vlastní domény

POUŽITÍ:
    ad-client [PŘÍKAZ]

CHYSTANÉ PŘÍKAZY (fáze 5):
    join      připojí počítač do domény (ověří otisk certifikátu serveru)
    status    vypíše stav připojení a naposledy stažené zásady
    logon     přihlásí doménového uživatele v programu
    policy    stáhne a zobrazí zásady
    leave     odpojí počítač a vrátí původní nastavení DNS

STAV: fáze 1 (architektura a protokol). Klient zatím nic v systému nemění.
Přihlašování do samotného systému (Credential Provider, PAM) tento projekt
záměrně nedělá.",
        verze = ad_core::VERZE
    );
}
