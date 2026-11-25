//! `ad-server` — řadič domény.
//!
//! Fáze 1: zatím jen ohlásí verzi a to, co bude umět. Síťové vrstvy
//! přidáme ve fázích 2 až 6, aby se dalo testovat po krocích.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("ad-server {} (protokol {})", ad_core::VERZE, ad_core::proto::PROTO_VERZE);
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
        "ad-server {verze} — vlastní zjednodušený řadič domény

POUŽITÍ:
    ad-server [PŘEPÍNAČ]

PŘEPÍNAČE:
    -V, --version    vypíše verzi
    -h, --help       vypíše tuto nápovědu

STAV: fáze 1 (architektura a protokol).
Hotové: sdílené jádro ad-core — model, protokol, zásady, hesla, validace.
Dál bude: databáze a přihlašování (fáze 2), webová správa (3), DNS (4),
klient a zásady (5), služby pro Windows/Debian/Void (6), balení (7).

Výchozí porty: {tls} doménové API (TLS), {sprava} webová správa (jen
127.0.0.1), {dns} DNS.",
        verze = ad_core::VERZE,
        tls = ad_core::proto::PORT_TLS,
        sprava = ad_core::proto::PORT_SPRAVA,
        dns = ad_core::proto::PORT_DNS,
    );
}
