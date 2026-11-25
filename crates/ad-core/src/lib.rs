//! # ad-core — sdílené jádro
//!
//! Tady je všechno, co musí server i klient chápat úplně stejně:
//! datový model, protokol, zásady, pravidla pro jména a práci s hesly.
//!
//! Proč to má být v jednom crate: kdyby server a klient měly každý svoji
//! kopii struktur, dřív nebo později by se rozešly a vznikla by chyba,
//! kterou kompilátor nenajde. Takhle se při změně protokolu nepřeloží
//! obojí, dokud to neopravíš.
//!
//! ## Bezpečnostní zásady tohoto crate
//! 1. Zásady (`policy`) jsou **data**, nikdy ne příkazy. Žádná struktura
//!    neobsahuje cestu ke spuštění, skript ani shellový příkaz.
//! 2. Všechny vstupní struktury mají `deny_unknown_fields`. Co neznáme,
//!    to odmítneme — a to na obou stranách.
//! 3. Hesla a tokeny chodí v `secret::Tajne`, které se nevypíše do logu.
//! 4. Validace je tady, ne v HTTP vrstvě, aby se nedala obejít jinou cestou.

pub mod dns;
pub mod error;
pub mod ids;
pub mod model;
pub mod names;
pub mod password;
pub mod policy;
pub mod proto;
pub mod secret;

pub use error::{AdError, ErrorCode, ErrorResponse, Result};

/// Verze celého projektu (z `Cargo.toml`).
pub const VERZE: &str = env!("CARGO_PKG_VERSION");

/// Naplní buffer náhodnými bajty z generátoru operačního systému.
///
/// Když OS generátor nefunguje, program **spadne**. To je schválně:
/// pokračovat s předvídatelnou náhodou by bylo horší než se zastavit.
pub fn rand_bytes(buf: &mut [u8]) {
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .expect("generátor náhodných čísel operačního systému nefunguje");
}

/// Aktuální čas v UTC.
pub fn nyni() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

#[cfg(test)]
mod tests {
    #[test]
    fn nahodne_bajty_nejsou_nuly() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::rand_bytes(&mut a);
        super::rand_bytes(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn verze_je_vyplnena() {
        assert!(!super::VERZE.is_empty());
    }
}
