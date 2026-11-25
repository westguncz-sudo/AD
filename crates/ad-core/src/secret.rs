//! Tajemství, tokeny a otisky certifikátů.
//!
//! Rozdíl proti modulu `password`: tokeny generujeme my a mají 256 bitů
//! entropie. Nedá se je hádat, takže je stačí ukládat jako SHA-256 —
//! Argon2 by byl zbytečně drahý na každý požadavek. Hesla si naopak volí
//! člověk, tam je Argon2id nutnost.

use crate::error::{AdError, ErrorCode, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Délka tokenů v bajtech (256 bitů).
pub const DELKA_TOKENU: usize = 32;

/// Zakóduje bajty do base64url bez zarovnání (bezpečné do URL i cookie).
pub fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Dekóduje base64url bez zarovnání.
pub fn base64url_dekoduj(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AdError::bad_request("hodnota není platné base64url"))
}

/// Vygeneruje nový náhodný token z generátoru operačního systému.
pub fn novy_token() -> String {
    let mut b = [0u8; DELKA_TOKENU];
    crate::rand_bytes(&mut b);
    base64url(&b)
}

/// Vygeneruje tajemství počítačového účtu. Stejná konstrukce jako token,
/// jen jiné použití — proto vlastní funkce, ať je v kódu vidět záměr.
pub fn nove_tajemstvi_pocitace() -> String {
    novy_token()
}

/// SHA-256 obsahu, hex malými písmeny.
pub fn sha256_hex(data: &[u8]) -> String {
    let d = Sha256::digest(data);
    hex::encode(d)
}

/// Haš tokenu pro uložení do databáze.
pub fn hash_tokenu(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Porovná dva řetězce v konstantním čase (nezávisle na tom, kde se liší).
/// Používej na všechna tajemství, nikdy `==`.
pub fn rovno_v_konstantnim_case(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        // Délka tokenu je u nás vždy stejná, takže tohle neprozradí nic
        // užitečného.
        return false;
    }
    a.ct_eq(b).into()
}

/// Otisk certifikátu: SHA-256 nad DER, hex velkými písmeny po dvojicích
/// oddělených dvojtečkou — tak, jak to zobrazují prohlížeče a openssl.
pub fn otisk_certifikatu(der: &[u8]) -> String {
    let d = Sha256::digest(der);
    d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Znormalizuje otisk zadaný uživatelem: zahodí dvojtečky, mezery
/// a pomlčky, převede na velká písmena a zkontroluje délku.
pub fn normalizuj_otisk(vstup: &str) -> Result<String> {
    let s: String = vstup
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-' | '\n' | '\r' | '\t'))
        .collect::<String>()
        .to_ascii_uppercase();
    if s.len() != 64 {
        return Err(AdError::new(
            ErrorCode::BadRequest,
            format!("otisk SHA-256 musí mít 64 hexadecimálních znaků, zadáno {}", s.len()),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AdError::new(
            ErrorCode::BadRequest,
            "otisk obsahuje jiný než hexadecimální znak",
        ));
    }
    Ok(s)
}

/// Porovná otisk zadaný uživatelem s otiskem certifikátu, který server
/// skutečně nabídl. Porovnání je v konstantním čase.
pub fn otisky_se_rovnaji(ocekavany: &str, skutecny: &str) -> Result<bool> {
    let a = normalizuj_otisk(ocekavany)?;
    let b = normalizuj_otisk(skutecny)?;
    Ok(rovno_v_konstantnim_case(&a, &b))
}

/// Zkrácený otisk pro přečtení do telefonu: první a poslední čtyři bajty.
/// Nikdy ho nepoužívej k ověření, jen k zobrazení.
pub fn otisk_zkraceny(otisk: &str) -> Result<String> {
    let s = normalizuj_otisk(otisk)?;
    Ok(format!("{}…{}", &s[..8], &s[s.len() - 8..]))
}

/// Obálka pro tajný řetězec (heslo, token, tajemství počítače).
///
/// Co dělá:
/// * `Debug` vypíše `Tajne(***)`, takže se tajemství nedostane do logu
///   ani přes `tracing::debug!("{:?}", req)`.
/// * `Display` **není** naschvál — do textu se to nedá vypsat omylem.
/// * Při zahození se paměť přepíše nulami (`zeroize`).
/// * `serde` serializuje skutečnou hodnotu, protože klient musí heslo
///   poslat na server. Používej to jen v tělech požadavků, nikdy v logu.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Tajne(String);

impl Tajne {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Vrátí hodnotu. Jméno je takhle ošklivé schválně, ať je v kódu vidět.
    pub fn odhal(&self) -> &str {
        &self.0
    }

    pub fn je_prazdne(&self) -> bool {
        self.0.is_empty()
    }

    pub fn delka(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for Tajne {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tajne(***)")
    }
}

impl Drop for Tajne {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl From<String> for Tajne {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Tajne {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokeny_jsou_jine_a_spravne_dlouhe() {
        let a = novy_token();
        let b = novy_token();
        assert_ne!(a, b);
        assert_eq!(base64url_dekoduj(&a).unwrap().len(), DELKA_TOKENU);
        assert!(!a.contains('+') && !a.contains('/') && !a.contains('='));
    }

    #[test]
    fn hash_tokenu_je_stabilni() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let t = novy_token();
        assert_eq!(hash_tokenu(&t), hash_tokenu(&t));
        assert_ne!(hash_tokenu(&t), t);
    }

    #[test]
    fn konstantni_porovnani() {
        assert!(rovno_v_konstantnim_case("abc", "abc"));
        assert!(!rovno_v_konstantnim_case("abc", "abd"));
        assert!(!rovno_v_konstantnim_case("abc", "abcd"));
    }

    #[test]
    fn otisk_ma_spravny_format() {
        let o = otisk_certifikatu(b"abc");
        assert_eq!(o.len(), 64 + 31);
        assert!(o.starts_with("BA:78:16:BF"));
        assert_eq!(normalizuj_otisk(&o).unwrap().len(), 64);
    }

    #[test]
    fn normalizace_otisku_je_tolerantni() {
        let a = normalizuj_otisk("ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad").unwrap();
        let b =
            normalizuj_otisk(" BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD ")
                .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn normalizace_odmitne_nesmysl() {
        assert!(normalizuj_otisk("abc").is_err());
        assert!(normalizuj_otisk(&"z".repeat(64)).is_err());
        assert!(normalizuj_otisk("").is_err());
    }

    #[test]
    fn porovnani_otisku() {
        let o = otisk_certifikatu(b"certifikat");
        assert!(otisky_se_rovnaji(&o, &o.to_lowercase().replace(':', "")).unwrap());
        let jiny = otisk_certifikatu(b"jiny certifikat");
        assert!(!otisky_se_rovnaji(&o, &jiny).unwrap());
    }

    #[test]
    fn zkraceny_otisk() {
        let o = otisk_certifikatu(b"abc");
        assert_eq!(otisk_zkraceny(&o).unwrap(), "BA7816BF…F20015AD");
    }

    #[test]
    fn tajne_se_nevypise_do_logu() {
        let t = Tajne::new("MojeHeslo123");
        assert_eq!(format!("{t:?}"), "Tajne(***)");
        assert!(!format!("{t:?}").contains("MojeHeslo"));
        assert_eq!(t.odhal(), "MojeHeslo123");
        assert_eq!(t.delka(), 12);
    }

    #[test]
    fn tajne_v_json_je_proste_string() {
        let t = Tajne::new("x");
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"x\"");
        let z: Tajne = serde_json::from_str("\"y\"").unwrap();
        assert_eq!(z.odhal(), "y");
    }

    #[test]
    fn struktura_s_tajnym_poli_nic_neprozradi() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Pozadavek {
            jmeno: String,
            heslo: Tajne,
        }
        let p = Pozadavek { jmeno: "jan".into(), heslo: Tajne::new("Tajne1!") };
        let vypis = format!("{p:?}");
        assert!(vypis.contains("jan"));
        assert!(!vypis.contains("Tajne1!"));
    }
}
