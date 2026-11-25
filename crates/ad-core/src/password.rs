//! Hesla: hašování Argon2id a kontrola zásad.
//!
//! Heslo se nikde neukládá ani nezapisuje do logu. V databázi je jen
//! PHC řetězec (`$argon2id$v=19$m=19456,t=2,p=1$sůl$haš`), ze kterého se
//! heslo spočítat nedá.

use crate::error::{AdError, ErrorCode, Result};
use crate::policy::PasswordPolicy;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Paměť v KiB. 19456 KiB = 19 MiB, doporučení OWASP pro Argon2id.
pub const ARGON_PAMET_KIB: u32 = 19_456;
/// Počet průchodů.
pub const ARGON_PRUCHODY: u32 = 2;
/// Počet vláken.
pub const ARGON_VLAKNA: u32 = 1;
/// Délka výstupu v bajtech.
pub const ARGON_DELKA: usize = 32;
/// Délka soli v bajtech.
pub const ARGON_SOL: usize = 16;

/// Nejdelší heslo, které vůbec přijmeme. Delší vstup zahodíme hned,
/// ať nám nikdo neposílá megabajty.
pub const MAX_DELKA_HESLA: usize = 256;

fn argon() -> Argon2<'static> {
    let params = Params::new(ARGON_PAMET_KIB, ARGON_PRUCHODY, ARGON_VLAKNA, Some(ARGON_DELKA))
        .expect("parametry Argon2 jsou konstanty a musí být platné");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Zahašuje heslo. Vrací PHC řetězec vhodný k uložení do databáze.
pub fn zahasuj(heslo: &str) -> Result<String> {
    if heslo.is_empty() {
        return Err(AdError::bad_request("heslo je prázdné"));
    }
    if heslo.len() > MAX_DELKA_HESLA {
        return Err(AdError::out_of_range(format!("heslo je delší než {MAX_DELKA_HESLA} bajtů")));
    }
    let mut sol = [0u8; ARGON_SOL];
    crate::rand_bytes(&mut sol);
    let salt = SaltString::encode_b64(&sol)
        .map_err(|e| AdError::internal(format!("sůl se nepodařilo zakódovat: {e}")))?;
    sol.zeroize();
    let hash = argon()
        .hash_password(heslo.as_bytes(), &salt)
        .map_err(|e| AdError::internal(format!("hašování hesla selhalo: {e}")))?;
    Ok(hash.to_string())
}

/// Ověří heslo proti uloženému hašování. `false` = nesouhlasí.
///
/// Chybu vrací jen tehdy, když je v databázi poškozený haš.
pub fn over(ulozeny_hash: &str, heslo: &str) -> Result<bool> {
    if heslo.len() > MAX_DELKA_HESLA {
        return Ok(false);
    }
    let parsed = PasswordHash::new(ulozeny_hash)
        .map_err(|e| AdError::internal(format!("uložený haš hesla je poškozený: {e}")))?;
    match argon().verify_password(heslo.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AdError::internal(format!("ověření hesla selhalo: {e}"))),
    }
}

/// Má se haš přepočítat, protože byl uložen se slabšími parametry?
pub fn potrebuje_prepocet(ulozeny_hash: &str) -> bool {
    let Ok(h) = PasswordHash::new(ulozeny_hash) else {
        return true;
    };
    if h.algorithm.as_str() != "argon2id" {
        return true;
    }
    let Ok(p) = Params::try_from(&h) else {
        return true;
    };
    p.m_cost() < ARGON_PAMET_KIB || p.t_cost() < ARGON_PRUCHODY
}

/// Haš náhodného hesla, který nikdy nikomu nepatří.
///
/// Když uživatel neexistuje, ověříme heslo proti tomuhle. Odpověď pak
/// trvá stejně dlouho jako u existujícího účtu, takže se útočník nedozví,
/// která jména v doméně existují.
pub fn haš_na_zdržení() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        let mut b = [0u8; 32];
        crate::rand_bytes(&mut b);
        let heslo = crate::secret::base64url(&b);
        zahasuj(&heslo).expect("haš na zdržení se musí povést")
    })
}

/// Co konkrétně na hesle nesouhlasí. Posíláme to do UI, aby uživatel
/// věděl, co opravit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum PasswordComplaint {
    /// Heslo je kratší, než zásada dovoluje.
    TooShort {
        min: u8,
    },
    /// Heslo je delší, než vůbec přijímáme.
    TooLong {
        max: usize,
    },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSymbol,
    /// Heslo obsahuje přihlašovací jméno.
    ContainsUsername,
    /// Heslo je v historii posledních hesel.
    InHistory {
        count: u8,
    },
    /// Heslo obsahuje řídicí znak.
    ControlCharacter,
    /// Heslo je ze seznamu nejčastějších.
    TooCommon,
}

/// Malý seznam hesel, která v testovací doméně stejně někdo zkusí.
/// Není to náhrada haveibeenpwned, jen pojistka proti „Password1“.
const CASTA_HESLA: &[&str] = &[
    "password",
    "password1",
    "password123",
    "passw0rd",
    "heslo",
    "heslo123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwertz",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "abc123",
    "aa123456",
    "skola",
    "skola123",
    "student",
    "ucitel",
    "test",
    "test123",
    "Password1",
    "Password123",
    "Heslo123",
    "Qwerty123",
];

/// Zkontroluje heslo proti zásadě. `Ok(())` = heslo je v pořádku.
///
/// `historie` jsou hašované verze předchozích hesel uživatele (nejnovější
/// první). Předává se jen tehdy, když ji voláme na serveru.
pub fn zkontroluj(
    heslo: &str,
    zasada: &PasswordPolicy,
    prihlasovaci_jmeno: Option<&str>,
    historie: &[String],
) -> Result<()> {
    let mut stiznosti: Vec<PasswordComplaint> = Vec::new();
    let pocet_znaku = heslo.chars().count();

    if heslo.len() > MAX_DELKA_HESLA {
        stiznosti.push(PasswordComplaint::TooLong { max: MAX_DELKA_HESLA });
    }
    if pocet_znaku < zasada.min_length as usize {
        stiznosti.push(PasswordComplaint::TooShort { min: zasada.min_length });
    }
    if heslo.chars().any(|c| c.is_control()) {
        stiznosti.push(PasswordComplaint::ControlCharacter);
    }
    if zasada.require_uppercase && !heslo.chars().any(|c| c.is_uppercase()) {
        stiznosti.push(PasswordComplaint::MissingUppercase);
    }
    if zasada.require_lowercase && !heslo.chars().any(|c| c.is_lowercase()) {
        stiznosti.push(PasswordComplaint::MissingLowercase);
    }
    if zasada.require_digit && !heslo.chars().any(|c| c.is_numeric()) {
        stiznosti.push(PasswordComplaint::MissingDigit);
    }
    if zasada.require_symbol && !heslo.chars().any(|c| !c.is_alphanumeric() && !c.is_control()) {
        stiznosti.push(PasswordComplaint::MissingSymbol);
    }
    if zasada.forbid_username {
        if let Some(jmeno) = prihlasovaci_jmeno {
            let j = jmeno.to_lowercase();
            if j.len() >= 3 && heslo.to_lowercase().contains(&j) {
                stiznosti.push(PasswordComplaint::ContainsUsername);
            }
        }
    }
    let male = heslo.to_lowercase();
    if CASTA_HESLA.iter().any(|c| c.to_lowercase() == male) {
        stiznosti.push(PasswordComplaint::TooCommon);
    }
    if zasada.history_length > 0 {
        let kolik = (zasada.history_length as usize).min(historie.len());
        for stary in &historie[..kolik] {
            if over(stary, heslo).unwrap_or(false) {
                stiznosti.push(PasswordComplaint::InHistory { count: zasada.history_length });
                break;
            }
        }
    }

    if stiznosti.is_empty() {
        return Ok(());
    }
    let detaily = serde_json::json!({ "complaints": stiznosti });
    Err(AdError::new(ErrorCode::PasswordPolicyViolation, "heslo nesplňuje zásady domény")
        .with_details(detaily))
}

/// Velmi hrubý odhad síly hesla 0–100 pro ukazatel v UI.
/// Není to bezpečnostní opatření, jen pomůcka pro uživatele.
pub fn odhad_sily(heslo: &str) -> u8 {
    if heslo.is_empty() {
        return 0;
    }
    let mut abeceda = 0u32;
    if heslo.chars().any(|c| c.is_ascii_lowercase()) {
        abeceda += 26;
    }
    if heslo.chars().any(|c| c.is_ascii_uppercase()) {
        abeceda += 26;
    }
    if heslo.chars().any(|c| c.is_ascii_digit()) {
        abeceda += 10;
    }
    if heslo.chars().any(|c| c.is_ascii_punctuation() || c == ' ') {
        abeceda += 33;
    }
    if !heslo.is_ascii() {
        abeceda += 100;
    }
    let bity = (heslo.chars().count() as f64) * (abeceda.max(2) as f64).log2();
    // 0 bitů = 0, 80 bitů a víc = 100
    let mut skore = (bity / 80.0 * 100.0).round().clamp(0.0, 100.0) as u8;
    if CASTA_HESLA.iter().any(|c| c.eq_ignore_ascii_case(heslo)) {
        skore = skore.min(10);
    }
    skore
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hasovani_a_overeni() {
        let h = zahasuj("Tajne-Heslo-42").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(over(&h, "Tajne-Heslo-42").unwrap());
        assert!(!over(&h, "Tajne-Heslo-43").unwrap());
    }

    #[test]
    fn dve_hasovani_stejneho_hesla_se_lisi() {
        let a = zahasuj("stejne heslo").unwrap();
        let b = zahasuj("stejne heslo").unwrap();
        assert_ne!(a, b, "sůl musí být náhodná");
    }

    #[test]
    fn hash_neobsahuje_heslo() {
        let h = zahasuj("MojeTajneHeslo1!").unwrap();
        assert!(!h.contains("MojeTajneHeslo"));
    }

    #[test]
    fn prazdne_a_prilis_dlouhe_heslo() {
        assert!(zahasuj("").is_err());
        assert!(zahasuj(&"a".repeat(MAX_DELKA_HESLA + 1)).is_err());
        let h = zahasuj("neco").unwrap();
        assert!(!over(&h, &"a".repeat(MAX_DELKA_HESLA + 1)).unwrap());
    }

    #[test]
    fn poskozeny_hash_je_chyba() {
        assert!(over("tohle neni phc", "x").is_err());
    }

    #[test]
    fn prepocet_se_pozna() {
        let h = zahasuj("Heslo1234!").unwrap();
        assert!(!potrebuje_prepocet(&h));
        assert!(potrebuje_prepocet("$argon2id$v=19$m=4096,t=1,p=1$c29sc29sc29sc29s$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaE"));
        assert!(potrebuje_prepocet("necoNeni"));
    }

    #[test]
    fn hash_na_zdrzeni_funguje_a_je_stabilni() {
        let a = haš_na_zdržení();
        let b = haš_na_zdržení();
        assert_eq!(a, b);
        assert!(!over(a, "cokoliv").unwrap());
    }

    #[test]
    fn zasada_hesel_chyta_vsechno() {
        let z = PasswordPolicy { min_length: 8, require_symbol: true, ..Default::default() };
        let e = zkontroluj("abc", &z, Some("jan.novak"), &[]).unwrap_err();
        assert_eq!(e.code, ErrorCode::PasswordPolicyViolation);
        let d = e.details.unwrap();
        let s = d["complaints"].as_array().unwrap();
        let pravidla: Vec<&str> = s.iter().map(|x| x["rule"].as_str().unwrap()).collect();
        assert!(pravidla.contains(&"too_short"));
        assert!(pravidla.contains(&"missing_uppercase"));
        assert!(pravidla.contains(&"missing_digit"));
        assert!(pravidla.contains(&"missing_symbol"));

        zkontroluj("Spravne-Heslo1", &z, Some("jan.novak"), &[]).unwrap();
    }

    #[test]
    fn heslo_nesmi_obsahovat_jmeno() {
        let z = PasswordPolicy::default();
        let e = zkontroluj("Jan.Novak123", &z, Some("jan.novak"), &[]).unwrap_err();
        let d = e.details.unwrap();
        assert!(d["complaints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["rule"] == "contains_username"));
    }

    #[test]
    fn casta_hesla_neprojdou() {
        let z = PasswordPolicy { min_length: 4, ..Default::default() };
        let e = zkontroluj("Password1", &z, None, &[]).unwrap_err();
        let d = e.details.unwrap();
        assert!(d["complaints"].as_array().unwrap().iter().any(|x| x["rule"] == "too_common"));
    }

    #[test]
    fn historie_hesel_se_hlida() {
        let z = PasswordPolicy { history_length: 2, ..Default::default() };
        let stare = vec![zahasuj("Stare-Heslo1").unwrap(), zahasuj("Jeste-Starsi2").unwrap()];
        let e = zkontroluj("Stare-Heslo1", &z, None, &stare).unwrap_err();
        let d = e.details.unwrap();
        assert!(d["complaints"].as_array().unwrap().iter().any(|x| x["rule"] == "in_history"));
        zkontroluj("Uplne-Nove3", &z, None, &stare).unwrap();
    }

    #[test]
    fn ridici_znak_v_hesle() {
        let z = PasswordPolicy { min_length: 4, ..Default::default() };
        let e = zkontroluj("Ab1\u{7}xyz", &z, None, &[]).unwrap_err();
        let d = e.details.unwrap();
        assert!(d["complaints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["rule"] == "control_character"));
    }

    #[test]
    fn odhad_sily_je_monotonni() {
        assert_eq!(odhad_sily(""), 0);
        assert!(odhad_sily("abc") < odhad_sily("abcdefghij"));
        assert!(odhad_sily("abcdefghij") < odhad_sily("Abcdefghij1!"));
        assert!(odhad_sily("password") <= 10);
        assert_eq!(odhad_sily(&"Ab1!".repeat(20)), 100);
    }
}
