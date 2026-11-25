//! Validace a normalizace jmen. Používá to **server i klient** — klient
//! kontroluje i to, co dostane od serveru (obrana do hloubky).
//!
//! Pravidla jsou naše, inspirovaná AD, ale záměrně jednodušší a popsaná
//! na jednom místě, aby se nedala obejít.

use crate::error::{AdError, ErrorCode, Result};

/// Maximální délka celého jména domény.
pub const MAX_FQDN: usize = 253;
/// Maximální délka jedné části (labelu) jména domény.
pub const MAX_LABEL: usize = 63;
/// Maximální délka přihlašovacího jména uživatele.
pub const MAX_SAM: usize = 20;
/// Maximální délka jména počítače.
pub const MAX_COMPUTER: usize = 15;
/// Maximální délka krátkého jména domény (obdoba NetBIOS).
pub const MAX_SHORT_DOMAIN: usize = 15;
/// Maximální délka jména OU nebo skupiny.
pub const MAX_OBJECT_NAME: usize = 64;
/// Maximální délka popisu.
pub const MAX_DESCRIPTION: usize = 512;

/// Doporučené koncovky pro vnitřní doménu. `.internal` je od roku 2024
/// vyhrazená ICANN právě pro privátní sítě, takže je první volbou.
pub const DOPORUCENE_TLD: &[&str] =
    &["internal", "intranet", "lan", "home", "corp", "ad", "test", "example", "invalid"];

/// Koncovky, které zakazujeme úplně. `.local` kolliduje s mDNS/Bonjour
/// (Avahi), takže by rozbila objevování služeb v síti.
pub const ZAKAZANE_TLD: &[&str] = &["local", "localhost", "onion", "arpa"];

/// Přihlašovací jména, která si rezervuje systém.
pub const VYHRAZENA_JMENA: &[&str] = &[
    "administrator",
    "admin",
    "guest",
    "krbtgt",
    "system",
    "root",
    "nobody",
    "daemon",
    "ad-server",
    "ad-client",
    "domain",
    "computers",
    "users",
    "builtin",
];

fn chyba(kod: ErrorCode, zprava: impl Into<String>) -> AdError {
    AdError::new(kod, zprava)
}

/// Obsahuje text řídicí znak? Ty do jmen ani popisů nepatří.
fn ma_ridici_znak(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
}

/// Validuje jednu část jména domény (label) podle LDH pravidla
/// (letters-digits-hyphen).
pub fn validuj_dns_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(chyba(ErrorCode::InvalidDomainName, "část jména je prázdná"));
    }
    if label.len() > MAX_LABEL {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            format!("část jména je delší než {MAX_LABEL} znaků"),
        ));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            "část jména nesmí začínat ani končit pomlčkou",
        ));
    }
    if !label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            "část jména smí obsahovat jen malá písmena a-z, číslice a pomlčku",
        ));
    }
    Ok(())
}

/// Výsledek kontroly jména domény. `varovani` neblokuje, jen upozorní v UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KontrolaDomeny {
    /// Normalizované jméno (malá písmena, bez tečky na konci).
    pub fqdn: String,
    /// Krátké jméno odvozené z prvního labelu (např. `SKOLA`).
    pub kratke: String,
    /// Nebrání pokračování, ale uživatel to má vidět.
    pub varovani: Vec<String>,
}

/// Zkontroluje a znormalizuje jméno domény, např. `Skola.Internal.` ->
/// `skola.internal`.
pub fn validuj_jmeno_domeny(vstup: &str) -> Result<KontrolaDomeny> {
    let s = vstup.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err(chyba(ErrorCode::InvalidDomainName, "jméno domény je prázdné"));
    }
    if !s.is_ascii() {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            "jméno domény musí být ASCII (diakritiku a IDN nepodporujeme)",
        ));
    }
    if s.len() > MAX_FQDN {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            format!("jméno domény je delší než {MAX_FQDN} znaků"),
        ));
    }
    let labely: Vec<&str> = s.split('.').collect();
    if labely.len() < 2 {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            "jméno domény musí mít alespoň dvě části, např. skola.internal",
        ));
    }
    if labely.len() > 10 {
        return Err(chyba(ErrorCode::InvalidDomainName, "jméno domény má příliš mnoho částí"));
    }
    for l in &labely {
        validuj_dns_label(l)?;
    }
    let tld = *labely.last().unwrap();
    if ZAKAZANE_TLD.contains(&tld) {
        return Err(chyba(
            ErrorCode::InvalidDomainName,
            format!(
                ".{tld} je zakázaná koncovka (koliduje s mDNS nebo je vyhrazená). \
                 Použij např. skola.internal"
            ),
        ));
    }
    if tld.chars().all(|c| c.is_ascii_digit()) {
        return Err(chyba(ErrorCode::InvalidDomainName, "koncovka nesmí být jen číslo"));
    }

    let mut varovani = Vec::new();
    if !DOPORUCENE_TLD.contains(&tld) {
        varovani.push(format!(
            ".{tld} může existovat i ve veřejném internetu. Doporučená koncovka je .internal"
        ));
    }
    if labely[0].len() > MAX_SHORT_DOMAIN {
        varovani.push(format!(
            "první část jména je delší než {MAX_SHORT_DOMAIN} znaků, krátké jméno se zkrátí"
        ));
    }

    let kratke = odvod_kratke_jmeno(labely[0]);
    Ok(KontrolaDomeny { fqdn: s, kratke, varovani })
}

/// Odvodí krátké (NetBIOS-like) jméno z prvního labelu: velká písmena,
/// jen A-Z 0-9 a pomlčka, nejvýš 15 znaků.
pub fn odvod_kratke_jmeno(label: &str) -> String {
    let mut out: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    out.truncate(MAX_SHORT_DOMAIN);
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Validuje krátké jméno domény zadané ručně.
pub fn validuj_kratke_jmeno(s: &str) -> Result<String> {
    let s = s.trim().to_ascii_uppercase();
    if s.is_empty() || s.len() > MAX_SHORT_DOMAIN {
        return Err(chyba(
            ErrorCode::InvalidName,
            format!("krátké jméno domény musí mít 1 až {MAX_SHORT_DOMAIN} znaků"),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-') {
        return Err(chyba(ErrorCode::InvalidName, "krátké jméno smí mít jen A-Z, 0-9 a pomlčku"));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(chyba(
            ErrorCode::InvalidName,
            "krátké jméno nesmí začínat ani končit pomlčkou",
        ));
    }
    Ok(s)
}

/// Validuje a znormalizuje přihlašovací jméno uživatele (obdoba
/// sAMAccountName). Vrací jméno malými písmeny — porovnáváme bez ohledu
/// na velikost písmen.
pub fn validuj_prihlasovaci_jmeno(vstup: &str) -> Result<String> {
    let s = vstup.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Err(chyba(ErrorCode::InvalidName, "přihlašovací jméno je prázdné"));
    }
    if s.len() > MAX_SAM {
        return Err(chyba(
            ErrorCode::InvalidName,
            format!("přihlašovací jméno je delší než {MAX_SAM} znaků"),
        ));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(chyba(
            ErrorCode::InvalidName,
            "přihlašovací jméno smí mít jen a-z, 0-9, tečku, podtržítko a pomlčku",
        ));
    }
    if !s.chars().next().unwrap().is_ascii_alphanumeric() {
        return Err(chyba(
            ErrorCode::InvalidName,
            "přihlašovací jméno musí začínat písmenem nebo číslicí",
        ));
    }
    if s.ends_with('.') {
        return Err(chyba(ErrorCode::InvalidName, "přihlašovací jméno nesmí končit tečkou"));
    }
    Ok(s)
}

/// Je jméno vyhrazené pro systém? (Nepouštíme ho uživatelům.)
pub fn je_vyhrazene_jmeno(jmeno: &str) -> bool {
    VYHRAZENA_JMENA.contains(&jmeno.to_ascii_lowercase().as_str())
}

/// Validuje jméno počítače. Vrací velkými písmeny (jak to zobrazuje AD),
/// ale v DNS se používá malými.
pub fn validuj_jmeno_pocitace(vstup: &str) -> Result<String> {
    let s = vstup.trim().to_ascii_uppercase();
    if s.is_empty() || s.len() > MAX_COMPUTER {
        return Err(chyba(
            ErrorCode::InvalidName,
            format!("jméno počítače musí mít 1 až {MAX_COMPUTER} znaků"),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-') {
        return Err(chyba(ErrorCode::InvalidName, "jméno počítače smí mít jen A-Z, 0-9 a pomlčku"));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(chyba(
            ErrorCode::InvalidName,
            "jméno počítače nesmí začínat ani končit pomlčkou",
        ));
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return Err(chyba(ErrorCode::InvalidName, "jméno počítače nesmí být jen číslo"));
    }
    Ok(s)
}

/// Validuje jméno OU, skupiny nebo zásady — tedy volný text bez znaků,
/// které by rozbily DN nebo HTML.
pub fn validuj_jmeno_objektu(vstup: &str) -> Result<String> {
    let s = vstup.trim();
    if s.is_empty() {
        return Err(chyba(ErrorCode::InvalidName, "jméno je prázdné"));
    }
    if s.chars().count() > MAX_OBJECT_NAME {
        return Err(chyba(
            ErrorCode::InvalidName,
            format!("jméno je delší než {MAX_OBJECT_NAME} znaků"),
        ));
    }
    if ma_ridici_znak(s) {
        return Err(chyba(ErrorCode::InvalidName, "jméno obsahuje řídicí znak"));
    }
    const ZAKAZANE: &[char] = &['/', '\\', ',', '=', '+', '<', '>', ';', '"', '#', '*', '?'];
    if let Some(c) = s.chars().find(|c| ZAKAZANE.contains(c)) {
        return Err(chyba(ErrorCode::InvalidName, format!("jméno nesmí obsahovat znak '{c}'")));
    }
    Ok(s.to_string())
}

/// Validuje volný popis.
pub fn validuj_popis(vstup: &str) -> Result<String> {
    let s = vstup.trim();
    if s.chars().count() > MAX_DESCRIPTION {
        return Err(chyba(
            ErrorCode::OutOfRange,
            format!("popis je delší než {MAX_DESCRIPTION} znaků"),
        ));
    }
    if s.chars().any(|c| c.is_control() && c != '\n') {
        return Err(chyba(ErrorCode::BadRequest, "popis obsahuje řídicí znak"));
    }
    Ok(s.to_string())
}

/// Složí UPN: `jmeno@skola.internal`.
pub fn upn(sam: &str, fqdn: &str) -> String {
    format!("{sam}@{fqdn}")
}

/// Složí přihlašovací jméno v krátkém tvaru: `SKOLA\jmeno`.
pub fn kratke_prihlaseni(kratke_domeny: &str, sam: &str) -> String {
    format!("{kratke_domeny}\\{sam}")
}

/// Rozdělí zadané přihlašovací jméno na (uživatel, případná doména).
/// Přijímá `jmeno`, `jmeno@domena`, `DOMENA\jmeno`.
pub fn rozdel_prihlaseni(vstup: &str) -> (String, Option<String>) {
    let s = vstup.trim();
    if let Some((dom, user)) = s.split_once('\\') {
        return (user.to_string(), Some(dom.to_string()));
    }
    if let Some((user, dom)) = s.split_once('@') {
        return (user.to_string(), Some(dom.to_string()));
    }
    (s.to_string(), None)
}

/// Složí DN ve stylu LDAP: `OU=Zaci,OU=Uzivatele,DC=skola,DC=internal`.
pub fn dn_z_cesty(cesta_ou: &[&str], fqdn: &str) -> String {
    let mut casti: Vec<String> =
        cesta_ou.iter().rev().map(|o| format!("OU={}", escapuj_dn(o))).collect();
    casti.extend(fqdn.split('.').map(|d| format!("DC={d}")));
    casti.join(",")
}

/// Escapuje hodnotu v DN podle RFC 4514 (jen pro zobrazení).
fn escapuj_dn(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domena_local_je_zakazana() {
        let e = validuj_jmeno_domeny("skola.local").unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidDomainName);
        assert!(e.message.contains("mDNS") || e.message.contains("zakázaná"));
    }

    #[test]
    fn domena_internal_projde_bez_varovani() {
        let k = validuj_jmeno_domeny("Skola.Internal.").unwrap();
        assert_eq!(k.fqdn, "skola.internal");
        assert_eq!(k.kratke, "SKOLA");
        assert!(k.varovani.is_empty(), "{:?}", k.varovani);
    }

    #[test]
    fn verejna_koncovka_jen_varuje() {
        let k = validuj_jmeno_domeny("skola.cz").unwrap();
        assert_eq!(k.varovani.len(), 1);
    }

    #[test]
    fn jednoslovna_domena_neprojde() {
        assert!(validuj_jmeno_domeny("skola").is_err());
        assert!(validuj_jmeno_domeny("").is_err());
        assert!(validuj_jmeno_domeny("škola.internal").is_err());
        assert!(validuj_jmeno_domeny("-skola.internal").is_err());
        assert!(validuj_jmeno_domeny("skola..internal").is_err());
    }

    #[test]
    fn prihlasovaci_jmeno() {
        assert_eq!(validuj_prihlasovaci_jmeno("  Jan.Novak ").unwrap(), "jan.novak");
        assert!(validuj_prihlasovaci_jmeno("jan novak").is_err());
        assert!(validuj_prihlasovaci_jmeno(".jan").is_err());
        assert!(validuj_prihlasovaci_jmeno("jan.").is_err());
        assert!(validuj_prihlasovaci_jmeno(&"a".repeat(21)).is_err());
        assert!(validuj_prihlasovaci_jmeno("jan;drop").is_err());
    }

    #[test]
    fn vyhrazena_jmena_pozname() {
        assert!(je_vyhrazene_jmeno("Administrator"));
        assert!(je_vyhrazene_jmeno("krbtgt"));
        assert!(!je_vyhrazene_jmeno("jan.novak"));
    }

    #[test]
    fn jmeno_pocitace() {
        assert_eq!(validuj_jmeno_pocitace("pc-01").unwrap(), "PC-01");
        assert!(validuj_jmeno_pocitace("12345").is_err());
        assert!(validuj_jmeno_pocitace("pc_01").is_err());
        assert!(validuj_jmeno_pocitace(&"p".repeat(16)).is_err());
    }

    #[test]
    fn jmeno_objektu_odmitne_nebezpecne_znaky() {
        assert_eq!(validuj_jmeno_objektu(" Žáci 1.A ").unwrap(), "Žáci 1.A");
        assert!(validuj_jmeno_objektu("Zaci,OU=x").is_err());
        assert!(validuj_jmeno_objektu("a\u{0}b").is_err());
        assert!(validuj_jmeno_objektu("<script>").is_err());
    }

    #[test]
    fn dn_se_sklada_spravne() {
        assert_eq!(
            dn_z_cesty(&["Uzivatele", "Zaci"], "skola.internal"),
            "OU=Zaci,OU=Uzivatele,DC=skola,DC=internal"
        );
        assert_eq!(dn_z_cesty(&[], "skola.internal"), "DC=skola,DC=internal");
    }

    #[test]
    fn rozdeleni_prihlaseni() {
        assert_eq!(rozdel_prihlaseni("SKOLA\\jan"), ("jan".into(), Some("SKOLA".into())));
        assert_eq!(
            rozdel_prihlaseni("jan@skola.internal"),
            ("jan".into(), Some("skola.internal".into()))
        );
        assert_eq!(rozdel_prihlaseni("jan"), ("jan".into(), None));
    }

    #[test]
    fn kratke_jmeno_se_zkrati() {
        assert_eq!(odvod_kratke_jmeno("velmi-dlouhe-jmeno-domeny"), "VELMI-DLOUHE-JM");
        assert_eq!(validuj_kratke_jmeno("skola").unwrap(), "SKOLA");
        assert!(validuj_kratke_jmeno("skola.x").is_err());
    }
}
