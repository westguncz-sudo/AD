//! Model DNS zón a záznamů.
//!
//! Vlastní DNS server (fáze 4) staví odpovědi z těchto dat pomocí
//! `hickory-proto`. Tady je jen model a validace, bez síťování —
//! aby se dal testovat i bez poslouchání na portu 53.

use crate::error::{AdError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Jméno služby, pod kterou se řadič domény ohlašuje v SRV záznamu.
/// Klient tím najde server, když zná jen jméno domény.
pub const SRV_SLUZBA: &str = "_ad._tcp";
/// Jméno služby pro webovou správu (jen informativní, poslouchá na loopbacku).
pub const SRV_SPRAVA: &str = "_ad-admin._tcp";

/// Výchozí doba platnosti záznamů v sekundách.
pub const VYCHOZI_TTL: u32 = 3600;
/// Nejkratší povolené TTL.
pub const MIN_TTL: u32 = 30;
/// Nejdelší povolené TTL (týden).
pub const MAX_TTL: u32 = 604_800;

/// Druh zóny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    /// Dopředná zóna: jméno -> adresa.
    Forward,
    /// Reverzní zóna: adresa -> jméno (`*.in-addr.arpa`).
    Reverse,
}

/// DNS zóna.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone {
    pub id: i64,
    /// Jméno zóny bez tečky na konci, např. `skola.internal`
    /// nebo `56.168.192.in-addr.arpa`.
    pub name: String,
    pub kind: ZoneKind,
    /// Sériové číslo SOA, zvyšuje se při každé změně.
    pub serial: u32,
    /// Primární server v SOA.
    pub primary_ns: String,
    /// Kontakt v SOA (`hostmaster.skola.internal`).
    pub rname: String,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// Zóna vytvořená automaticky při povýšení na řadič domény —
    /// nedá se smazat, dokud doména existuje.
    pub managed: bool,
}

/// Typ záznamu, který umíme. Záměrně krátký seznam — co neumíme,
/// to nepředstíráme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Ptr,
    Srv,
    Txt,
    Ns,
    Mx,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Ptr => "PTR",
            Self::Srv => "SRV",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Mx => "MX",
        }
    }
}

/// Data záznamu. Rozlišené podle typu, takže nejde uložit nesmysl
/// typu „A záznam s textem“.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum RecordData {
    A {
        address: Ipv4Addr,
    },
    #[serde(rename = "AAAA")]
    Aaaa {
        address: Ipv6Addr,
    },
    #[serde(rename = "CNAME")]
    Cname {
        target: String,
    },
    #[serde(rename = "PTR")]
    Ptr {
        target: String,
    },
    #[serde(rename = "SRV")]
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    #[serde(rename = "TXT")]
    Txt {
        text: String,
    },
    #[serde(rename = "NS")]
    Ns {
        target: String,
    },
    #[serde(rename = "MX")]
    Mx {
        preference: u16,
        target: String,
    },
}

impl RecordData {
    pub fn typ(&self) -> RecordType {
        match self {
            Self::A { .. } => RecordType::A,
            Self::Aaaa { .. } => RecordType::Aaaa,
            Self::Cname { .. } => RecordType::Cname,
            Self::Ptr { .. } => RecordType::Ptr,
            Self::Srv { .. } => RecordType::Srv,
            Self::Txt { .. } => RecordType::Txt,
            Self::Ns { .. } => RecordType::Ns,
            Self::Mx { .. } => RecordType::Mx,
        }
    }

    /// Zkontroluje, že data mají smysl (platná jména, rozumné délky).
    pub fn validuj(&self) -> Result<()> {
        match self {
            Self::A { .. } | Self::Aaaa { .. } => Ok(()),
            Self::Cname { target } | Self::Ptr { target } | Self::Ns { target } => {
                validuj_cilove_jmeno(target)?;
                Ok(())
            }
            Self::Mx { target, .. } => {
                validuj_cilove_jmeno(target)?;
                Ok(())
            }
            Self::Srv { port, target, .. } => {
                if *port == 0 {
                    return Err(AdError::out_of_range("port v SRV nesmí být 0"));
                }
                validuj_cilove_jmeno(target)?;
                Ok(())
            }
            Self::Txt { text } => {
                if text.len() > 255 {
                    return Err(AdError::out_of_range("TXT záznam je nejvýš 255 bajtů"));
                }
                if text.chars().any(|c| c.is_control()) {
                    return Err(AdError::bad_request("TXT záznam obsahuje řídicí znak"));
                }
                Ok(())
            }
        }
    }
}

/// Jeden záznam v zóně.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: i64,
    pub zone_id: i64,
    /// Jméno vlevo, relativně k zóně. `@` znamená vrchol zóny.
    pub name: String,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: RecordData,
    /// Záznam spravuje server (A/PTR/SRV řadiče, registrace klientů).
    /// Ručně se nemaže.
    pub managed: bool,
}

/// Validuje jméno vlevo v záznamu (relativní jméno nebo `@`).
pub fn validuj_jmeno_zaznamu(jmeno: &str) -> Result<String> {
    let s = jmeno.trim().trim_end_matches('.').to_ascii_lowercase();
    if s == "@" || s.is_empty() {
        return Ok("@".to_string());
    }
    if s.len() > 253 {
        return Err(AdError::new(ErrorCode::InvalidName, "jméno záznamu je příliš dlouhé"));
    }
    for label in s.split('.') {
        validuj_label_zaznamu(label)?;
    }
    Ok(s)
}

/// Label v záznamu smí navíc začínat podtržítkem (SRV) nebo být `*`
/// (zástupný znak), proto nepoužíváme `names::validuj_dns_label`.
fn validuj_label_zaznamu(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(AdError::new(ErrorCode::InvalidName, "prázdná část jména záznamu"));
    }
    if label.len() > 63 {
        return Err(AdError::new(
            ErrorCode::InvalidName,
            "část jména záznamu je delší než 63 znaků",
        ));
    }
    if label == "*" {
        return Ok(());
    }
    let jadro = label.strip_prefix('_').unwrap_or(label);
    if jadro.is_empty() {
        return Err(AdError::new(ErrorCode::InvalidName, "část jména je jen podtržítko"));
    }
    if jadro.starts_with('-') || jadro.ends_with('-') {
        return Err(AdError::new(
            ErrorCode::InvalidName,
            "část jména nesmí začínat ani končit pomlčkou",
        ));
    }
    if !jadro.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(AdError::new(
            ErrorCode::InvalidName,
            "část jména smí mít jen a-z, 0-9, pomlčku (a volitelné podtržítko na začátku)",
        ));
    }
    Ok(())
}

/// Validuje cílové jméno vpravo (plně kvalifikované, bez `*` a `_`).
pub fn validuj_cilove_jmeno(jmeno: &str) -> Result<String> {
    let s = jmeno.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err(AdError::new(ErrorCode::InvalidName, "cílové jméno je prázdné"));
    }
    if s.len() > 253 {
        return Err(AdError::new(ErrorCode::InvalidName, "cílové jméno je příliš dlouhé"));
    }
    if !s.contains('.') {
        return Err(AdError::new(
            ErrorCode::InvalidName,
            "cílové jméno musí být plné (např. dc01.skola.internal)",
        ));
    }
    for label in s.split('.') {
        validuj_label_zaznamu(label)?;
        if label.contains('*') {
            return Err(AdError::new(
                ErrorCode::InvalidName,
                "cílové jméno nesmí mít zástupný znak",
            ));
        }
    }
    Ok(s)
}

/// Zkontroluje TTL.
pub fn validuj_ttl(ttl: u32) -> Result<()> {
    if !(MIN_TTL..=MAX_TTL).contains(&ttl) {
        return Err(AdError::out_of_range(format!("TTL musí být {MIN_TTL} až {MAX_TTL} sekund")));
    }
    Ok(())
}

/// Jméno reverzní zóny pro IPv4 síť s maskou /8, /16 nebo /24.
///
/// `192.168.56.0/24` -> `56.168.192.in-addr.arpa`
pub fn reverzni_zona_ipv4(adresa: Ipv4Addr, prefix: u8) -> Result<String> {
    let o = adresa.octets();
    let jmeno = match prefix {
        8 => format!("{}.in-addr.arpa", o[0]),
        16 => format!("{}.{}.in-addr.arpa", o[1], o[0]),
        24 => format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0]),
        _ => {
            return Err(AdError::out_of_range("reverzní zónu umíme jen pro masku /8, /16 nebo /24"))
        }
    };
    Ok(jmeno)
}

/// Celé PTR jméno adresy: `192.168.56.10` -> `10.56.168.192.in-addr.arpa`.
pub fn ptr_jmeno(adresa: Ipv4Addr) -> String {
    let o = adresa.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Relativní jméno PTR záznamu v dané reverzní zóně.
///
/// Pro adresu `192.168.56.10` v zóně `56.168.192.in-addr.arpa` vrátí `10`.
pub fn ptr_relativne(adresa: Ipv4Addr, zona: &str) -> Result<String> {
    let plne = ptr_jmeno(adresa);
    let zona = zona.trim_end_matches('.').to_ascii_lowercase();
    let pripona = format!(".{zona}");
    plne.strip_suffix(&pripona).map(|s| s.to_string()).ok_or_else(|| {
        AdError::new(ErrorCode::RecordConflict, format!("adresa {adresa} nepatří do zóny {zona}"))
    })
}

/// Složí plné jméno záznamu ze relativního jména a jména zóny.
pub fn plne_jmeno(relativni: &str, zona: &str) -> String {
    if relativni == "@" {
        zona.to_string()
    } else {
        format!("{relativni}.{zona}")
    }
}

/// Patří jméno do zóny?
pub fn patri_do_zony(plne: &str, zona: &str) -> bool {
    let p = plne.trim_end_matches('.').to_ascii_lowercase();
    let z = zona.trim_end_matches('.').to_ascii_lowercase();
    p == z || p.ends_with(&format!(".{z}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverzni_zony() {
        let ip: Ipv4Addr = "192.168.56.10".parse().unwrap();
        assert_eq!(reverzni_zona_ipv4(ip, 24).unwrap(), "56.168.192.in-addr.arpa");
        assert_eq!(reverzni_zona_ipv4(ip, 16).unwrap(), "168.192.in-addr.arpa");
        assert_eq!(reverzni_zona_ipv4(ip, 8).unwrap(), "192.in-addr.arpa");
        assert!(reverzni_zona_ipv4(ip, 25).is_err());
    }

    #[test]
    fn ptr_jmena() {
        let ip: Ipv4Addr = "192.168.56.10".parse().unwrap();
        assert_eq!(ptr_jmeno(ip), "10.56.168.192.in-addr.arpa");
        assert_eq!(ptr_relativne(ip, "56.168.192.in-addr.arpa").unwrap(), "10");
        assert_eq!(ptr_relativne(ip, "168.192.in-addr.arpa").unwrap(), "10.56");
        assert!(ptr_relativne(ip, "1.2.3.in-addr.arpa").is_err());
    }

    #[test]
    fn jmena_zaznamu() {
        assert_eq!(validuj_jmeno_zaznamu("").unwrap(), "@");
        assert_eq!(validuj_jmeno_zaznamu("DC01").unwrap(), "dc01");
        assert_eq!(validuj_jmeno_zaznamu("_ad._tcp").unwrap(), "_ad._tcp");
        assert_eq!(validuj_jmeno_zaznamu("*").unwrap(), "*");
        assert!(validuj_jmeno_zaznamu("dc 01").is_err());
        assert!(validuj_jmeno_zaznamu("-dc").is_err());
        assert!(validuj_jmeno_zaznamu("dc..01").is_err());
    }

    #[test]
    fn cilova_jmena_musi_byt_plna() {
        assert_eq!(validuj_cilove_jmeno("DC01.Skola.Internal.").unwrap(), "dc01.skola.internal");
        assert!(validuj_cilove_jmeno("dc01").is_err());
        assert!(validuj_cilove_jmeno("*.skola.internal").is_err());
        assert!(validuj_cilove_jmeno("").is_err());
    }

    #[test]
    fn data_zaznamu_v_json() {
        let a = RecordData::A { address: "192.168.56.10".parse().unwrap() };
        assert_eq!(serde_json::to_string(&a).unwrap(), r#"{"type":"A","address":"192.168.56.10"}"#);
        let srv = RecordData::Srv {
            priority: 0,
            weight: 100,
            port: 8443,
            target: "dc01.skola.internal".into(),
        };
        let j = serde_json::to_value(&srv).unwrap();
        assert_eq!(j["type"], "SRV");
        assert_eq!(j["port"], 8443);
        assert_eq!(srv.typ(), RecordType::Srv);
        srv.validuj().unwrap();
    }

    #[test]
    fn validace_dat() {
        assert!(RecordData::Srv { priority: 0, weight: 0, port: 0, target: "a.b".into() }
            .validuj()
            .is_err());
        assert!(RecordData::Txt { text: "a".repeat(256) }.validuj().is_err());
        assert!(RecordData::Txt { text: "ahoj\u{0}".into() }.validuj().is_err());
        assert!(RecordData::Cname { target: "dc01".into() }.validuj().is_err());
        RecordData::Txt { text: "v=ad1".into() }.validuj().unwrap();
    }

    #[test]
    fn ttl_rozsah() {
        assert!(validuj_ttl(10).is_err());
        assert!(validuj_ttl(1_000_000).is_err());
        validuj_ttl(VYCHOZI_TTL).unwrap();
    }

    #[test]
    fn prislusnost_k_zone() {
        assert!(patri_do_zony("dc01.skola.internal", "skola.internal"));
        assert!(patri_do_zony("skola.internal.", "skola.internal"));
        assert!(!patri_do_zony("dc01.jina.internal", "skola.internal"));
        assert!(!patri_do_zony("xskola.internal", "skola.internal"));
        assert_eq!(plne_jmeno("@", "skola.internal"), "skola.internal");
        assert_eq!(plne_jmeno("dc01", "skola.internal"), "dc01.skola.internal");
    }
}
