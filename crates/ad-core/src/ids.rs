//! Identifikátory objektů.
//!
//! Napodobujeme vzhled SID ze skutečného AD (`S-1-5-21-a-b-c-RID`), ale je to
//! **náš vlastní** formát — nic se nesnaží být binárně kompatibilní.
//! Doména má trojici náhodných 32bitových čísel, každý objekt v ní má RID.

use crate::error::{AdError, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// RID (relative identifier) vyhrazené pro systémové objekty.
pub mod rid {
    /// Vestavěný správce domény.
    pub const ADMINISTRATOR: u32 = 500;
    /// Vestavěný účet hosta (vytvoříme ho vypnutý).
    pub const GUEST: u32 = 501;
    /// Skupina správců domény.
    pub const DOMAIN_ADMINS: u32 = 512;
    /// Skupina všech uživatelů domény.
    pub const DOMAIN_USERS: u32 = 513;
    /// Skupina všech počítačů domény.
    pub const DOMAIN_COMPUTERS: u32 = 515;
    /// Skupina operátorů, kteří smí spravovat DNS.
    pub const DNS_ADMINS: u32 = 1101;
    /// První RID pro objekty vytvořené uživatelem.
    pub const FIRST_USER_RID: u32 = 10000;

    /// Je RID vyhrazený systémem?
    pub fn je_vyhrazeny(rid: u32) -> bool {
        rid < FIRST_USER_RID
    }
}

/// Identifikátor domény: tři náhodná 32bitová čísla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainSid {
    pub a: u32,
    pub b: u32,
    pub c: u32,
}

impl DomainSid {
    /// Vygeneruje nový náhodný identifikátor domény z OS generátoru.
    pub fn generate() -> Self {
        let mut buf = [0u8; 12];
        crate::rand_bytes(&mut buf);
        Self {
            a: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            b: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            c: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        }
    }

    /// Složí plný SID objektu s daným RID.
    pub fn sid(self, rid: u32) -> Sid {
        Sid { domain: self, rid }
    }
}

impl fmt::Display for DomainSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-1-5-21-{}-{}-{}", self.a, self.b, self.c)
    }
}

impl FromStr for DomainSid {
    type Err = AdError;

    fn from_str(s: &str) -> Result<Self> {
        let zbytek = s
            .strip_prefix("S-1-5-21-")
            .ok_or_else(|| AdError::new(ErrorCode::BadRequest, "SID musí začínat S-1-5-21-"))?;
        let casti: Vec<&str> = zbytek.split('-').collect();
        if casti.len() != 3 {
            return Err(AdError::new(ErrorCode::BadRequest, "SID domény má tři části"));
        }
        let cislo = |x: &str| -> Result<u32> {
            x.parse::<u32>().map_err(|_| AdError::new(ErrorCode::BadRequest, "část SID není číslo"))
        };
        Ok(Self { a: cislo(casti[0])?, b: cislo(casti[1])?, c: cislo(casti[2])? })
    }
}

/// Plný identifikátor objektu = SID domény + RID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sid {
    pub domain: DomainSid,
    pub rid: u32,
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.domain, self.rid)
    }
}

impl FromStr for Sid {
    type Err = AdError;

    fn from_str(s: &str) -> Result<Self> {
        let posledni =
            s.rfind('-').ok_or_else(|| AdError::new(ErrorCode::BadRequest, "SID nemá RID"))?;
        let domain: DomainSid = s[..posledni].parse()?;
        let rid = s[posledni + 1..]
            .parse::<u32>()
            .map_err(|_| AdError::new(ErrorCode::BadRequest, "RID není číslo"))?;
        Ok(Self { domain, rid })
    }
}

impl Serialize for Sid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// GUID objektu — stabilní napříč přejmenováním.
pub type Guid = uuid::Uuid;

/// Chyba při čtení GUID z textu.
pub type GuidError = uuid::Error;

/// Nový náhodný GUID (UUIDv4).
pub fn novy_guid() -> Guid {
    uuid::Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_tam_a_zpet() {
        let d = DomainSid { a: 1234, b: 5678, c: 9012 };
        assert_eq!(d.to_string(), "S-1-5-21-1234-5678-9012");
        let s = d.sid(rid::ADMINISTRATOR);
        assert_eq!(s.to_string(), "S-1-5-21-1234-5678-9012-500");
        assert_eq!(s.to_string().parse::<Sid>().unwrap(), s);
        assert_eq!(d.to_string().parse::<DomainSid>().unwrap(), d);
    }

    #[test]
    fn sid_odmitne_nesmysl() {
        assert!("S-1-5-32-1-2-3".parse::<DomainSid>().is_err());
        assert!("S-1-5-21-1-2".parse::<DomainSid>().is_err());
        assert!("S-1-5-21-1-2-x".parse::<DomainSid>().is_err());
        assert!("neco".parse::<Sid>().is_err());
    }

    #[test]
    fn generovany_sid_je_jiny() {
        let a = DomainSid::generate();
        let b = DomainSid::generate();
        assert_ne!(a, b, "dva náhodné SID se nesmí shodnout");
    }

    #[test]
    fn sid_v_json_je_string() {
        let s = DomainSid { a: 1, b: 2, c: 3 }.sid(513);
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"S-1-5-21-1-2-3-513\"");
    }

    #[test]
    fn vyhrazene_ridy() {
        assert!(rid::je_vyhrazeny(rid::DOMAIN_ADMINS));
        assert!(!rid::je_vyhrazeny(rid::FIRST_USER_RID));
    }
}
