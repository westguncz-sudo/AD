//! Datový model domény. Tyto struktury jdou po drátě do webového rozhraní
//! i klientovi, proto v nich **není nic tajného** — žádné hashe hesel,
//! žádná tajemství počítačů. Ta zůstávají jen v databázi serveru.

use crate::ids::{Guid, Sid};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Čas v RFC 3339 (`2026-11-25T18:00:00Z`).
pub mod cas {
    pub use time::serde::rfc3339 as povinny;
    pub use time::serde::rfc3339::option as volitelny;
}

/// Doména. V naší implementaci je v databázi vždy nejvýš jedna.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    /// Plné DNS jméno, např. `skola.internal`.
    pub dns_name: String,
    /// Krátké jméno, např. `SKOLA`.
    pub short_name: String,
    /// Identifikátor domény.
    pub domain_sid: crate::ids::DomainSid,
    /// Jméno řadiče domény bez domény, např. `DC01`.
    pub dc_hostname: String,
    /// Plné jméno řadiče, např. `dc01.skola.internal`.
    pub dc_fqdn: String,
    /// IP adresa, na které řadič poslouchá a která je v DNS záznamu A.
    pub dc_ip: String,
    #[serde(with = "cas::povinny")]
    pub created_at: OffsetDateTime,
}

/// Organizační jednotka — uzel ve stromu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ou {
    pub id: i64,
    pub guid: Guid,
    pub name: String,
    /// `None` = OU přímo pod doménou.
    pub parent_id: Option<i64>,
    /// Cesta od korene pro zobrazení a pro vyhodnocení zásad,
    /// např. `/Uzivatele/Zaci`.
    pub path: String,
    pub description: String,
    /// Chrání OU proti smazání (obdoba „Protect object from accidental deletion“).
    pub protected: bool,
    #[serde(with = "cas::povinny")]
    pub created_at: OffsetDateTime,
}

/// Uživatelský účet. Bez hesla.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub guid: Guid,
    pub sid: Sid,
    /// Přihlašovací jméno malými písmeny, např. `jan.novak`.
    pub sam_account_name: String,
    /// `jan.novak@skola.internal`
    pub upn: String,
    pub display_name: String,
    pub given_name: String,
    pub surname: String,
    pub email: String,
    pub description: String,
    pub ou_id: Option<i64>,
    pub enabled: bool,
    /// Musí si při příštím přihlášení změnit heslo.
    pub must_change_password: bool,
    /// Heslo tomuto účtu nikdy nevyprší.
    pub password_never_expires: bool,
    #[serde(with = "cas::volitelny")]
    pub password_set_at: Option<OffsetDateTime>,
    #[serde(with = "cas::volitelny")]
    pub last_logon_at: Option<OffsetDateTime>,
    /// Do kdy je účet zamčený. `None` = není zamčený.
    #[serde(with = "cas::volitelny")]
    pub locked_until: Option<OffsetDateTime>,
    /// Vestavěný účet (např. Administrator) — nedá se smazat.
    pub builtin: bool,
    #[serde(with = "cas::povinny")]
    pub created_at: OffsetDateTime,
}

/// K čemu skupina slouží.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// Skupina dává práva (obdoba Security group).
    #[default]
    Security,
    /// Skupina je jen seznam (obdoba Distribution group).
    Distribution,
}

/// Skupina uživatelů nebo počítačů.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub guid: Guid,
    pub sid: Sid,
    pub sam_account_name: String,
    pub name: String,
    pub description: String,
    pub kind: GroupKind,
    pub ou_id: Option<i64>,
    pub builtin: bool,
    /// Počet členů — doplňuje server, ať se nemusí dotazovat zvlášť.
    #[serde(default)]
    pub member_count: u32,
    #[serde(with = "cas::povinny")]
    pub created_at: OffsetDateTime,
}

/// Druh členství — skupina může obsahovat uživatele, počítače i jiné skupiny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    User,
    Group,
    Computer,
}

/// Jeden člen skupiny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub kind: MemberKind,
    pub id: i64,
    pub sid: Sid,
    /// Jméno pro zobrazení v seznamu.
    pub name: String,
}

/// Počítačový účet. Tajemství (`machine_secret`) tady **není**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Computer {
    pub id: i64,
    pub guid: Guid,
    pub sid: Sid,
    /// Jméno velkými písmeny, např. `PC-01`.
    pub name: String,
    /// `pc-01.skola.internal`
    pub dns_name: String,
    pub description: String,
    pub ou_id: Option<i64>,
    pub enabled: bool,
    /// Co o sobě klient řekl při připojení. Je to **nedůvěryhodný text**
    /// od klienta, v UI se escapuje.
    pub os_name: String,
    pub os_version: String,
    /// Poslední IP, ze které se klient ohlásil.
    pub last_ip: String,
    #[serde(with = "cas::povinny")]
    pub joined_at: OffsetDateTime,
    #[serde(with = "cas::volitelny")]
    pub last_seen_at: Option<OffsetDateTime>,
}

/// Kam je zásada připojená.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum GpoTarget {
    /// Na celou doménu.
    Domain,
    /// Na jednu OU.
    Ou { ou_id: i64 },
}

/// Zásada skupiny (naše obdoba GPO).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gpo {
    pub id: i64,
    pub guid: Guid,
    pub name: String,
    pub description: String,
    /// Vypnutá zásada se nevyhodnocuje vůbec.
    pub enabled: bool,
    pub settings: crate::policy::PolicySet,
    #[serde(with = "cas::povinny")]
    pub created_at: OffsetDateTime,
    #[serde(with = "cas::povinny")]
    pub modified_at: OffsetDateTime,
}

/// Připojení zásady k doméně nebo OU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpoLink {
    pub id: i64,
    pub gpo_id: i64,
    pub gpo_guid: Guid,
    pub gpo_name: String,
    pub target: GpoTarget,
    /// Pořadí v rámci jedné úrovně; menší číslo = vyšší priorita,
    /// stejně jako v AD.
    pub order: u32,
    /// Vynucené připojení přebije i zásady z nižších OU.
    pub enforced: bool,
    pub enabled: bool,
}

/// Jaké role jsou na serveru nainstalované. Odpovídá „Přidat role
/// a funkce“.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InstalledRoles {
    /// Doménové služby (obdoba AD DS).
    pub directory: bool,
    /// Náš DNS server.
    pub dns: bool,
}

/// V jakém stavu je server jako celek.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStage {
    /// Čistý server, nic nenainstalováno.
    Fresh,
    /// Role nainstalované, doména ještě není.
    RolesInstalled,
    /// Server je řadič domény.
    DomainController,
}

/// Záznam v auditním logu. Nikdy neobsahuje hesla.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    #[serde(with = "cas::povinny")]
    pub at: OffsetDateTime,
    /// Strojový kód akce, např. `user.create`, `auth.logon.failed`.
    pub action: String,
    /// Kdo akci udělal: `SKOLA\administrator`, `machine:PC-01`, `setup-token`.
    pub actor: String,
    /// Čeho se akce týkala, např. `user:jan.novak`.
    pub target: String,
    /// IP adresa, ze které akce přišla.
    pub source_ip: String,
    pub success: bool,
    /// Volné podrobnosti pro zobrazení.
    pub detail: String,
}

/// Úroveň závažnosti upozornění na přehledu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertLevel {
    Info,
    Warning,
    Error,
}

/// Upozornění na přehledu — třeba „Povýšit server na řadič domény“.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// Stabilní kód, podle kterého UI pozná, co nabídnout za akci.
    pub code: String,
    pub level: AlertLevel,
    pub title: String,
    pub detail: String,
    /// Kam má odkazovat tlačítko v UI, např. `#/promote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::DomainSid;
    use time::macros::datetime;

    #[test]
    fn domena_se_serializuje_s_rfc3339() {
        let d = Domain {
            dns_name: "skola.internal".into(),
            short_name: "SKOLA".into(),
            domain_sid: DomainSid { a: 1, b: 2, c: 3 },
            dc_hostname: "DC01".into(),
            dc_fqdn: "dc01.skola.internal".into(),
            dc_ip: "192.168.56.10".into(),
            created_at: datetime!(2026-11-25 18:00:00 UTC),
        };
        let j = serde_json::to_value(&d).unwrap();
        assert_eq!(j["created_at"], "2026-11-25T18:00:00Z");
        assert_eq!(j["domain_sid"]["a"], 1);
        let zpet: Domain = serde_json::from_value(j).unwrap();
        assert_eq!(zpet, d);
    }

    #[test]
    fn cil_gpo_ma_tag() {
        assert_eq!(serde_json::to_string(&GpoTarget::Domain).unwrap(), r#"{"scope":"domain"}"#);
        assert_eq!(
            serde_json::to_string(&GpoTarget::Ou { ou_id: 7 }).unwrap(),
            r#"{"scope":"ou","ou_id":7}"#
        );
    }

    #[test]
    fn volitelny_cas_je_null() {
        let j = serde_json::json!({
            "id": 1, "guid": "00000000-0000-4000-8000-000000000000",
            "sid": "S-1-5-21-1-2-3-10000",
            "sam_account_name": "jan", "upn": "jan@skola.internal",
            "display_name": "Jan", "given_name": "Jan", "surname": "Novák",
            "email": "", "description": "", "ou_id": null, "enabled": true,
            "must_change_password": false, "password_never_expires": false,
            "password_set_at": null, "last_logon_at": null, "locked_until": null,
            "builtin": false, "created_at": "2026-11-25T18:00:00Z"
        });
        let u: User = serde_json::from_value(j).unwrap();
        assert!(u.password_set_at.is_none());
        assert_eq!(u.surname, "Novák");
    }
}
