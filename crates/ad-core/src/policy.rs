//! Zásady skupiny (obdoba GPO).
//!
//! # Bezpečnostní pravidlo číslo jedna
//! Zásada je **uzavřený výčet dat**, nikdy ne příkaz. Server nemá žádnou
//! možnost poslat klientovi text, který by klient spustil. Všechny struktury
//! mají `deny_unknown_fields`, takže kdyby server poslal cokoli navíc,
//! klient to odmítne už při parsování.
//!
//! Klient navíc po přijetí zásady znovu zavolá `validuj()` — nevěří ani
//! vlastnímu serveru.

use crate::error::{AdError, ErrorCode, Result};
use serde::{Deserialize, Serialize};

/// Mez pro titulek uvítací zprávy.
pub const MAX_TITULEK: usize = 120;
/// Mez pro text uvítací zprávy.
pub const MAX_TEXT_ZPRAVY: usize = 2000;
/// Největší povolená tapeta v bajtech (8 MiB).
pub const MAX_TAPETA_BAJTU: u64 = 8 * 1024 * 1024;

/// Pravidla pro hesla.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPolicy {
    /// Minimální délka hesla ve znacích.
    pub min_length: u8,
    /// Vyžadovat velké písmeno.
    pub require_uppercase: bool,
    /// Vyžadovat malé písmeno.
    pub require_lowercase: bool,
    /// Vyžadovat číslici.
    pub require_digit: bool,
    /// Vyžadovat symbol.
    pub require_symbol: bool,
    /// Maximální věk hesla ve dnech, 0 = nikdy nevyprší.
    pub max_age_days: u16,
    /// Minimální věk hesla ve dnech (brání rychlému protočení historie).
    pub min_age_days: u16,
    /// Kolik posledních hesel si pamatujeme a zakazujeme, 0 = žádná historie.
    pub history_length: u8,
    /// Zakázat heslo, které obsahuje přihlašovací jméno.
    pub forbid_username: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_symbol: false,
            max_age_days: 0,
            min_age_days: 0,
            history_length: 3,
            forbid_username: true,
        }
    }
}

impl PasswordPolicy {
    pub fn validuj(&self) -> Result<()> {
        if !(4..=128).contains(&self.min_length) {
            return Err(AdError::out_of_range("minimální délka hesla musí být 4 až 128"));
        }
        if self.max_age_days > 3650 {
            return Err(AdError::out_of_range("maximální věk hesla je nejvýš 3650 dní"));
        }
        if self.min_age_days > 365 {
            return Err(AdError::out_of_range("minimální věk hesla je nejvýš 365 dní"));
        }
        if self.max_age_days != 0 && self.min_age_days as u32 >= self.max_age_days as u32 {
            return Err(AdError::out_of_range("minimální věk hesla musí být menší než maximální"));
        }
        if self.history_length > 24 {
            return Err(AdError::out_of_range("historie hesel je nejvýš 24"));
        }
        Ok(())
    }
}

/// Pravidla zamykání účtu po neúspěšných přihlášeních.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockoutPolicy {
    /// Kolik špatných hesel vede k zamčení, 0 = nezamykat.
    pub threshold: u8,
    /// V jakém okně se špatné pokusy počítají (minuty).
    pub window_minutes: u16,
    /// Jak dlouho je účet zamčený (minuty).
    pub duration_minutes: u16,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self { threshold: 5, window_minutes: 15, duration_minutes: 15 }
    }
}

impl LockoutPolicy {
    pub fn validuj(&self) -> Result<()> {
        if self.threshold > 100 {
            return Err(AdError::out_of_range("počet pokusů je nejvýš 100"));
        }
        if self.threshold > 0 {
            if !(1..=1440).contains(&self.window_minutes) {
                return Err(AdError::out_of_range("okno pro počítání pokusů je 1 až 1440 minut"));
            }
            if !(1..=10080).contains(&self.duration_minutes) {
                return Err(AdError::out_of_range("doba zamčení je 1 až 10080 minut"));
            }
        }
        Ok(())
    }
}

/// Uvítací zpráva, kterou klient zobrazí po přihlášení. **Čistý text.**
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WelcomeMessage {
    pub enabled: bool,
    pub title: String,
    pub body: String,
}

impl WelcomeMessage {
    pub fn validuj(&self) -> Result<()> {
        if self.title.chars().count() > MAX_TITULEK {
            return Err(AdError::out_of_range(format!(
                "titulek zprávy je delší než {MAX_TITULEK} znaků"
            )));
        }
        if self.body.chars().count() > MAX_TEXT_ZPRAVY {
            return Err(AdError::out_of_range(format!(
                "text zprávy je delší než {MAX_TEXT_ZPRAVY} znaků"
            )));
        }
        // Řídicí znaky kromě nového řádku a tabulátoru zahodíme hned tady,
        // aby se nedaly použít na podvržení výpisu v terminálu klienta.
        for (jmeno, text) in [("titulek", &self.title), ("text", &self.body)] {
            if text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
                return Err(AdError::new(
                    ErrorCode::BadRequest,
                    format!("{jmeno} zprávy obsahuje řídicí znak"),
                ));
            }
        }
        if self.enabled && self.title.trim().is_empty() && self.body.trim().is_empty() {
            return Err(AdError::bad_request("zapnutá uvítací zpráva nesmí být prázdná"));
        }
        Ok(())
    }
}

/// Jak tapetu umístit na plochu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WallpaperStyle {
    /// Vyplnit a případně přesahující části odříznout.
    #[default]
    Fill,
    /// Vejít se celý, zbytek dobarvit.
    Fit,
    /// Roztáhnout bez ohledu na poměr stran.
    Stretch,
    /// Vycentrovat v původní velikosti.
    Center,
    /// Vyskládat vedle sebe.
    Tile,
}

/// Formát obrázku. Jen rastrové formáty, které umíme ověřit podle hlavičky.
/// Záměrně **ne** SVG — to je XML a umí v sobě skript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Png,
    Jpeg,
}

impl ImageFormat {
    /// Pozná formát podle magických bajtů. `None` = nepodporovaný soubor.
    pub fn poznej(data: &[u8]) -> Option<Self> {
        const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        if data.starts_with(PNG) {
            return Some(Self::Png);
        }
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(Self::Jpeg);
        }
        None
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }

    pub fn pripona(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
        }
    }
}

/// Tapeta. Klient si obrázek stáhne zvlášť podle `asset_id` a **musí**
/// zkontrolovat `sha256`, jinak soubor zahodí.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WallpaperPolicy {
    pub enabled: bool,
    /// ID souboru na serveru (`GET /api/v1/machine/asset/{id}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<crate::ids::Guid>,
    /// Kontrolní součet obsahu, hex, malá písmena, 64 znaků.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub format: Option<ImageFormat>,
    pub style: WallpaperStyle,
    /// Zakázat uživateli tapetu změnit (klient to jen oznámí, nevynucuje
    /// to v systému — přihlašování do systému zatím neřešíme).
    pub lock_user_change: bool,
}

impl Default for WallpaperPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            asset_id: None,
            sha256: None,
            format: None,
            style: WallpaperStyle::Fill,
            lock_user_change: false,
        }
    }
}

impl WallpaperPolicy {
    pub fn validuj(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.asset_id.is_none() {
            return Err(AdError::bad_request("zapnutá tapeta musí mít asset_id"));
        }
        if self.format.is_none() {
            return Err(AdError::bad_request("zapnutá tapeta musí mít formát"));
        }
        let Some(h) = self.sha256.as_deref() else {
            return Err(AdError::bad_request("zapnutá tapeta musí mít sha256"));
        };
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err(AdError::bad_request(
                "sha256 musí být 64 hexadecimálních znaků malými písmeny",
            ));
        }
        Ok(())
    }
}

/// Sada zásad jedné GPO. Každá část je volitelná: `None` znamená
/// „tato GPO o tom nerozhoduje“ a hodnota se vezme z nadřazené úrovně.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<PasswordPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout: Option<LockoutPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome: Option<WelcomeMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallpaper: Option<WallpaperPolicy>,
}

impl PolicySet {
    pub fn validuj(&self) -> Result<()> {
        if let Some(p) = &self.password {
            p.validuj()?;
        }
        if let Some(p) = &self.lockout {
            p.validuj()?;
        }
        if let Some(p) = &self.welcome {
            p.validuj()?;
        }
        if let Some(p) = &self.wallpaper {
            p.validuj()?;
        }
        Ok(())
    }

    /// Je sada úplně prázdná?
    pub fn je_prazdna(&self) -> bool {
        self.password.is_none()
            && self.lockout.is_none()
            && self.welcome.is_none()
            && self.wallpaper.is_none()
    }
}

/// Výsledná zásada po vyhodnocení celého řetězce GPO. Tady už je všechno
/// vyplněné, takže se klient nemusí ptát „a co když je to None“.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub password: PasswordPolicy,
    pub lockout: LockoutPolicy,
    pub welcome: WelcomeMessage,
    pub wallpaper: WallpaperPolicy,
    /// Které GPO se na výsledku podílely, v pořadí použití. Jen pro
    /// zobrazení („výsledná sada zásad“) a pro ladění.
    #[serde(default)]
    pub applied: Vec<AppliedGpo>,
}

impl EffectivePolicy {
    pub fn validuj(&self) -> Result<()> {
        self.password.validuj()?;
        self.lockout.validuj()?;
        self.welcome.validuj()?;
        self.wallpaper.validuj()?;
        Ok(())
    }
}

/// Záznam o jedné použité GPO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedGpo {
    pub guid: crate::ids::Guid,
    pub name: String,
    /// Kde byla GPO připojená (doména / cesta k OU).
    pub linked_at: String,
    pub enforced: bool,
}

/// Jedna GPO připravená k vyhodnocení.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpoKVyhodnoceni {
    pub guid: crate::ids::Guid,
    pub name: String,
    pub linked_at: String,
    /// Vynucená GPO přebije i ty, které jsou v řetězci níž.
    pub enforced: bool,
    pub policy: PolicySet,
}

/// Vyhodnotí řetězec GPO. Vstup musí být **v pořadí od domény k listu**
/// (nejdřív GPO připojené na doménu, pak OU od korene k dané OU).
///
/// Pravidla, stejná jako ve skutečném AD:
/// 1. Co je dál od korene, přebíjí to, co je blíž.
/// 2. GPO označená „vynuceno“ (enforced) ale přebíjí vše, co přišlo po ní.
pub fn vyhodnot(retez: &[GpoKVyhodnoceni]) -> EffectivePolicy {
    let mut vysledek = EffectivePolicy::default();
    // Nejdřív nevynucené v daném pořadí, pak vynucené v daném pořadí —
    // tím se vynucené dostanou „nahoru“.
    let poradi = retez.iter().filter(|g| !g.enforced).chain(retez.iter().filter(|g| g.enforced));

    for g in poradi {
        if let Some(v) = &g.policy.password {
            vysledek.password = v.clone();
        }
        if let Some(v) = &g.policy.lockout {
            vysledek.lockout = v.clone();
        }
        if let Some(v) = &g.policy.welcome {
            vysledek.welcome = v.clone();
        }
        if let Some(v) = &g.policy.wallpaper {
            vysledek.wallpaper = v.clone();
        }
        if !g.policy.je_prazdna() {
            vysledek.applied.push(AppliedGpo {
                guid: g.guid,
                name: g.name.clone(),
                linked_at: g.linked_at.clone(),
                enforced: g.enforced,
            });
        }
    }
    vysledek
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpo(jmeno: &str, enforced: bool, min: u8) -> GpoKVyhodnoceni {
        GpoKVyhodnoceni {
            guid: crate::ids::novy_guid(),
            name: jmeno.to_string(),
            linked_at: "/".to_string(),
            enforced,
            policy: PolicySet {
                password: Some(PasswordPolicy { min_length: min, ..Default::default() }),
                ..Default::default()
            },
        }
    }

    #[test]
    fn blizsi_ou_prebiji_domenu() {
        let v = vyhodnot(&[gpo("domena", false, 8), gpo("ou", false, 12)]);
        assert_eq!(v.password.min_length, 12);
        assert_eq!(v.applied.len(), 2);
    }

    #[test]
    fn vynucena_gpo_prebiji_vsechno() {
        let v = vyhodnot(&[gpo("domena-vynucena", true, 14), gpo("ou", false, 6)]);
        assert_eq!(v.password.min_length, 14);
    }

    #[test]
    fn prazdny_retez_da_vychozi_hodnoty() {
        let v = vyhodnot(&[]);
        assert_eq!(v.password, PasswordPolicy::default());
        assert!(v.applied.is_empty());
        v.validuj().unwrap();
    }

    #[test]
    fn neznama_polozka_v_json_se_odmitne() {
        // Tohle je ta hlavní pojistka: server nemůže klientovi propašovat
        // nic, co klient nezná.
        let j = r#"{"password":{"min_length":8,"require_uppercase":true,
            "require_lowercase":true,"require_digit":true,"require_symbol":false,
            "max_age_days":0,"min_age_days":0,"history_length":3,
            "forbid_username":true,"run_command":"rm -rf /"}}"#;
        let r: std::result::Result<PolicySet, _> = serde_json::from_str(j);
        assert!(r.is_err(), "neznámé pole musí odmítnout");

        let j2 = r#"{"script":"calc.exe"}"#;
        assert!(serde_json::from_str::<PolicySet>(j2).is_err());
    }

    #[test]
    fn validace_hesel_hlida_rozsahy() {
        assert!(PasswordPolicy { min_length: 3, ..Default::default() }.validuj().is_err());
        assert!(PasswordPolicy { min_length: 129, ..Default::default() }.validuj().is_err());
        assert!(PasswordPolicy { min_age_days: 10, max_age_days: 5, ..Default::default() }
            .validuj()
            .is_err());
        assert!(PasswordPolicy { history_length: 25, ..Default::default() }.validuj().is_err());
        PasswordPolicy::default().validuj().unwrap();
    }

    #[test]
    fn validace_zamykani() {
        assert!(LockoutPolicy { threshold: 5, window_minutes: 0, duration_minutes: 10 }
            .validuj()
            .is_err());
        // Vypnuté zamykání nemusí mít smysluplné okno.
        LockoutPolicy { threshold: 0, window_minutes: 0, duration_minutes: 0 }.validuj().unwrap();
        LockoutPolicy::default().validuj().unwrap();
    }

    #[test]
    fn uvitaci_zprava_bez_ridicich_znaku() {
        let z =
            WelcomeMessage { enabled: true, title: "Vítej".into(), body: "ahoj\u{1b}[2J".into() };
        assert!(z.validuj().is_err(), "ANSI escape musí projít jako chyba");
        let ok =
            WelcomeMessage {
                enabled: true, title: "Vítej".into(), body: "první\nřádek".into()
            };
        ok.validuj().unwrap();
        let prazdna = WelcomeMessage { enabled: true, title: " ".into(), body: "".into() };
        assert!(prazdna.validuj().is_err());
    }

    #[test]
    fn tapeta_potrebuje_soucet() {
        let mut t = WallpaperPolicy { enabled: true, ..Default::default() };
        assert!(t.validuj().is_err());
        t.asset_id = Some(crate::ids::novy_guid());
        t.format = Some(ImageFormat::Png);
        assert!(t.validuj().is_err());
        t.sha256 = Some("AB".repeat(32));
        assert!(t.validuj().is_err(), "velká písmena v hexu neberem");
        t.sha256 = Some("ab".repeat(32));
        t.validuj().unwrap();
    }

    #[test]
    fn format_obrazku_podle_hlavicky() {
        assert_eq!(
            ImageFormat::poznej(&[0x89, b'P', b'N', b'G', 13, 10, 26, 10, 0]),
            Some(ImageFormat::Png)
        );
        assert_eq!(ImageFormat::poznej(&[0xFF, 0xD8, 0xFF, 0xE0]), Some(ImageFormat::Jpeg));
        assert_eq!(ImageFormat::poznej(b"<svg xmlns"), None);
        assert_eq!(ImageFormat::poznej(b""), None);
    }
}
