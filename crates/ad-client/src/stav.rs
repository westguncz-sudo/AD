//! Co si klient pamatuje mezi spuštěními.
//!
//! Všechno je v jednom adresáři, takže odinstalace znamená smazat ho.
//! Soubor se stavem obsahuje tajemství počítačového účtu, proto má
//! práva jen pro vlastníka.

use ad_core::{AdError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// Cesty ke všemu, co si klient ukládá.
#[derive(Debug, Clone)]
pub struct Cesty {
    pub data_dir: PathBuf,
}

impl Cesty {
    pub fn nove(prepsano: Option<PathBuf>) -> Self {
        let data = prepsano
            .or_else(|| std::env::var_os("AD_CLIENT_DATA_DIR").map(PathBuf::from))
            .unwrap_or_else(Self::vychozi);
        Self { data_dir: data }
    }

    #[cfg(windows)]
    fn vychozi() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("ad-client")
    }

    #[cfg(not(windows))]
    fn vychozi() -> PathBuf {
        PathBuf::from("/var/lib/ad-client")
    }

    pub fn stav(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }

    pub fn ca(&self) -> PathBuf {
        self.data_dir.join("ca.pem")
    }

    pub fn dns_zaloha(&self) -> PathBuf {
        self.data_dir.join("dns-backup.json")
    }

    pub fn zasady(&self) -> PathBuf {
        self.data_dir.join("policy.json")
    }

    pub fn tapeta(&self) -> PathBuf {
        self.data_dir.join("tapeta")
    }

    pub fn priprav(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir).map_err(|e| {
            AdError::internal(format!(
                "nelze vytvořit {}: {e}. Spusť příkaz se správcovským oprávněním, \
                 nebo zvol jiný adresář přepínačem --data-dir.",
                self.data_dir.display()
            ))
        })?;
        omez_prava(&self.data_dir)?;
        Ok(())
    }
}

/// Stav připojení do domény.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StavPripojeni {
    pub server_host: String,
    pub server_port: u16,
    /// Připnutý otisk certifikační autority domény.
    pub ca_fingerprint: String,
    pub machine_id: String,
    /// Tajemství počítačového účtu. Nikdy se nevypisuje.
    pub machine_secret: String,
    pub computer_name: String,
    pub domain_dns_name: String,
    pub domain_short_name: String,
    pub dc_fqdn: String,
    pub dns_servers: Vec<String>,
    pub policy_poll_seconds: u64,
    pub joined_at: String,
}

impl StavPripojeni {
    pub fn nacti(cesty: &Cesty) -> Result<Option<Self>> {
        match std::fs::read_to_string(cesty.stav()) {
            Ok(text) => {
                let s: Self = serde_json::from_str(&text).map_err(|e| {
                    AdError::internal(format!(
                        "soubor {} je poškozený: {e}",
                        cesty.stav().display()
                    ))
                })?;
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => {
                Err(AdError::internal(format!("nelze přečíst {}: {e}", cesty.stav().display())))
            }
        }
    }

    /// Stav, nebo srozumitelná chyba, že počítač v doméně není.
    pub fn vyzaduj(cesty: &Cesty) -> Result<Self> {
        Self::nacti(cesty)?.ok_or_else(|| {
            AdError::bad_request("tenhle počítač není v doméně. Nejdřív spusť: ad-client join …")
        })
    }

    pub fn uloz(&self, cesty: &Cesty) -> Result<()> {
        cesty.priprav()?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| AdError::internal(format!("stav: {e}")))?;
        zapis_tajne(&cesty.stav(), &text)
    }
}

/// Naposledy stažené zásady.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UlozeneZasady {
    pub policy: ad_core::policy::EffectivePolicy,
    pub serial: u64,
    pub fetched_at: String,
    /// Kdy se naposledy povedlo zásady skutečně použít.
    #[serde(default)]
    pub applied_at: Option<String>,
}

impl UlozeneZasady {
    pub fn nacti(cesty: &Cesty) -> Result<Option<Self>> {
        match std::fs::read_to_string(cesty.zasady()) {
            Ok(t) => Ok(serde_json::from_str(&t).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AdError::internal(format!("zásady: {e}"))),
        }
    }

    pub fn uloz(&self, cesty: &Cesty) -> Result<()> {
        cesty.priprav()?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| AdError::internal(format!("zásady: {e}")))?;
        std::fs::write(cesty.zasady(), text)
            .map_err(|e| AdError::internal(format!("nelze zapsat zásady: {e}")))
    }
}

/// Čas v RFC 3339 pro ukládání do souborů.
pub fn nyni_text() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Práva jen pro vlastníka.
///
/// Na Windows to programově neděláme — `C:\ProgramData\ad-client`
/// dědí ACL, které běžnému uživateli zápis nedovolí. Nastavení ACL
/// patří do instalátoru služby (fáze 6). **Je to vědomá mezera.**
pub fn omez_prava(cesta: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(cesta)
            .map_err(|e| AdError::internal(format!("{}: {e}", cesta.display())))?;
        let mut p = meta.permissions();
        p.set_mode(if meta.is_dir() { 0o700 } else { 0o600 });
        std::fs::set_permissions(cesta, p)
            .map_err(|e| AdError::internal(format!("{}: {e}", cesta.display())))?;
    }
    #[cfg(not(unix))]
    {
        let _ = cesta;
    }
    Ok(())
}

pub fn zapis_tajne(cesta: &Path, obsah: &str) -> Result<()> {
    std::fs::write(cesta, obsah)
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesta.display())))?;
    omez_prava(cesta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docasny() -> Cesty {
        let dir = std::env::temp_dir().join(format!(
            "ad-client-test-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..10]
        ));
        Cesty::nove(Some(dir))
    }

    fn vzor() -> StavPripojeni {
        StavPripojeni {
            server_host: "dc01.skola.internal".into(),
            server_port: 8443,
            ca_fingerprint: "AB".repeat(32),
            machine_id: ad_core::ids::novy_guid().to_string(),
            machine_secret: "tajemstvi".into(),
            computer_name: "PC-01".into(),
            domain_dns_name: "skola.internal".into(),
            domain_short_name: "SKOLA".into(),
            dc_fqdn: "dc01.skola.internal".into(),
            dns_servers: vec!["192.168.56.10".into()],
            policy_poll_seconds: 900,
            joined_at: nyni_text(),
        }
    }

    #[test]
    fn stav_tam_a_zpet() {
        let c = docasny();
        assert!(StavPripojeni::nacti(&c).unwrap().is_none());
        assert!(StavPripojeni::vyzaduj(&c).is_err());

        let s = vzor();
        s.uloz(&c).unwrap();
        let zpet = StavPripojeni::nacti(&c).unwrap().unwrap();
        assert_eq!(zpet.computer_name, "PC-01");
        assert_eq!(zpet.machine_secret, "tajemstvi");
        std::fs::remove_dir_all(&c.data_dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn soubor_se_stavem_je_jen_pro_vlastnika() {
        use std::os::unix::fs::PermissionsExt;
        let c = docasny();
        vzor().uloz(&c).unwrap();
        let prava = std::fs::metadata(c.stav()).unwrap().permissions().mode() & 0o777;
        assert_eq!(prava, 0o600, "soubor s tajemstvím musí být jen pro vlastníka");
        let prava_adresare = std::fs::metadata(&c.data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(prava_adresare, 0o700);
        std::fs::remove_dir_all(&c.data_dir).ok();
    }

    #[test]
    fn poskozeny_soubor_je_srozumitelna_chyba() {
        let c = docasny();
        c.priprav().unwrap();
        std::fs::write(c.stav(), "{tohle neni json").unwrap();
        let e = StavPripojeni::nacti(&c).unwrap_err();
        assert!(e.message.contains("poškozený"), "{}", e.message);
        std::fs::remove_dir_all(&c.data_dir).ok();
    }

    #[test]
    fn zasady_se_ulozi_a_nactou() {
        let c = docasny();
        let z = UlozeneZasady {
            policy: ad_core::policy::EffectivePolicy::default(),
            serial: 7,
            fetched_at: nyni_text(),
            applied_at: None,
        };
        z.uloz(&c).unwrap();
        let zpet = UlozeneZasady::nacti(&c).unwrap().unwrap();
        assert_eq!(zpet.serial, 7);
        std::fs::remove_dir_all(&c.data_dir).ok();
    }
}
