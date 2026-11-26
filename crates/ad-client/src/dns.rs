//! Nastavení DNS na klientovi — záloha, přepnutí na náš server a návrat.
//!
//! Tohle je jediné místo, kde klient zasahuje do systému. Proto platí:
//!
//! 1. **Nejdřív záloha, pak změna.** Když se záloha nepovede, nic se
//!    nemění.
//! 2. Záloha je čitelný JSON. Kdyby klient přestal fungovat, správce
//!    si původní stav přečte a vrátí ho ručně.
//! 3. `leave` vrátí přesně to, co bylo — včetně toho, jestli byl
//!    `/etc/resolv.conf` symbolický odkaz a kam mířil.

use crate::stav::Cesty;
use ad_core::{AdError, Result};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
const RESOLV: &str = "/etc/resolv.conf";

/// Cesta k souboru s nastavením DNS.
///
/// Dá se přesměrovat proměnnou `AD_CLIENT_RESOLV_CONF`. Slouží to
/// k testování: test si tak ověří zálohu i návrat, aniž by přepsal
/// nastavení celého stroje. V běžném provozu se proměnná nenastavuje.
#[cfg(unix)]
fn resolv_cesta() -> std::path::PathBuf {
    std::env::var_os("AD_CLIENT_RESOLV_CONF")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(RESOLV))
}

/// Zazálohovaný stav nastavení DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zaloha {
    pub platforma: String,
    pub zalohovano: String,
    /// Linux: obsah `/etc/resolv.conf`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolv: Option<ZalohaResolv>,
    /// Windows: nastavení jednotlivých síťových rozhraní.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rozhrani: Vec<ZalohaRozhrani>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZalohaResolv {
    /// Byl to symbolický odkaz? (systemd-resolved to tak dělá.)
    pub byl_symlink: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cil_symlinku: Option<String>,
    /// Původní obsah souboru.
    pub obsah: String,
    /// Existoval soubor vůbec?
    pub existoval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZalohaRozhrani {
    pub jmeno: String,
    pub adresy: Vec<String>,
    /// Adresy se braly z DHCP (tedy žádné ruční nastavení).
    pub z_dhcp: bool,
}

impl Zaloha {
    pub fn nacti(cesty: &Cesty) -> Result<Option<Self>> {
        match std::fs::read_to_string(cesty.dns_zaloha()) {
            Ok(t) => serde_json::from_str(&t)
                .map(Some)
                .map_err(|e| AdError::internal(format!("záloha DNS je poškozená: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AdError::internal(format!("záloha DNS: {e}"))),
        }
    }

    pub fn uloz(&self, cesty: &Cesty) -> Result<()> {
        cesty.priprav()?;
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| AdError::internal(format!("záloha DNS: {e}")))?;
        std::fs::write(cesty.dns_zaloha(), text)
            .map_err(|e| AdError::internal(format!("nelze zapsat zálohu DNS: {e}")))
    }

    /// Krátký popis pro výpis uživateli.
    pub fn popis(&self) -> String {
        if let Some(r) = &self.resolv {
            if !r.existoval {
                return "soubor /etc/resolv.conf neexistoval".to_string();
            }
            let servery = nameservery(&r.obsah);
            let odkaz = if r.byl_symlink {
                format!(" (odkaz na {})", r.cil_symlinku.clone().unwrap_or_default())
            } else {
                String::new()
            };
            if servery.is_empty() {
                format!("/etc/resolv.conf bez nameserveru{odkaz}")
            } else {
                format!("{}{odkaz}", servery.join(", "))
            }
        } else if !self.rozhrani.is_empty() {
            self.rozhrani
                .iter()
                .map(|r| {
                    if r.z_dhcp {
                        format!("{}: z DHCP", r.jmeno)
                    } else {
                        format!("{}: {}", r.jmeno, r.adresy.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            "nic nezálohováno".to_string()
        }
    }
}

/// Vytáhne adresy nameserverů z obsahu resolv.conf.
pub fn nameservery(obsah: &str) -> Vec<String> {
    obsah
        .lines()
        .filter_map(|r| r.trim().strip_prefix("nameserver").map(|z| z.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Jaké DNS servery systém používá teď.
pub fn aktualni() -> Vec<String> {
    #[cfg(unix)]
    {
        std::fs::read_to_string(resolv_cesta()).map(|t| nameservery(&t)).unwrap_or_default()
    }
    #[cfg(windows)]
    {
        windows_adresy().unwrap_or_default().into_iter().flat_map(|r| r.adresy).collect()
    }
}

// =======================================================================
// Linux a jiné unixy
// =======================================================================

#[cfg(unix)]
pub fn zalohuj() -> Result<Zaloha> {
    zalohuj_z(&resolv_cesta())
}

#[cfg(unix)]
fn zalohuj_z(cesta: &std::path::Path) -> Result<Zaloha> {
    let metadata = std::fs::symlink_metadata(cesta);

    let (existoval, byl_symlink, cil) = match &metadata {
        Ok(m) => {
            let symlink = m.file_type().is_symlink();
            let cil = if symlink {
                std::fs::read_link(cesta).ok().map(|p| p.to_string_lossy().to_string())
            } else {
                None
            };
            (true, symlink, cil)
        }
        Err(_) => (false, false, None),
    };
    let obsah = std::fs::read_to_string(cesta).unwrap_or_default();

    Ok(Zaloha {
        platforma: "unix".to_string(),
        zalohovano: crate::stav::nyni_text(),
        resolv: Some(ZalohaResolv { byl_symlink, cil_symlinku: cil, obsah, existoval }),
        rozhrani: Vec::new(),
    })
}

#[cfg(unix)]
pub fn nastav(servery: &[String], domena: &str) -> Result<()> {
    nastav_v(&resolv_cesta(), servery, domena)
}

#[cfg(unix)]
fn nastav_v(cesta: &std::path::Path, servery: &[String], domena: &str) -> Result<()> {
    let mut obsah = String::from(
        "# Nastaveno programem ad-client při připojení do domény.\n\
         # Původní soubor je zazálohovaný v dns-backup.json a vrátí ho\n\
         # příkaz: ad-client leave\n",
    );
    if !domena.is_empty() {
        obsah.push_str(&format!("search {domena}\n"));
    }
    for s in servery {
        obsah.push_str(&format!("nameserver {s}\n"));
    }

    // Když je resolv.conf symbolický odkaz (systemd-resolved), musíme
    // ho nejdřív odstranit — jinak bychom přepsali cíl odkazu.
    if std::fs::symlink_metadata(cesta).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        std::fs::remove_file(cesta).map_err(|e| {
            AdError::internal(format!(
                "{} je symbolický odkaz a nejde odstranit: {e}. Spusť příkaz jako správce.",
                cesta.display()
            ))
        })?;
    }
    std::fs::write(cesta, obsah).map_err(|e| {
        AdError::internal(format!(
            "do {} nelze zapsat: {e}. Spusť příkaz jako správce (sudo).",
            cesta.display()
        ))
    })?;
    Ok(())
}

#[cfg(unix)]
pub fn obnov(zaloha: &Zaloha) -> Result<()> {
    obnov_do(&resolv_cesta(), zaloha)
}

#[cfg(unix)]
fn obnov_do(cesta: &std::path::Path, zaloha: &Zaloha) -> Result<()> {
    let Some(r) = &zaloha.resolv else {
        return Err(AdError::internal("záloha neobsahuje nastavení pro tenhle systém"));
    };
    let _ = std::fs::remove_file(cesta);

    if !r.existoval {
        // Soubor předtím nebyl — necháme to tak.
        return Ok(());
    }
    if r.byl_symlink {
        if let Some(cil) = &r.cil_symlinku {
            std::os::unix::fs::symlink(cil, cesta).map_err(|e| {
                AdError::internal(format!("nelze obnovit odkaz {} -> {cil}: {e}", cesta.display()))
            })?;
            return Ok(());
        }
    }
    std::fs::write(cesta, &r.obsah)
        .map_err(|e| AdError::internal(format!("nelze obnovit {}: {e}", cesta.display())))?;
    Ok(())
}

// =======================================================================
// Windows
// =======================================================================
//
// Používáme PowerShell, abychom kvůli třem příkazům netahali celou
// knihovnu na Windows API. Je to vidět v logu a dá se to zopakovat
// ručně, což je při ladění k nezaplacení.
//
// POZOR: tahle část je napsaná podle dokumentace, ale v tomhle
// prostředí ji nemám jak vyzkoušet. Otestuj ji ve virtuálce
// s Windows — je to první věc, co by mohla selhat.

#[cfg(windows)]
fn powershell(prikaz: &str) -> Result<String> {
    let vystup = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", prikaz])
        .output()
        .map_err(|e| AdError::internal(format!("nelze spustit powershell: {e}")))?;
    if !vystup.status.success() {
        return Err(AdError::internal(format!(
            "powershell skončil chybou: {}",
            String::from_utf8_lossy(&vystup.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&vystup.stdout).to_string())
}

#[cfg(windows)]
fn windows_adresy() -> Result<Vec<ZalohaRozhrani>> {
    // Vypíšeme jen rozhraní, která jsou nahoře a mají IPv4.
    let json = powershell(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | \
         Where-Object {$_.InterfaceAlias -notlike 'Loopback*'} | \
         Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress",
    )?;
    let hodnota: serde_json::Value =
        serde_json::from_str(json.trim()).unwrap_or(serde_json::Value::Null);
    let pole = match hodnota {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(_) => vec![hodnota],
        _ => Vec::new(),
    };
    Ok(pole
        .into_iter()
        .filter_map(|v| {
            let jmeno = v.get("InterfaceAlias")?.as_str()?.to_string();
            let adresy: Vec<String> = v
                .get("ServerAddresses")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            Some(ZalohaRozhrani { z_dhcp: adresy.is_empty(), jmeno, adresy })
        })
        .collect())
}

#[cfg(windows)]
pub fn zalohuj() -> Result<Zaloha> {
    Ok(Zaloha {
        platforma: "windows".to_string(),
        zalohovano: crate::stav::nyni_text(),
        resolv: None,
        rozhrani: windows_adresy()?,
    })
}

#[cfg(windows)]
pub fn nastav(servery: &[String], _domena: &str) -> Result<()> {
    if servery.is_empty() {
        return Err(AdError::bad_request("není co nastavit, seznam DNS serverů je prázdný"));
    }
    let seznam =
        servery.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(",");
    for rozhrani in windows_adresy()? {
        let jmeno = rozhrani.jmeno.replace('\'', "");
        powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{jmeno}' -ServerAddresses {seznam}"
        ))?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn obnov(zaloha: &Zaloha) -> Result<()> {
    for r in &zaloha.rozhrani {
        let jmeno = r.jmeno.replace('\'', "");
        if r.z_dhcp {
            powershell(&format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{jmeno}' -ResetServerAddresses"
            ))?;
        } else {
            let seznam = r
                .adresy
                .iter()
                .map(|s| format!("'{}'", s.replace('\'', "")))
                .collect::<Vec<_>>()
                .join(",");
            powershell(&format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{jmeno}' -ServerAddresses {seznam}"
            ))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameservery_z_resolv_conf() {
        let obsah = "# komentar\nsearch skola.internal\nnameserver 192.168.56.10\n\
                     nameserver  1.1.1.1  \noptions ndots:1\n";
        assert_eq!(nameservery(obsah), vec!["192.168.56.10", "1.1.1.1"]);
        assert!(nameservery("").is_empty());
        assert!(nameservery("# nic").is_empty());
    }

    #[test]
    fn popis_zalohy() {
        let z = Zaloha {
            platforma: "unix".into(),
            zalohovano: "2026-11-26T10:00:00Z".into(),
            resolv: Some(ZalohaResolv {
                byl_symlink: true,
                cil_symlinku: Some("../run/systemd/resolve/stub-resolv.conf".into()),
                obsah: "nameserver 127.0.0.53\n".into(),
                existoval: true,
            }),
            rozhrani: vec![],
        };
        let p = z.popis();
        assert!(p.contains("127.0.0.53"));
        assert!(p.contains("odkaz na"));
    }

    #[test]
    fn popis_chybejiciho_souboru() {
        let z = Zaloha {
            platforma: "unix".into(),
            zalohovano: "x".into(),
            resolv: Some(ZalohaResolv {
                byl_symlink: false,
                cil_symlinku: None,
                obsah: String::new(),
                existoval: false,
            }),
            rozhrani: vec![],
        };
        assert!(z.popis().contains("neexistoval"));
    }

    #[cfg(unix)]
    #[test]
    fn zaloha_a_navrat_vrati_puvodni_soubor() {
        // Pracujeme nad vlastním souborem, ne nad /etc/resolv.conf —
        // test nesmí sahat na nastavení stroje, na kterém běží.
        let dir = std::env::temp_dir().join(format!(
            "ad-dns-navrat-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..8]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        let puvodni = "nameserver 1.1.1.1\nsearch puvodni\n";
        std::fs::write(&resolv, puvodni).unwrap();

        let zaloha = zalohuj_z(&resolv).unwrap();
        assert!(zaloha.popis().contains("1.1.1.1"));

        nastav_v(&resolv, &["192.168.56.10".to_string()], "skola.internal").unwrap();
        let novy = std::fs::read_to_string(&resolv).unwrap();
        assert_eq!(nameservery(&novy), vec!["192.168.56.10"]);
        assert!(novy.contains("search skola.internal"));
        assert!(novy.contains("ad-client"), "v souboru má být poznámka, kdo ho zapsal");

        obnov_do(&resolv, &zaloha).unwrap();
        assert_eq!(std::fs::read_to_string(&resolv).unwrap(), puvodni);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn navrat_obnovi_i_symbolicky_odkaz() {
        let dir = std::env::temp_dir().join(format!(
            "ad-dns-symlink-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..8]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let skutecny = dir.join("skutecny.conf");
        std::fs::write(&skutecny, "nameserver 127.0.0.53\n").unwrap();
        let resolv = dir.join("resolv.conf");
        std::os::unix::fs::symlink(&skutecny, &resolv).unwrap();

        let zaloha = zalohuj_z(&resolv).unwrap();
        assert!(zaloha.resolv.as_ref().unwrap().byl_symlink);

        nastav_v(&resolv, &["192.168.56.10".to_string()], "skola.internal").unwrap();
        // Cíl odkazu se nesmí přepsat — odkaz se odstraní a vytvoří
        // obyčejný soubor.
        assert_eq!(std::fs::read_to_string(&skutecny).unwrap(), "nameserver 127.0.0.53\n");
        assert!(!std::fs::symlink_metadata(&resolv).unwrap().file_type().is_symlink());

        obnov_do(&resolv, &zaloha).unwrap();
        assert!(
            std::fs::symlink_metadata(&resolv).unwrap().file_type().is_symlink(),
            "po návratu tu má zase být symbolický odkaz"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn zaloha_se_da_ulozit_a_nacist() {
        let dir = std::env::temp_dir().join(format!(
            "ad-dns-zaloha-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..8]
        ));
        let cesty = Cesty::nove(Some(dir.clone()));
        assert!(Zaloha::nacti(&cesty).unwrap().is_none());

        let z = zalohuj().unwrap();
        z.uloz(&cesty).unwrap();
        let zpet = Zaloha::nacti(&cesty).unwrap().unwrap();
        assert_eq!(zpet.platforma, "unix");
        assert!(zpet.resolv.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }
}
