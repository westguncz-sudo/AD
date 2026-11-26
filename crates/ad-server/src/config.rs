//! Konfigurace serveru a cesty k datům.
//!
//! Konfigurace je TOML. Když soubor neexistuje, použijí se výchozí
//! hodnoty a soubor se při prvním startu vypíše — ať je vidět, co se
//! dá nastavit.

use ad_core::proto;
use ad_core::{AdError, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Celá konfigurace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub domain_api: DomainApiConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Kde leží databáze, certifikáty a soubory. `None` = podle systému.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Kde poslouchá webová správa.
    pub bind: SocketAddr,
    /// Použít HTTPS. Mimo loopback je to **povinné**.
    pub tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainApiConfig {
    /// Kde poslouchá doménové API pro klienty. Vždy TLS.
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub bind: SocketAddr,
    /// Spustit vlastní DNS server.
    pub enabled: bool,
    /// Přeposílat dotazy mimo naše zóny jen klientům z vnitřní sítě.
    ///
    /// Vypnout to znamená udělat z serveru otevřený přeposílač. Ten se
    /// dá z internetu zneužít k zesílení útoku: útočník pošle malý
    /// dotaz s podvrženou adresou oběti a velká odpověď letí na ni.
    /// Nechávej zapnuté.
    pub forward_only_local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// `error`, `warn`, `info`, `debug`, `trace`
    pub level: String,
    /// Psát i do souboru v datovém adresáři.
    pub to_file: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self { bind: SocketAddr::from(([127, 0, 0, 1], proto::PORT_SPRAVA)), tls: false }
    }
}

impl Default for DomainApiConfig {
    fn default() -> Self {
        Self { bind: SocketAddr::from(([0, 0, 0, 0], proto::PORT_TLS)) }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], proto::PORT_DNS)),
            enabled: true,
            forward_only_local: true,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { level: "info".to_string(), to_file: true }
    }
}

impl Config {
    /// Načte konfiguraci ze souboru. Když soubor není, vrátí výchozí.
    pub fn nacti(cesta: &Path) -> Result<Self> {
        match std::fs::read_to_string(cesta) {
            Ok(text) => {
                let c: Config = toml::from_str(&text).map_err(|e| {
                    AdError::bad_request(format!("konfigurace {}: {e}", cesta.display()))
                })?;
                c.validuj()?;
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(AdError::internal(format!(
                "konfiguraci {} nelze přečíst: {e}",
                cesta.display()
            ))),
        }
    }

    /// Pojistka: správa bez TLS smí poslouchat jen na loopbacku.
    ///
    /// Na `127.0.0.1` provoz nikdy neopustí počítač. Na `0.0.0.0` by
    /// heslo správce letělo sítí v čistém textu, a to nedovolíme ani
    /// na vyžádání.
    pub fn validuj(&self) -> Result<()> {
        if !self.admin.tls && !self.admin.bind.ip().is_loopback() {
            return Err(AdError::bad_request(format!(
                "[admin] bind = \"{}\" není loopback, takže tls musí být true \
                 (jinak by heslo správce šlo sítí nezašifrované)",
                self.admin.bind
            )));
        }
        if !["error", "warn", "info", "debug", "trace"].contains(&self.log.level.as_str()) {
            return Err(AdError::bad_request(format!(
                "[log] level = \"{}\" není známá úroveň",
                self.log.level
            )));
        }
        Ok(())
    }

    pub fn jako_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_else(|e| format!("# chyba serializace: {e}\n"))
    }
}

/// Všechny cesty, které server používá. Nic se nezapisuje jinam —
/// odinstalace je pak smazání těchto adresářů.
#[derive(Debug, Clone)]
pub struct Cesty {
    pub data_dir: PathBuf,
    pub config: PathBuf,
}

impl Cesty {
    /// Výchozí cesty podle systému, případně přepsané.
    pub fn nove(data_dir: Option<PathBuf>, config: Option<PathBuf>) -> Self {
        let data = data_dir
            .or_else(|| std::env::var_os("AD_SERVER_DATA_DIR").map(PathBuf::from))
            .unwrap_or_else(Self::vychozi_data_dir);
        let cfg = config.unwrap_or_else(|| Self::vychozi_config(&data));
        Self { data_dir: data, config: cfg }
    }

    #[cfg(windows)]
    fn vychozi_data_dir() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("ad-server")
    }

    #[cfg(not(windows))]
    fn vychozi_data_dir() -> PathBuf {
        PathBuf::from("/var/lib/ad-server")
    }

    #[cfg(windows)]
    fn vychozi_config(data: &Path) -> PathBuf {
        data.join("config.toml")
    }

    #[cfg(not(windows))]
    fn vychozi_config(_data: &Path) -> PathBuf {
        PathBuf::from("/etc/ad-server/config.toml")
    }

    pub fn databaze(&self) -> PathBuf {
        self.data_dir.join("domain.db")
    }

    pub fn pki(&self) -> PathBuf {
        self.data_dir.join("pki")
    }

    pub fn assets(&self) -> PathBuf {
        self.data_dir.join("assets")
    }

    pub fn log(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    pub fn setup_token(&self) -> PathBuf {
        self.data_dir.join("setup-token.txt")
    }

    /// Vytvoří adresáře, které chybí.
    pub fn priprav(&self) -> Result<()> {
        for d in [&self.data_dir, &self.pki(), &self.assets(), &self.log()] {
            std::fs::create_dir_all(d)
                .map_err(|e| AdError::internal(format!("nelze vytvořit {}: {e}", d.display())))?;
        }
        omez_prava(&self.pki())?;
        Ok(())
    }
}

/// Nastaví na souboru nebo adresáři práva jen pro vlastníka.
///
/// Na Windows to zatím neděláme programově — `C:\ProgramData\ad-server`
/// dědí ACL, které běžnému uživateli zápis nedovolí, a nastavení ACL
/// pro službu patří do fáze 6 (instalátor služby). **Je to vědomá
/// mezera, ne omyl.**
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

/// Zapíše soubor s tajemstvím: nejdřív práva, pak obsah.
pub fn zapis_tajny_soubor(cesta: &Path, obsah: &str) -> Result<()> {
    std::fs::write(cesta, obsah)
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesta.display())))?;
    omez_prava(cesta)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vychozi_konfigurace_je_platna() {
        Config::default().validuj().unwrap();
    }

    #[test]
    fn sprava_mimo_loopback_bez_tls_je_chyba() {
        let mut c = Config::default();
        c.admin.bind = "0.0.0.0:8080".parse().unwrap();
        c.admin.tls = false;
        let e = c.validuj().unwrap_err();
        assert!(e.message.contains("nezašifrované"), "{}", e.message);

        // S TLS je to v pořádku.
        c.admin.tls = true;
        c.validuj().unwrap();
    }

    #[test]
    fn loopback_bez_tls_je_v_poradku() {
        let mut c = Config::default();
        c.admin.tls = false;
        c.admin.bind = "127.0.0.1:9999".parse().unwrap();
        c.validuj().unwrap();
    }

    #[test]
    fn toml_tam_a_zpet() {
        let c = Config::default();
        let t = c.jako_toml();
        let zpet: Config = toml::from_str(&t).unwrap();
        assert_eq!(c, zpet);
    }

    #[test]
    fn neznama_polozka_v_konfiguraci_se_odmitne() {
        let t = "[admin]\nbind = \"127.0.0.1:8080\"\ntls = false\nneco = 1\n";
        assert!(toml::from_str::<Config>(t).is_err());
    }

    #[test]
    fn spatna_uroven_logu() {
        let mut c = Config::default();
        c.log.level = "vsechno".into();
        assert!(c.validuj().is_err());
    }

    #[test]
    fn cesty_se_skladaji_pod_data_dir() {
        let c = Cesty::nove(Some(PathBuf::from("/tmp/ad-test")), None);
        assert_eq!(c.databaze(), PathBuf::from("/tmp/ad-test/domain.db"));
        assert_eq!(c.pki(), PathBuf::from("/tmp/ad-test/pki"));
        assert!(c.setup_token().ends_with("setup-token.txt"));
    }
}
