//! Běh jako systémová služba.
//!
//! Tři systémy, tři způsoby, jedna zásada: **nic se nenainstaluje bez
//! výslovného souhlasu a všechno jde odinstalovat.** Příkaz nejdřív
//! vypíše, co přesně udělá, a bez `--yes` skončí.
//!
//! | Systém | Jak | Kde |
//! |---|---|---|
//! | Debian a jiné se systemd | jednotka systemd | `/etc/systemd/system/ad-server.service` |
//! | Void Linux | runit | `/etc/sv/ad-server/` |
//! | Windows | Windows Service | SCM, jméno `ADServer` |
//!
//! Na Linuxu server neběží pod rootem. Port 53 je pod 1024, takže by
//! na něj běžný uživatel nedosáhl — řeší to schopnost
//! `CAP_NET_BIND_SERVICE`, ne spouštění pod rootem.

use crate::config::{Cesty, Config};
use ad_core::{AdError, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Jméno služby ve všech systémech.
pub const JMENO: &str = "ad-server";
/// Jméno služby na Windows (SCM nemá rád pomlčky v zobrazovaném jméně).
pub const JMENO_WINDOWS: &str = "ADServer";
/// Výchozí systémový uživatel, pod kterým služba běží na Linuxu.
pub const VYCHOZI_UZIVATEL: &str = "ad-server";

/// Co se má udělat.
#[derive(Debug, Clone)]
pub struct Volby {
    /// Uživatel, pod kterým služba poběží (jen Linux).
    pub uzivatel: String,
    /// Cesta k binárce. `None` = zjistí se sama.
    pub binarka: Option<PathBuf>,
    /// Bez tohohle se nic neprovede.
    pub potvrzeno: bool,
    /// Smazat při odinstalaci i data domény.
    pub smazat_data: bool,
}

impl Default for Volby {
    fn default() -> Self {
        Self {
            uzivatel: VYCHOZI_UZIVATEL.to_string(),
            binarka: None,
            potvrzeno: false,
            smazat_data: false,
        }
    }
}

/// Který správce služeb na tomhle stroji je.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spravce {
    Systemd,
    Runit,
    Windows,
    Neznamy,
}

impl Spravce {
    pub fn jmeno(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Runit => "runit",
            Self::Windows => "Windows Service",
            Self::Neznamy => "neznámý",
        }
    }
}

/// Pozná správce služeb podle toho, co na stroji je.
pub fn poznej_spravce() -> Spravce {
    if cfg!(windows) {
        return Spravce::Windows;
    }
    // systemd se pozná podle běžícího adresáře, ne podle binárky —
    // ta může být nainstalovaná, i když systém běží na něčem jiném.
    if Path::new("/run/systemd/system").is_dir() {
        return Spravce::Systemd;
    }
    if Path::new("/etc/sv").is_dir() || Path::new("/etc/runit").is_dir() {
        return Spravce::Runit;
    }
    Spravce::Neznamy
}

/// Cesta k běžící binárce.
pub fn cesta_k_binarce(volby: &Volby) -> Result<PathBuf> {
    if let Some(c) = &volby.binarka {
        return Ok(c.clone());
    }
    let cesta = std::env::current_exe()
        .map_err(|e| AdError::internal(format!("nelze zjistit cestu k programu: {e}")))?;
    cesta
        .canonicalize()
        .or(Ok(cesta))
        .map_err(|e: std::io::Error| AdError::internal(format!("cesta k programu: {e}")))
}

/// Spustí příkaz a vrátí jeho výstup, nebo srozumitelnou chybu.
fn spust(program: &str, argumenty: &[&str]) -> Result<String> {
    let vystup = Command::new(program).args(argumenty).output().map_err(|e| {
        AdError::internal(format!("nelze spustit {program}: {e}. Je nainstalovaný?"))
    })?;
    if !vystup.status.success() {
        return Err(AdError::internal(format!(
            "{program} {} selhal: {}",
            argumenty.join(" "),
            String::from_utf8_lossy(&vystup.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&vystup.stdout).to_string())
}

#[cfg_attr(not(unix), allow(dead_code))]
fn existuje_prikaz(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

// =======================================================================
// Instalace
// =======================================================================

/// Nainstaluje službu. Bez `volby.potvrzeno` jen vypíše, co by udělala.
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn nainstaluj(cesty: &Cesty, konfigurace: &Config, volby: &Volby) -> Result<()> {
    let spravce = poznej_spravce();
    let binarka = cesta_k_binarce(volby)?;

    println!("Instalace služby {JMENO}");
    println!("  správce služeb: {}", spravce.jmeno());
    println!("  program:        {}", binarka.display());
    println!("  data:           {}", cesty.data_dir.display());
    println!("  konfigurace:    {}", cesty.config.display());
    if spravce != Spravce::Windows {
        println!("  uživatel:       {}", volby.uzivatel);
    }
    println!("\nCo se stane:");
    for krok in plan(spravce, cesty, &binarka, volby) {
        println!("  • {krok}");
    }

    if !volby.potvrzeno {
        println!(
            "\nNic jsem neudělal. Když s tím souhlasíš, spusť to znovu s --yes.\n\
             Odinstalovat se to dá příkazem: {JMENO} uninstall-service --yes"
        );
        return Ok(());
    }
    println!();

    match spravce {
        #[cfg(unix)]
        Spravce::Systemd => nainstaluj_systemd(cesty, konfigurace, &binarka, volby),
        #[cfg(unix)]
        Spravce::Runit => nainstaluj_runit(cesty, konfigurace, &binarka, volby),
        Spravce::Windows => nainstaluj_windows(cesty, konfigurace, &binarka),
        _ => Err(AdError::bad_request(
            "nepoznal jsem správce služeb. Na Linuxu čekám systemd (/run/systemd/system) \
             nebo runit (/etc/sv). Server se dá spustit i ručně: ad-server run",
        )),
    }
}

fn plan(spravce: Spravce, cesty: &Cesty, binarka: &Path, volby: &Volby) -> Vec<String> {
    let mut kroky = Vec::new();
    match spravce {
        Spravce::Systemd => {
            kroky.push(format!("vytvoří se systémový uživatel {} (pokud není)", volby.uzivatel));
            kroky.push(format!("vznikne {}", cesta_systemd().display()));
            kroky.push(format!(
                "adresáře {} a {} dostanou vlastníka {}",
                cesty.data_dir.display(),
                cesty.log().display(),
                volby.uzivatel
            ));
            kroky.push("služba se zapne a spustí (systemctl enable --now)".to_string());
            kroky.push(
                "služba dostane jen schopnost CAP_NET_BIND_SERVICE kvůli portu 53, \
                 ne práva roota"
                    .to_string(),
            );
        }
        Spravce::Runit => {
            kroky.push(format!("vytvoří se systémový uživatel {} (pokud není)", volby.uzivatel));
            kroky.push(format!(
                "vznikne {}/run a {}/log/run",
                adresar_runit().display(),
                adresar_runit().display()
            ));
            kroky.push(format!(
                "binárka {} dostane schopnost CAP_NET_BIND_SERVICE (setcap)",
                binarka.display()
            ));
            kroky.push(format!("služba se zapne odkazem v {}", adresar_sluzeb_runit().display()));
        }
        Spravce::Windows => {
            kroky.push(format!("zaregistruje se služba {JMENO_WINDOWS} se spuštěním při startu"));
            kroky.push(format!("vznikne adresář {}", cesty.data_dir.display()));
            kroky.push(format!("vznikne konfigurace {}", cesty.config.display()));
            kroky.push("služba poběží pod účtem LocalSystem".to_string());
        }
        Spravce::Neznamy => kroky.push("nic — správce služeb se nepodařilo poznat".to_string()),
    }
    kroky
}

// ----------------------------------------------------------- systemd

fn cesta_systemd() -> PathBuf {
    PathBuf::from("/etc/systemd/system/ad-server.service")
}

#[cfg(unix)]
fn nainstaluj_systemd(
    cesty: &Cesty,
    konfigurace: &Config,
    binarka: &Path,
    volby: &Volby,
) -> Result<()> {
    zalozi_uzivatele(&volby.uzivatel)?;
    priprav_adresare(cesty, &volby.uzivatel)?;
    uloz_konfiguraci(cesty, konfigurace)?;

    let jednotka = jednotka_systemd(cesty, binarka, &volby.uzivatel);
    std::fs::write(cesta_systemd(), &jednotka).map_err(|e| {
        AdError::internal(format!(
            "nelze zapsat {}: {e}. Spusť příkaz jako root.",
            cesta_systemd().display()
        ))
    })?;
    println!("  ✓ {}", cesta_systemd().display());

    spust("systemctl", &["daemon-reload"])?;
    spust("systemctl", &["enable", "--now", "ad-server.service"])?;
    println!("  ✓ služba zapnutá a spuštěná");
    println!(
        "\nStav:    systemctl status {JMENO}\n\
         Log:     journalctl -u {JMENO} -f\n\
         Vypnout: systemctl disable --now {JMENO}"
    );
    Ok(())
}

/// Text jednotky systemd.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn jednotka_systemd(cesty: &Cesty, binarka: &Path, uzivatel: &str) -> String {
    format!(
        "# Vygeneroval ad-server install-service.\n\
         # Odebrat: ad-server uninstall-service --yes\n\
         [Unit]\n\
         Description=ad-server — řadič domény\n\
         Documentation=https://github.com/westguncz-sudo/AD\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} --data-dir {data} --config {config} run\n\
         User={uzivatel}\n\
         Group={uzivatel}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         # Port 53 je pod 1024. Místo spouštění pod rootem dáme službě\n\
         # jen tuhle jedinou schopnost.\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         NoNewPrivileges=true\n\
         \n\
         # Ze systému smí služba zapisovat jen do svých adresářů.\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         PrivateTmp=true\n\
         PrivateDevices=true\n\
         ProtectKernelTunables=true\n\
         ProtectKernelModules=true\n\
         ProtectControlGroups=true\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
         RestrictNamespaces=true\n\
         LockPersonality=true\n\
         MemoryDenyWriteExecute=true\n\
         ReadWritePaths={data} {log}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = binarka.display(),
        data = cesty.data_dir.display(),
        config = cesty.config.display(),
        log = cesty.log().display(),
        uzivatel = uzivatel,
    )
}

// ------------------------------------------------------------- runit

fn adresar_runit() -> PathBuf {
    PathBuf::from("/etc/sv/ad-server")
}

/// Kam se dává odkaz, aby služba běžela. Void používá /var/service.
fn adresar_sluzeb_runit() -> PathBuf {
    for kandidat in ["/var/service", "/run/runit/service", "/etc/service"] {
        if Path::new(kandidat).is_dir() {
            return PathBuf::from(kandidat);
        }
    }
    PathBuf::from("/var/service")
}

#[cfg(unix)]
fn nainstaluj_runit(
    cesty: &Cesty,
    konfigurace: &Config,
    binarka: &Path,
    volby: &Volby,
) -> Result<()> {
    zalozi_uzivatele(&volby.uzivatel)?;
    priprav_adresare(cesty, &volby.uzivatel)?;
    uloz_konfiguraci(cesty, konfigurace)?;

    let dir = adresar_runit();
    std::fs::create_dir_all(dir.join("log"))
        .map_err(|e| AdError::internal(format!("nelze vytvořit {}: {e}", dir.display())))?;

    zapis_spustitelny(&dir.join("run"), &skript_runit(cesty, binarka, &volby.uzivatel))?;
    zapis_spustitelny(&dir.join("log/run"), &skript_runit_log(cesty))?;
    println!("  ✓ {}/run a {}/log/run", dir.display(), dir.display());

    // runit službu spouští pod jiným uživatelem, takže port 53 musí
    // povolit schopnost na binárce.
    if existuje_prikaz("setcap") {
        match spust("setcap", &["cap_net_bind_service=+ep", &binarka.to_string_lossy()]) {
            Ok(_) => println!("  ✓ binárka smí poslouchat na portu 53 (setcap)"),
            Err(e) => println!("  ! setcap selhal: {} — DNS na portu 53 nepoběží", e.message),
        }
    } else {
        println!(
            "  ! setcap tu není (balíček libcap). Bez něj nepůjde port 53.\n    \
             Nainstaluj ho a spusť: setcap cap_net_bind_service=+ep {}",
            binarka.display()
        );
    }

    let odkaz = adresar_sluzeb_runit().join(JMENO);
    if !odkaz.exists() {
        std::os::unix::fs::symlink(&dir, &odkaz).map_err(|e| {
            AdError::internal(format!("nelze vytvořit odkaz {}: {e}", odkaz.display()))
        })?;
    }
    println!("  ✓ služba zapnutá ({})", odkaz.display());
    println!(
        "\nStav:    sv status {JMENO}\n\
         Log:     tail -f {}/current\n\
         Vypnout: rm {}",
        cesty.log().display(),
        odkaz.display()
    );
    Ok(())
}

/// Skript `run` pro runit.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn skript_runit(cesty: &Cesty, binarka: &Path, uzivatel: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Vygeneroval ad-server install-service.\n\
         # Odebrat: ad-server uninstall-service --yes\n\
         exec 2>&1\n\
         exec chpst -u {uzivatel}:{uzivatel} {bin} --data-dir {data} --config {config} run\n",
        uzivatel = uzivatel,
        bin = binarka.display(),
        data = cesty.data_dir.display(),
        config = cesty.config.display(),
    )
}

/// Skript `log/run` pro runit — log jde přes svlogd.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn skript_runit_log(cesty: &Cesty) -> String {
    format!(
        "#!/bin/sh\n\
         exec chpst -u root:root svlogd -tt {}\n",
        cesty.log().display()
    )
}

#[cfg(unix)]
fn zapis_spustitelny(cesta: &Path, obsah: &str) -> Result<()> {
    std::fs::write(cesta, obsah)
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesta.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cesta, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| AdError::internal(format!("práva {}: {e}", cesta.display())))?;
    }
    Ok(())
}

// ------------------------------------------------------- společné pro Linux

#[cfg(unix)]
fn zalozi_uzivatele(jmeno: &str) -> Result<()> {
    let existuje = Command::new("id")
        .args(["-u", jmeno])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if existuje {
        println!("  • uživatel {jmeno} už existuje");
        return Ok(());
    }
    // useradd je na Debianu i na Void (balíček shadow).
    let vysledek =
        spust("useradd", &["--system", "--no-create-home", "--shell", "/sbin/nologin", jmeno]);
    match vysledek {
        Ok(_) => {
            println!("  ✓ vytvořen systémový uživatel {jmeno}");
            Ok(())
        }
        Err(e) => Err(AdError::internal(format!(
            "{}. Vytvoř ho ručně: useradd --system --no-create-home {jmeno}",
            e.message
        ))),
    }
}

/// Na Windows služba běží pod LocalSystem, žádný uživatel se nezakládá.
#[cfg(not(unix))]
#[allow(dead_code)]
fn zalozi_uzivatele(_jmeno: &str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn priprav_adresare(cesty: &Cesty, uzivatel: &str) -> Result<()> {
    cesty.priprav()?;
    if let Some(rodic) = cesty.config.parent() {
        std::fs::create_dir_all(rodic)
            .map_err(|e| AdError::internal(format!("nelze vytvořit {}: {e}", rodic.display())))?;
    }
    for d in [cesty.data_dir.clone(), cesty.log()] {
        let _ = spust("chown", &["-R", &format!("{uzivatel}:{uzivatel}"), &d.to_string_lossy()]);
    }
    println!("  ✓ adresáře patří uživateli {uzivatel}");
    Ok(())
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn priprav_adresare(cesty: &Cesty, _uzivatel: &str) -> Result<()> {
    cesty.priprav()
}

/// Zapíše konfiguraci, pokud ještě není — ať je co upravovat.
fn uloz_konfiguraci(cesty: &Cesty, konfigurace: &Config) -> Result<()> {
    if cesty.config.exists() {
        println!("  • konfigurace {} už existuje, nechávám ji", cesty.config.display());
        return Ok(());
    }
    if let Some(rodic) = cesty.config.parent() {
        let _ = std::fs::create_dir_all(rodic);
    }
    std::fs::write(&cesty.config, konfigurace.jako_toml())
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesty.config.display())))?;
    println!("  ✓ konfigurace {}", cesty.config.display());
    Ok(())
}

// ----------------------------------------------------------- Windows

/// Registrace služby na Windows.
///
/// **Tahle část se v Linuxu nedá vyzkoušet.** Je napsaná podle
/// dokumentace `windows-service`. Otestuj ji ve virtuálce s Windows —
/// je to nejpravděpodobnější místo, kde se něco nepovede.
#[cfg(windows)]
fn nainstaluj_windows(cesty: &Cesty, konfigurace: &Config, binarka: &Path) -> Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    cesty.priprav()?;
    uloz_konfiguraci(cesty, konfigurace)?;

    let spravce = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        AdError::internal(format!(
            "nelze se připojit ke správci služeb: {e}. \
             Spusť příkazový řádek jako správce."
        ))
    })?;

    let popis = ServiceInfo {
        name: OsString::from(JMENO_WINDOWS),
        display_name: OsString::from("ad-server — řadič domény"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binarka.to_path_buf(),
        launch_arguments: vec![
            OsString::from("--data-dir"),
            OsString::from(cesty.data_dir.as_os_str()),
            OsString::from("--config"),
            OsString::from(cesty.config.as_os_str()),
            OsString::from("service-run"),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let sluzba = spravce
        .create_service(&popis, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| AdError::internal(format!("nelze zaregistrovat službu: {e}")))?;
    sluzba
        .set_description("Vlastní zjednodušený řadič domény (školní projekt).")
        .map_err(|e| AdError::internal(format!("popis služby: {e}")))?;
    println!("  ✓ služba {JMENO_WINDOWS} zaregistrována");

    sluzba
        .start::<OsString>(&[])
        .map_err(|e| AdError::internal(format!("službu se nepodařilo spustit: {e}")))?;
    println!("  ✓ služba spuštěna");
    println!(
        "\nStav:    sc query {JMENO_WINDOWS}\n\
         Zastavit: sc stop {JMENO_WINDOWS}\n\
         Odebrat:  ad-server uninstall-service --yes"
    );
    Ok(())
}

#[cfg(not(windows))]
fn nainstaluj_windows(_cesty: &Cesty, _konfigurace: &Config, _binarka: &Path) -> Result<()> {
    Err(AdError::bad_request("Windows Service se dá nainstalovat jen na Windows"))
}

// =======================================================================
// Odinstalace
// =======================================================================

/// Odebere službu. S `smazat_data` smaže i data domény.
pub fn odinstaluj(cesty: &Cesty, volby: &Volby) -> Result<()> {
    let spravce = poznej_spravce();
    println!("Odinstalace služby {JMENO} ({})", spravce.jmeno());
    println!("\nCo se stane:");
    match spravce {
        Spravce::Systemd => {
            println!("  • služba se zastaví a vypne");
            println!("  • smaže se {}", cesta_systemd().display());
        }
        Spravce::Runit => {
            println!("  • smaže se odkaz v {}", adresar_sluzeb_runit().display());
            println!("  • smaže se {}", adresar_runit().display());
        }
        Spravce::Windows => println!("  • služba {JMENO_WINDOWS} se zastaví a odebere"),
        Spravce::Neznamy => println!("  • nic, správce služeb se nepodařilo poznat"),
    }
    if volby.smazat_data {
        println!(
            "  • SMAŽE SE {} včetně domény, uživatelů a certifikátů",
            cesty.data_dir.display()
        );
    } else {
        println!("  • data v {} zůstanou", cesty.data_dir.display());
    }
    println!(
        "  • systémový uživatel (pokud nějaký instalace vytvořila) zůstane — \
         smaž ho ručně: userdel JMÉNO"
    );

    if !volby.potvrzeno {
        println!("\nNic jsem neudělal. Spusť to znovu s --yes.");
        return Ok(());
    }
    println!();

    match spravce {
        #[cfg(unix)]
        Spravce::Systemd => {
            let _ = spust("systemctl", &["disable", "--now", "ad-server.service"]);
            if cesta_systemd().exists() {
                std::fs::remove_file(cesta_systemd()).map_err(|e| {
                    AdError::internal(format!("nelze smazat {}: {e}", cesta_systemd().display()))
                })?;
            }
            let _ = spust("systemctl", &["daemon-reload"]);
            println!("  ✓ služba odebrána");
        }
        #[cfg(unix)]
        Spravce::Runit => {
            let odkaz = adresar_sluzeb_runit().join(JMENO);
            if odkaz.exists() {
                let _ = spust("sv", &["down", JMENO]);
                let _ = std::fs::remove_file(&odkaz);
            }
            if adresar_runit().exists() {
                let _ = std::fs::remove_dir_all(adresar_runit());
            }
            println!("  ✓ služba odebrána");
        }
        Spravce::Windows => odinstaluj_windows()?,
        _ => {}
    }

    if volby.smazat_data && cesty.data_dir.exists() {
        std::fs::remove_dir_all(&cesty.data_dir).map_err(|e| {
            AdError::internal(format!("nelze smazat {}: {e}", cesty.data_dir.display()))
        })?;
        println!("  ✓ data smazána");
    }
    println!("\nHotovo.");
    Ok(())
}

#[cfg(windows)]
fn odinstaluj_windows() -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let spravce = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| AdError::internal(format!("správce služeb: {e}")))?;
    let sluzba = spravce
        .open_service(
            JMENO_WINDOWS,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| AdError::internal(format!("služba {JMENO_WINDOWS} nenalezena: {e}")))?;

    if sluzba.query_status().map(|s| s.current_state).unwrap_or(ServiceState::Stopped)
        != ServiceState::Stopped
    {
        let _ = sluzba.stop();
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    sluzba.delete().map_err(|e| AdError::internal(format!("nelze odebrat službu: {e}")))?;
    println!("  ✓ služba odebrána");
    Ok(())
}

#[cfg(not(windows))]
fn odinstaluj_windows() -> Result<()> {
    Err(AdError::bad_request("Windows Service se dá odebrat jen na Windows"))
}

// =======================================================================
// Stav
// =======================================================================

/// Vypíše, jestli je služba nainstalovaná a jak se na ni podívat.
pub fn vypis_stav(cesty: &Cesty) -> Result<()> {
    let spravce = poznej_spravce();
    println!("Správce služeb: {}", spravce.jmeno());
    match spravce {
        Spravce::Systemd => {
            let je = cesta_systemd().exists();
            println!(
                "Jednotka:       {} ({})",
                cesta_systemd().display(),
                if je { "existuje" } else { "není" }
            );
            if je {
                match spust("systemctl", &["is-active", "ad-server.service"]) {
                    Ok(s) => println!("Stav:           {}", s.trim()),
                    Err(_) => println!("Stav:           neběží"),
                }
                println!("\nPodrobnosti:  systemctl status {JMENO}");
                println!("Log:          journalctl -u {JMENO} -n 50");
            }
        }
        Spravce::Runit => {
            let je = adresar_runit().exists();
            println!(
                "Adresář:        {} ({})",
                adresar_runit().display(),
                if je { "existuje" } else { "není" }
            );
            if je {
                match spust("sv", &["status", JMENO]) {
                    Ok(s) => println!("Stav:           {}", s.trim()),
                    Err(e) => println!("Stav:           {}", e.message),
                }
                println!("\nLog:          tail -f {}/current", cesty.log().display());
            }
        }
        Spravce::Windows => {
            println!("Služba:         {JMENO_WINDOWS}");
            println!("\nPodrobnosti:  sc query {JMENO_WINDOWS}");
        }
        Spravce::Neznamy => {
            println!("Služba se tu nainstalovat nedá. Spusť server ručně: {JMENO} run");
        }
    }
    println!("\nData:           {}", cesty.data_dir.display());
    println!("Konfigurace:    {}", cesty.config.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cesty() -> Cesty {
        Cesty::nove(
            Some(PathBuf::from("/var/lib/ad-server")),
            Some(PathBuf::from("/etc/ad-server/config.toml")),
        )
    }

    #[test]
    fn jednotka_systemd_ma_podstatne_veci() {
        let j = jednotka_systemd(&cesty(), Path::new("/usr/local/bin/ad-server"), "ad-server");
        assert!(j.contains("ExecStart=/usr/local/bin/ad-server --data-dir /var/lib/ad-server"));
        assert!(j.contains("User=ad-server"));
        assert!(j.contains("WantedBy=multi-user.target"));
        // Port 53 bez práv roota.
        assert!(j.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(j.contains("NoNewPrivileges=true"));
        // Služba nesmí zapisovat, kam se jí zachce.
        assert!(j.contains("ProtectSystem=strict"));
        assert!(j.contains("ReadWritePaths=/var/lib/ad-server /var/lib/ad-server/logs"));
        assert!(!j.contains("User=root"), "služba nesmí běžet pod rootem");
    }

    #[test]
    fn skript_runit_spousti_pod_uzivatelem() {
        let s = skript_runit(&cesty(), Path::new("/usr/local/bin/ad-server"), "ad-server");
        assert!(s.starts_with("#!/bin/sh"));
        assert!(s.contains("exec chpst -u ad-server:ad-server /usr/local/bin/ad-server"));
        assert!(s.contains("--data-dir /var/lib/ad-server"));
        assert!(s.contains("exec 2>&1"), "výstup musí jít do logu runitu");
    }

    #[test]
    fn skript_logu_pouziva_svlogd() {
        let s = skript_runit_log(&cesty());
        assert!(s.contains("svlogd"));
        // Log patří do datového adresáře — odinstalace je pak smazání
        // jednoho místa, ne hledání po systému.
        assert!(s.contains("/var/lib/ad-server/logs"));
    }

    #[test]
    fn plan_bez_potvrzeni_nic_nedela() {
        // Bez --yes musí `nainstaluj` jen vypsat plán a skončit bez chyby.
        let volby = Volby { binarka: Some(PathBuf::from("/tmp/ad-server")), ..Default::default() };
        assert!(!volby.potvrzeno);
        let kroky = plan(Spravce::Systemd, &cesty(), Path::new("/tmp/ad-server"), &volby);
        assert!(kroky.iter().any(|k| k.contains("CAP_NET_BIND_SERVICE")));
        assert!(kroky.len() >= 4);
    }

    #[test]
    fn plan_pro_runit_zminuje_setcap() {
        let volby = Volby::default();
        let kroky = plan(Spravce::Runit, &cesty(), Path::new("/usr/local/bin/ad-server"), &volby);
        assert!(kroky.iter().any(|k| k.contains("setcap")));
    }

    #[test]
    fn spravce_se_pozna() {
        // Na tomhle stroji to nevíme, ale nesmí to spadnout a musí to
        // vrátit něco smysluplného.
        let s = poznej_spravce();
        assert!(!s.jmeno().is_empty());
    }
}
