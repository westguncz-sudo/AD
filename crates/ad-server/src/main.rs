//! `ad-server` — řadič naší vlastní domény.
//!
//! Jeden proces, uvnitř oddělené úlohy:
//! * webová správa na loopbacku,
//! * doménové API pro klienty přes TLS,
//! * (od fáze 4) vlastní DNS server.

mod assets;
mod config;
mod dns;
mod domain;
mod http;
mod pki;
mod sluzba;
mod store;

use ad_core::{AdError, Result};
use config::{Cesty, Config};
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;
use tokio::sync::watch;

fn main() {
    if let Err(e) = hlavni() {
        eprintln!("ad-server: {}", e.message);
        std::process::exit(1);
    }
}

/// Co se chce po serveru udělat.
enum Prikaz {
    Spust,
    /// Spuštění správcem služeb (Windows SCM).
    SpustJakoSluzbu,
    Verze,
    Napoveda,
    UkazKonfiguraci,
    NovySetupToken,
    NainstalujSluzbu,
    OdinstalujSluzbu,
    StavSluzby,
}

struct Argumenty {
    prikaz: Prikaz,
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    sluzba: sluzba::Volby,
}

fn zparsuj_argumenty() -> Result<Argumenty> {
    let mut a = Argumenty {
        prikaz: Prikaz::Spust,
        data_dir: None,
        config: None,
        sluzba: sluzba::Volby::default(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "run" => a.prikaz = Prikaz::Spust,
            "service-run" => a.prikaz = Prikaz::SpustJakoSluzbu,
            "show-config" => a.prikaz = Prikaz::UkazKonfiguraci,
            "setup-token" => a.prikaz = Prikaz::NovySetupToken,
            "install-service" => a.prikaz = Prikaz::NainstalujSluzbu,
            "uninstall-service" => a.prikaz = Prikaz::OdinstalujSluzbu,
            "service-status" => a.prikaz = Prikaz::StavSluzby,
            "--yes" => a.sluzba.potvrzeno = true,
            "--purge" => a.sluzba.smazat_data = true,
            "--user" => {
                a.sluzba.uzivatel =
                    args.next().ok_or_else(|| AdError::bad_request("--user potřebuje jméno"))?
            }
            "--bin" => {
                a.sluzba.binarka = Some(PathBuf::from(
                    args.next().ok_or_else(|| AdError::bad_request("--bin potřebuje cestu"))?,
                ))
            }
            "-V" | "--version" => a.prikaz = Prikaz::Verze,
            "-h" | "--help" => a.prikaz = Prikaz::Napoveda,
            "--data-dir" => {
                a.data_dir = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| AdError::bad_request("--data-dir potřebuje cestu"))?,
                ))
            }
            "--config" => {
                a.config = Some(PathBuf::from(
                    args.next().ok_or_else(|| AdError::bad_request("--config potřebuje cestu"))?,
                ))
            }
            jine => {
                return Err(AdError::bad_request(format!("neznámý argument: {jine} (zkus --help)")))
            }
        }
    }
    Ok(a)
}

fn napoveda() {
    println!(
        "ad-server {verze} — vlastní zjednodušený řadič domény

POUŽITÍ:
    ad-server [PŘÍKAZ] [PŘEPÍNAČE]

PŘÍKAZY:
    run                 spustí server (výchozí)
    show-config         vypíše výchozí konfiguraci k uložení do config.toml
    setup-token         vytvoří nový jednorázový token pro první přihlášení
                        (jen dokud doména neexistuje)
    install-service     nainstaluje server jako systémovou službu
    uninstall-service   službu zase odebere
    service-status      vypíše, jestli je služba nainstalovaná a běží

PŘEPÍNAČE:
    --data-dir CESTA   kde držet databázi, certifikáty a soubory
    --config CESTA     cesta ke config.toml
    --yes              u install-service a uninstall-service: opravdu to udělej
    --user JMÉNO       uživatel, pod kterým služba poběží (Linux)
    --bin CESTA        cesta k binárce pro službu (jinak ta běžící)
    --purge            u uninstall-service smazat i data domény
    -V, --version      verze
    -h, --help         tato nápověda

SLUŽBA:
    Bez --yes příkaz jen vypíše, co by udělal, a skončí. Nic se
    nenainstaluje bez výslovného souhlasu a všechno jde odebrat.
    Na Linuxu server neběží pod rootem — port 53 řeší schopnost
    CAP_NET_BIND_SERVICE.

PROMĚNNÉ PROSTŘEDÍ:
    AD_SERVER_DATA_DIR   totéž jako --data-dir
    RUST_LOG             podrobnost logu (přebije config.toml)

PŘÍKLAD PRO TESTOVÁNÍ:
    ad-server --data-dir ./data run

Webová správa poslouchá na 127.0.0.1:{sprava}. Na serveru bez grafiky
použij SSH tunel:
    ssh -L {sprava}:127.0.0.1:{sprava} uzivatel@server
",
        verze = ad_core::VERZE,
        sprava = ad_core::proto::PORT_SPRAVA,
    );
}

fn hlavni() -> Result<()> {
    let args = zparsuj_argumenty()?;
    match args.prikaz {
        Prikaz::Verze => {
            println!("ad-server {} (protokol {})", ad_core::VERZE, ad_core::proto::PROTO_VERZE);
            return Ok(());
        }
        Prikaz::Napoveda => {
            napoveda();
            return Ok(());
        }
        Prikaz::UkazKonfiguraci => {
            println!("# Výchozí konfigurace ad-serveru.");
            println!("# Ulož jako config.toml a změň, co potřebuješ.\n");
            print!("{}", Config::default().jako_toml());
            return Ok(());
        }
        _ => {}
    }

    let cesty = Arc::new(Cesty::nove(args.data_dir, args.config));
    let konfigurace = Arc::new(Config::nacti(&cesty.config)?);
    cesty.priprav()?;

    if let Prikaz::NovySetupToken = args.prikaz {
        let store = Store::otevri(&cesty.databaze())?;
        if store.domena()?.is_some() {
            return Err(AdError::conflict(
                "doména už existuje — přihlas se jako administrator, \
                 jednorázový token už neplatí",
            ));
        }
        store.zrus_nastaveni(store::schema::nastaveni::SETUP_TOKEN_HASH)?;
        let token = store
            .zajisti_setup_token()?
            .ok_or_else(|| AdError::internal("token se nepodařilo vytvořit"))?;
        config::zapis_tajny_soubor(&cesty.setup_token(), &format!("{token}\n"))?;
        vypis_setup_token(&token, &cesty, &konfigurace);
        return Ok(());
    }

    match args.prikaz {
        Prikaz::NainstalujSluzbu => return sluzba::nainstaluj(&cesty, &konfigurace, &args.sluzba),
        Prikaz::OdinstalujSluzbu => return sluzba::odinstaluj(&cesty, &args.sluzba),
        Prikaz::StavSluzby => return sluzba::vypis_stav(&cesty),
        _ => {}
    }

    nastav_logovani(&konfigurace, &cesty)?;
    pki::init_rustls()?;

    if let Prikaz::SpustJakoSluzbu = args.prikaz {
        return spust_jako_sluzbu(cesty, konfigurace);
    }

    spust_v_runtime(cesty, konfigurace, pockej_na_signal())
}

/// Postaví běhové prostředí a spustí server. `konec` je to, na co se
/// čeká — Ctrl-C, SIGTERM, nebo pokyn od správce služeb.
fn spust_v_runtime(
    cesty: Arc<Cesty>,
    konfigurace: Arc<Config>,
    konec: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ad-server")
        .build()
        .map_err(|e| AdError::internal(format!("tokio runtime: {e}")))?;
    runtime.block_on(spust(cesty, konfigurace, konec))
}

/// Běh pod správcem služeb Windows.
///
/// **Nemám jak vyzkoušet** — je to napsané podle dokumentace crate
/// `windows-service`. Otestuj ve virtuálce s Windows.
#[cfg(windows)]
fn spust_jako_sluzbu(_cesty: Arc<Cesty>, _konfigurace: Arc<Config>) -> Result<()> {
    windows_sluzba::spust()
}

#[cfg(not(windows))]
fn spust_jako_sluzbu(cesty: Arc<Cesty>, konfigurace: Arc<Config>) -> Result<()> {
    // Na Linuxu služba spouští obyčejné `run`; systemd i runit čekají
    // program v popředí. Tenhle příkaz je tu jen pro jednotnost.
    tracing::info!("spouštím pod správcem služeb (systemd/runit)");
    spust_v_runtime(cesty, konfigurace, pockej_na_signal())
}

#[cfg(windows)]
mod windows_sluzba {
    use super::*;
    use std::ffi::OsString;
    use std::sync::mpsc;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    pub fn spust() -> Result<()> {
        service_dispatcher::start(crate::sluzba::JMENO_WINDOWS, ffi_service_main)
            .map_err(|e| AdError::internal(format!("nelze se ohlásit správci služeb: {e}")))
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = telo_sluzby() {
            tracing::error!(chyba = %e.message, "služba skončila chybou");
        }
    }

    fn telo_sluzby() -> Result<()> {
        // Argumenty si přečteme z příkazové řádky procesu — správce
        // služeb nás spustil s tím, co jsme při registraci zapsali.
        let args = zparsuj_argumenty()?;
        let cesty = Arc::new(Cesty::nove(args.data_dir, args.config));
        let konfigurace = Arc::new(Config::nacti(&cesty.config)?);

        let (poslat_stop, prijmout_stop) = mpsc::channel::<()>();
        let obsluha = move |udalost| -> ServiceControlHandlerResult {
            match udalost {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = poslat_stop.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let stav = service_control_handler::register(crate::sluzba::JMENO_WINDOWS, obsluha)
            .map_err(|e| AdError::internal(format!("registrace obsluhy: {e}")))?;

        let ohlas = |s: ServiceState, prijima: ServiceControlAccept| {
            let _ = stav.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: s,
                controls_accepted: prijima,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: std::time::Duration::from_secs(10),
                process_id: None,
            });
        };
        ohlas(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN);

        let vysledek = spust_v_runtime(cesty, konfigurace, async move {
            // Čekání na pokyn ke stopnutí přesuneme mimo asynchronní
            // vlákna — je to blokující kanál.
            let _ = tokio::task::spawn_blocking(move || prijmout_stop.recv()).await;
        });

        ohlas(ServiceState::Stopped, ServiceControlAccept::empty());
        vysledek
    }
}

fn nastav_logovani(cfg: &Config, cesty: &Cesty) -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{fmt, EnvFilter};

    let filtr = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("ad_server={0},ad_core={0},warn", cfg.log.level))
    });

    let do_konzole = fmt::layer().with_target(false).with_writer(std::io::stderr);

    let do_souboru = if cfg.log.to_file {
        let cesta = cesty.log().join("ad-server.log");
        let soubor = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cesta)
            .map_err(|e| AdError::internal(format!("log {}: {e}", cesta.display())))?;
        Some(fmt::layer().with_ansi(false).with_target(false).with_writer(Arc::new(soubor)))
    } else {
        None
    };

    tracing_subscriber::registry().with(filtr).with(do_konzole).with(do_souboru).init();
    Ok(())
}

async fn spust(
    cesty: Arc<Cesty>,
    konfigurace: Arc<Config>,
    konec: impl std::future::Future<Output = ()>,
) -> Result<()> {
    tracing::info!(
        verze = ad_core::VERZE,
        protokol = ad_core::proto::PROTO_VERZE,
        data = %cesty.data_dir.display(),
        "ad-server startuje"
    );

    let store = Store::otevri(&cesty.databaze())?;

    // První spuštění: jednorázový token do konzole i do souboru.
    if let Some(token) = store.zajisti_setup_token()? {
        config::zapis_tajny_soubor(&cesty.setup_token(), &format!("{token}\n"))?;
        vypis_setup_token(&token, &cesty, &konfigurace);
        // Do logu jde jen to, že token vznikl — nikdy jeho hodnota.
        tracing::info!("vytvořen jednorázový token pro první přihlášení");
    }

    let (signal_zmeny, prijem_zmeny) = watch::channel(0u64);
    let stav: http::Stav = Arc::new(http::AppState {
        store: store.clone(),
        cesty: cesty.clone(),
        config: konfigurace.clone(),
        start: std::time::Instant::now(),
        dns: Arc::new(dns::DnsStav::default()),
        signal_zmeny,
    });

    let (vypni, prijem_vypnuti) = watch::channel(false);

    // --- webová správa ---
    let tls_spravy = if konfigurace.admin.tls {
        if !pki::SouboryPki::v(&cesty.pki()).existuji() {
            return Err(AdError::bad_request(
                "[admin] tls = true, ale certifikát ještě neexistuje. \
                 Nejdřív vytvoř doménu s tls = false, pak přepni.",
            ));
        }
        Some(pki::tls_config(&cesty.pki())?)
    } else {
        None
    };
    let sprava = tokio::spawn(http::poslouchej(
        "admin",
        konfigurace.admin.bind,
        http::admin_router(stav.clone()),
        tls_spravy,
        prijem_vypnuti.clone(),
    ));

    // --- doménové API (čeká na certifikát) ---
    let domenove =
        tokio::spawn(domenove_api(stav.clone(), prijem_zmeny.clone(), prijem_vypnuti.clone()));

    // --- DNS server (čeká na nainstalovanou roli) ---
    let dns_uloha = tokio::spawn(dns_sluzba(stav.clone(), prijem_zmeny, prijem_vypnuti.clone()));

    vypis_uvod(&store, &konfigurace)?;

    // --- čekání na ukončení ---
    konec.await;
    tracing::info!("ukončuji, zavírám poslouchátka");
    let _ = vypni.send(true);

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), sprava).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), domenove).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), dns_uloha).await;
    tracing::info!("ad-server ukončen");
    Ok(())
}

/// Doménové API běží jen tehdy, když existuje certifikát. Po povýšení
/// (nebo zrušení) domény se tahle úloha sama přestaví.
async fn domenove_api(
    stav: http::Stav,
    mut restart: watch::Receiver<u64>,
    mut vypni: watch::Receiver<bool>,
) {
    loop {
        let pki_je = pki::SouboryPki::v(&stav.cesty.pki()).existuji();
        if !pki_je {
            tracing::info!("doménové API čeká na vytvoření domény (není certifikát)");
            tokio::select! {
                _ = restart.changed() => continue,
                _ = vypni.changed() => return,
            }
        }

        let cfg = match pki::tls_config(&stav.cesty.pki()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(chyba = %e.message, "TLS konfiguraci nelze postavit");
                tokio::select! {
                    _ = restart.changed() => continue,
                    _ = vypni.changed() => return,
                }
            }
        };

        let (stop, prijem_stopu) = watch::channel(false);
        let adresa = stav.config.domain_api.bind;
        let router = http::domain_router(stav.clone());
        let uloha =
            tokio::spawn(http::poslouchej("domain-api", adresa, router, Some(cfg), prijem_stopu));

        let koncime = tokio::select! {
            _ = restart.changed() => false,
            _ = vypni.changed() => true,
            vysledek = uloha => {
                if let Ok(Err(e)) = vysledek {
                    tracing::error!(chyba = %e.message, "doménové API skončilo chybou");
                }
                // Poslouchátko spadlo (třeba obsazený port) — počkáme
                // na další pokyn, ať to nezkoušíme ve smyčce.
                tokio::select! {
                    _ = restart.changed() => continue,
                    _ = vypni.changed() => return,
                }
            }
        };
        let _ = stop.send(true);
        if koncime {
            return;
        }
        tracing::info!("doménové API se restartuje (změna certifikátu)");
    }
}

/// DNS server běží, jen když je nainstalovaná role DNS a je povolený
/// v konfiguraci. Po instalaci role nebo po zrušení domény se tahle
/// úloha sama přestaví.
async fn dns_sluzba(
    stav: http::Stav,
    mut zmena: watch::Receiver<u64>,
    mut vypni: watch::Receiver<bool>,
) {
    loop {
        let role_dns = {
            let store = stav.store.clone();
            tokio::task::spawn_blocking(move || store.role())
                .await
                .ok()
                .and_then(|r| r.ok())
                .map(|r| r.dns)
                .unwrap_or(false)
        };

        if !stav.config.dns.enabled || !role_dns {
            if !stav.config.dns.enabled {
                tracing::info!("DNS server je v konfiguraci vypnutý");
            } else {
                tracing::info!("DNS server čeká na nainstalování role DNS");
            }
            tokio::select! {
                _ = zmena.changed() => continue,
                _ = vypni.changed() => return,
            }
        }

        let (stop, prijem_stopu) = watch::channel(false);
        let mut uloha = tokio::spawn(dns::spust(
            stav.store.clone(),
            stav.dns.clone(),
            stav.config.dns.bind,
            stav.config.dns.forward_only_local,
            prijem_stopu,
        ));

        let koncime = tokio::select! {
            _ = zmena.changed() => false,
            _ = vypni.changed() => true,
            vysledek = &mut uloha => {
                if let Ok(Err(e)) = vysledek {
                    // Nejčastěji obsazený port 53 nebo chybějící
                    // oprávnění. Server kvůli tomu nekončí — správa
                    // i doménové API běží dál a je to vidět v přehledu.
                    tracing::error!(chyba = %e.message, "DNS server se nespustil");
                }
                tokio::select! {
                    _ = zmena.changed() => continue,
                    _ = vypni.changed() => return,
                }
            }
        };
        let _ = stop.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), uloha).await;
        if koncime {
            return;
        }
        tracing::info!("DNS server se přestavuje (změna stavu serveru)");
    }
}

#[cfg(unix)]
async fn pockej_na_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(chyba = %e, "SIGTERM nelze odchytit");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("přišel Ctrl-C"),
        _ = term.recv() => tracing::info!("přišel SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn pockej_na_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("přišel Ctrl-C");
}

fn vypis_setup_token(token: &str, cesty: &Cesty, cfg: &Config) {
    let schema = if cfg.admin.tls { "https" } else { "http" };
    println!(
        "
================================================================
 PRVNÍ SPUŠTĚNÍ — jednorázový token pro přihlášení do správy

   {token}

 Uloženo v souboru: {soubor}
 Správa: {schema}://{bind}
 Na serveru bez grafiky použij SSH tunel z vlastního počítače:
   ssh -L {port}:127.0.0.1:{port} uzivatel@<adresa serveru>

 Token platí jen dokud nevytvoříš doménu. Pak se přihlašuješ
 účtem administrator.
================================================================
",
        token = token,
        soubor = cesty.setup_token().display(),
        schema = schema,
        bind = cfg.admin.bind,
        port = cfg.admin.bind.port(),
    );
}

fn vypis_uvod(store: &Store, cfg: &Config) -> Result<()> {
    let stav = store.stav()?;
    match store.domena()? {
        Some(d) => {
            tracing::info!(
                domena = %d.dns_name,
                radic = %d.dc_fqdn,
                adresa = %d.dc_ip,
                "server je řadičem domény"
            );
        }
        None => {
            tracing::info!(
                stav = ?stav,
                sprava = %cfg.admin.bind,
                "doména zatím neexistuje — otevři správu a povyš server"
            );
        }
    }
    Ok(())
}
