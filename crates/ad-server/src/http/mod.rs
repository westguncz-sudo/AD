//! HTTP vrstva: dva oddělené routery na dvou oddělených poslouchátkách.
//!
//! * `admin_router` — webová správa, jen na loopbacku (nebo s TLS).
//! * `domain_router` — doménové API pro klienty, vždy přes TLS.
//!
//! Oddělení je záměrné: z vnější sítě se na správu nedá dosáhnout,
//! protože tam server neposlouchá.

pub mod admin;
pub mod domain_api;
pub mod error;
pub mod extract;
pub mod web;

use crate::config::{Cesty, Config};
use crate::store::Store;
use ad_core::{AdError, Result};
use axum::Router;
use error::Chyba;
use extract::KlientIp;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tower::ServiceExt;

/// Společný stav, který mají handlery k dispozici.
pub struct AppState {
    pub store: Store,
    pub cesty: Arc<Cesty>,
    pub config: Arc<Config>,
    pub start: std::time::Instant,
    /// Zvýšením čísla se restartuje poslouchátko doménového API —
    /// potřebujeme to po povýšení, kdy vznikne certifikát.
    pub restart_tls: watch::Sender<u64>,
}

pub type Stav = Arc<AppState>;

/// Spustí práci s databází mimo asynchronní vlákna.
///
/// Všechny dotazy do SQLite a hlavně Argon2id (desítky milisekund) musí
/// jít do `spawn_blocking`, jinak by blokovaly obsluhu ostatních
/// požadavků.
pub async fn blok<T, F>(f: F) -> std::result::Result<T, Chyba>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Chyba(e)),
        Err(e) => Err(Chyba(AdError::internal(format!("úloha spadla: {e}")))),
    }
}

/// Router webové správy.
pub fn admin_router(stav: Stav) -> Router {
    admin::routes().with_state(stav)
}

/// Router doménového API.
pub fn domain_router(stav: Stav) -> Router {
    domain_api::routes().with_state(stav)
}

/// Poslouchá na adrese a obsluhuje požadavky, dokud nepřijde signál
/// k vypnutí.
pub async fn poslouchej(
    jmeno: &'static str,
    adresa: SocketAddr,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    mut vypni: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(adresa)
        .await
        .map_err(|e| AdError::internal(format!("nelze poslouchat na {adresa}: {e}")))?;
    tracing::info!(
        poslouchadlo = jmeno,
        adresa = %adresa,
        tls = tls.is_some(),
        "poslouchám"
    );

    loop {
        tokio::select! {
            _ = vypni.changed() => {
                if *vypni.borrow() {
                    tracing::info!(poslouchadlo = jmeno, "končím");
                    return Ok(());
                }
            }
            prijato = listener.accept() => {
                let (stream, peer) = match prijato {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(chyba = %e, "spojení se nepodařilo přijmout");
                        continue;
                    }
                };
                let router = router.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Err(e) = obsluz(stream, peer, router, tls).await {
                        tracing::debug!(klient = %peer, chyba = %e, "spojení skončilo chybou");
                    }
                });
            }
        }
    }
}

async fn obsluz(
    stream: TcpStream,
    peer: SocketAddr,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Nagle vypnutý — odpovědi jsou malé a nechceme je zdržovat.
    let _ = stream.set_nodelay(true);

    let sluzba =
        hyper::service::service_fn(move |pozadavek: hyper::Request<hyper::body::Incoming>| {
            let router = router.clone();
            async move {
                let mut pozadavek = pozadavek.map(axum::body::Body::new);
                // IP klienta vkládáme my — vlastní server nad hyper nemá
                // `ConnectInfo`, a adresa ze spojení je jediná, které se
                // dá věřit.
                pozadavek.extensions_mut().insert(KlientIp(peer.ip()));
                router.oneshot(pozadavek).await
            }
        });

    match tls {
        None => {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), sluzba)
                .await?;
        }
        Some(cfg) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            let tls_stream = acceptor.accept(stream).await?;
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), sluzba)
                .await?;
        }
    }
    Ok(())
}

/// Jméno tohoto stroje — jen pro zobrazení v přehledu.
pub fn hostname_stroje() -> String {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "neznámý".to_string())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "neznámý".to_string())
    }
}

/// Stručný popis operačního systému.
pub fn popis_os() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}
