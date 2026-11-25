//! Extraktory: kdo požadavek posílá a jestli na to má právo.
//!
//! Tady je hlavní trik celé bezpečnosti správního API: **kontrola CSRF
//! je součástí extraktoru `Spravce`.** Když handler vyžaduje `Spravce`,
//! CSRF se zkontroluje automaticky a nedá se zapomenout.

use super::error::Chyba;
use super::Stav;
use ad_core::model::Computer;
use ad_core::proto::{AdminPrincipal, COOKIE_SESSION, HLAVICKA_CSRF};
use ad_core::{secret, AdError, ErrorCode};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, Method};
use std::net::IpAddr;

/// IP adresa klienta. Vkládá ji přijímací smyčka, protože s vlastním
/// serverem nad hyper nemáme `ConnectInfo`.
#[derive(Debug, Clone, Copy)]
pub struct KlientIp(pub IpAddr);

impl KlientIp {
    pub fn text(&self) -> String {
        self.0.to_string()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for KlientIp {
    type Rejection = Chyba;

    async fn from_request_parts(
        parts: &mut Parts,
        _s: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<KlientIp>()
            .copied()
            .ok_or_else(|| Chyba(AdError::internal("chybí IP adresa klienta v požadavku")))
    }
}

/// Přihlášený správce ve webovém rozhraní.
///
/// U měnících metod (POST/PUT/PATCH/DELETE) navíc ověří CSRF token
/// a hlavičku `Origin`.
#[derive(Debug, Clone)]
pub struct Spravce {
    pub principal: AdminPrincipal,
    pub session_token: String,
}

impl Spravce {
    /// Jméno pro auditní log.
    pub fn jmeno(&self) -> String {
        match &self.principal {
            AdminPrincipal::Setup => "setup-token".to_string(),
            AdminPrincipal::User { sam_account_name, .. } => sam_account_name.clone(),
        }
    }

    /// Je to plnohodnotný doménový správce (ne jednorázový token)?
    pub fn je_domenovy(&self) -> bool {
        matches!(self.principal, AdminPrincipal::User { .. })
    }

    /// Vyžaduje doménového správce — pro akce, které jednorázový token
    /// dělat nesmí.
    pub fn vyzaduj_domenoveho(&self) -> Result<(), AdError> {
        if self.je_domenovy() {
            Ok(())
        } else {
            Err(AdError::permission_denied(
                "tuhle akci smí jen doménový správce, ne jednorázový token",
            ))
        }
    }
}

impl FromRequestParts<Stav> for Spravce {
    type Rejection = Chyba;

    async fn from_request_parts(
        parts: &mut Parts,
        stav: &Stav,
    ) -> std::result::Result<Self, Self::Rejection> {
        let token = cookie(parts, COOKIE_SESSION)
            .ok_or_else(|| Chyba(AdError::new(ErrorCode::AuthRequired, "nejsi přihlášený")))?;

        let store = stav.store.clone();
        let t = token.clone();
        let nalezeno = tokio::task::spawn_blocking(move || store.session(&t))
            .await
            .map_err(|e| Chyba(AdError::internal(format!("úloha spadla: {e}"))))??;

        let (principal, csrf) = nalezeno.ok_or_else(|| {
            Chyba(AdError::new(ErrorCode::SessionExpired, "přihlášení vypršelo, přihlas se znovu"))
        })?;

        // --- CSRF ---
        // Čtení je bezpečné, měnící metody musí mít token v hlavičce.
        let meni = !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        if meni {
            let poslany =
                parts.headers.get(HLAVICKA_CSRF).and_then(|v| v.to_str().ok()).unwrap_or_default();
            if poslany.is_empty() || !secret::rovno_v_konstantnim_case(poslany, &csrf) {
                return Err(Chyba(AdError::new(
                    ErrorCode::CsrfFailed,
                    format!("chybí nebo nesouhlasí hlavička {HLAVICKA_CSRF}"),
                )));
            }
            // Origin: když ho prohlížeč pošle, musí ukazovat na nás.
            if let Some(origin) = parts.headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
                if !origin_je_nas(
                    origin,
                    &stav.config.admin.bind.to_string(),
                    stav.config.admin.tls,
                ) {
                    return Err(Chyba(AdError::new(
                        ErrorCode::CsrfFailed,
                        "požadavek přišel z cizí stránky (Origin nesouhlasí)",
                    )));
                }
            }
        }

        Ok(Spravce { principal, session_token: token })
    }
}

/// Počítač ověřený tokenem v hlavičce `Authorization: Bearer ...`.
#[derive(Debug, Clone)]
pub struct Stroj {
    pub computer: Computer,
}

impl FromRequestParts<Stav> for Stroj {
    type Rejection = Chyba;

    async fn from_request_parts(
        parts: &mut Parts,
        stav: &Stav,
    ) -> std::result::Result<Self, Self::Rejection> {
        let hlavicka = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let token = hlavicka.strip_prefix("Bearer ").or_else(|| hlavicka.strip_prefix("bearer "));
        let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
            return Err(Chyba(AdError::new(
                ErrorCode::AuthRequired,
                "chybí hlavička Authorization: Bearer <token počítače>",
            )));
        };

        let store = stav.store.clone();
        let t = token.to_string();
        let nalezeno = tokio::task::spawn_blocking(move || store.pocitac_podle_tokenu(&t))
            .await
            .map_err(|e| Chyba(AdError::internal(format!("úloha spadla: {e}"))))??;

        let computer = nalezeno.ok_or_else(|| {
            Chyba(AdError::new(
                ErrorCode::AuthRequired,
                "token počítače neplatí nebo vypršel — získej nový přes /machine/token",
            ))
        })?;
        Ok(Stroj { computer })
    }
}

/// Vytáhne cookie z hlavičky.
fn cookie(parts: &Parts, jmeno: &str) -> Option<String> {
    let hlavicka = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    for cast in hlavicka.split(';') {
        let cast = cast.trim();
        if let Some(hodnota) = cast.strip_prefix(&format!("{jmeno}=")) {
            if !hodnota.is_empty() {
                return Some(hodnota.to_string());
            }
        }
    }
    None
}

/// Ukazuje `Origin` na naši vlastní správu?
fn origin_je_nas(origin: &str, bind: &str, tls: bool) -> bool {
    let schema = if tls { "https" } else { "http" };
    let port = bind.rsplit(':').next().unwrap_or("8080");
    let povolene = [
        format!("{schema}://127.0.0.1:{port}"),
        format!("{schema}://localhost:{port}"),
        format!("{schema}://[::1]:{port}"),
    ];
    povolene.iter().any(|p| p == origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_se_kontroluje() {
        assert!(origin_je_nas("http://127.0.0.1:8080", "127.0.0.1:8080", false));
        assert!(origin_je_nas("http://localhost:8080", "127.0.0.1:8080", false));
        assert!(!origin_je_nas("http://zlo.example", "127.0.0.1:8080", false));
        assert!(!origin_je_nas("http://127.0.0.1:9999", "127.0.0.1:8080", false));
        // Při zapnutém TLS platí https, ne http.
        assert!(origin_je_nas("https://127.0.0.1:8080", "127.0.0.1:8080", true));
        assert!(!origin_je_nas("http://127.0.0.1:8080", "127.0.0.1:8080", true));
    }
}
