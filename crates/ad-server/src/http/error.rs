//! Překlad našich chyb na HTTP odpovědi.
//!
//! Každá chyba jde ven ve stejném tvaru `{"error":{"code":...}}`.
//! Vnitřní podrobnosti (`internal`) se **nelogují klientovi** — ten
//! dostane jen obecnou větu, podrobnost jde do logu serveru.

use ad_core::{AdError, ErrorCode, ErrorResponse};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Obal nad `AdError`, aby se dal vrátit z handleru.
#[derive(Debug)]
pub struct Chyba(pub AdError);

impl From<AdError> for Chyba {
    fn from(e: AdError) -> Self {
        Self(e)
    }
}

impl IntoResponse for Chyba {
    fn into_response(self) -> Response {
        let mut e = self.0;
        let status =
            StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if e.code == ErrorCode::Internal {
            // Podrobnost patří do logu, ne do odpovědi.
            tracing::error!(chyba = %e.message, "vnitřní chyba serveru");
            e = AdError::new(ErrorCode::Internal, "vnitřní chyba serveru, podrobnosti jsou v logu");
        } else {
            tracing::debug!(kod = %e.code, zprava = %e.message, "chyba požadavku");
        }

        (status, Json(ErrorResponse::from(e))).into_response()
    }
}

/// Výsledek handleru.
pub type Odpoved<T> = std::result::Result<T, Chyba>;

/// Tělo požadavku jako JSON, ale s našimi chybami.
///
/// Výchozí `Json` z axum vrací vlastní formát chyby. Tohle ho sjednotí
/// s ostatními odpověďmi — a hlavně se tím chyba `deny_unknown_fields`
/// dostane ke klientovi v čitelné podobě.
pub struct Telo<T>(pub T);

impl<T, S> FromRequest<S> for Telo<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Chyba;

    async fn from_request(req: Request, state: &S) -> std::result::Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(hodnota)) => Ok(Telo(hodnota)),
            Err(odmitnuti) => {
                let zprava = match &odmitnuti {
                    JsonRejection::JsonDataError(e) => format!("tělo požadavku: {e}"),
                    JsonRejection::JsonSyntaxError(e) => format!("tělo není platný JSON: {e}"),
                    JsonRejection::MissingJsonContentType(_) => {
                        "chybí hlavička content-type: application/json".to_string()
                    }
                    jine => format!("tělo požadavku: {jine}"),
                };
                Err(Chyba(AdError::bad_request(zprava)))
            }
        }
    }
}
