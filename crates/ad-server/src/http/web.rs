//! Webové rozhraní zabalené v binárce.
//!
//! HTML, CSS a JavaScript jsou uvnitř programu (`rust-embed`), takže
//! `ad-server` je jeden soubor a nic se nestahuje z internetu. To není
//! jen pohodlí: hlavička `Content-Security-Policy` níž zakazuje načítat
//! cokoli z cizího serveru, takže rozhraní funguje i na stroji úplně
//! bez internetu.
//!
//! V debug sestavení se soubory čtou z disku (`web/`), aby se daly
//! upravovat bez překladu. V release jsou zabalené.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::Embed)]
#[folder = "web/"]
struct Soubory;

/// Pravidla, co smí stránka načítat. Všechno jen z našeho serveru,
/// žádné inline skripty, žádné vkládání do rámců.
const CSP: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     form-action 'none'; \
     base-uri 'none'; \
     object-src 'none'; \
     frame-ancestors 'none'";

/// Obslouží požadavek na statický soubor rozhraní.
///
/// Cesty bez tečky (např. `/users`) vrací `index.html`, aby fungovalo
/// přesměrování v prohlížeči i po obnovení stránky.
pub async fn soubor(uri: axum::http::Uri, hlavicky: axum::http::HeaderMap) -> Response {
    let cesta = uri.path().trim_start_matches('/');
    let cesta = if cesta.is_empty() { "index.html" } else { cesta };

    // Cesta se nesmí dostat mimo zabalené soubory. `rust-embed` sice
    // nic jiného nezná, ale lepší to odmítnout hned a nahlas.
    if cesta.contains("..") || cesta.starts_with('/') || cesta.contains('\\') {
        return (StatusCode::BAD_REQUEST, "neplatná cesta").into_response();
    }

    let nalezeno = Soubory::get(cesta).or_else(|| {
        // Cesta bez přípony = adresa v rozhraní, vrátíme aplikaci.
        if cesta.contains('.') {
            None
        } else {
            Soubory::get("index.html")
        }
    });

    let Some(soubor) = nalezeno else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Takový soubor rozhraní neexistuje.\n",
        )
            .into_response();
    };

    let etag = format!("\"{}\"", hex::encode(&soubor.metadata.sha256_hash()[..8]));
    let typ = typ_obsahu(cesta);

    // Prohlížeč už soubor má?
    if let Some(poslany) = hlavicky.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if poslany.split(',').any(|e| e.trim() == etag) {
            return (StatusCode::NOT_MODIFIED, bezpecnostni_hlavicky(&etag, typ)).into_response();
        }
    }

    (StatusCode::OK, bezpecnostni_hlavicky(&etag, typ), soubor.data.to_vec()).into_response()
}

fn bezpecnostni_hlavicky(etag: &str, typ: &'static str) -> [(header::HeaderName, HeaderValue); 7] {
    [
        (header::CONTENT_TYPE, HeaderValue::from_static(typ)),
        (header::ETAG, HeaderValue::from_str(etag).unwrap_or(HeaderValue::from_static("\"0\""))),
        // Rozhraní se mění s verzí serveru, takže se spoléháme na ETag
        // a necháme prohlížeč vždy zkontrolovat.
        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        (header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)),
        (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
        (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
        (header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
    ]
}

fn typ_obsahu(cesta: &str) -> &'static str {
    match cesta.rsplit_once('.').map(|(_, p)| p) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typy_obsahu() {
        assert_eq!(typ_obsahu("index.html"), "text/html; charset=utf-8");
        assert_eq!(typ_obsahu("js/app.js"), "text/javascript; charset=utf-8");
        assert_eq!(typ_obsahu("css/app.css"), "text/css; charset=utf-8");
        assert_eq!(typ_obsahu("neco"), "application/octet-stream");
    }

    #[test]
    fn soubory_jsou_zabalene() {
        // Kdyby se rozhraní nezabalilo, server by běžel bez UI a nikdo
        // by si toho nevšiml až do spuštění.
        assert!(Soubory::get("index.html").is_some(), "index.html musí být v binárce");
        assert!(Soubory::get("css/app.css").is_some(), "app.css musí být v binárce");
        assert!(Soubory::get("js/app.js").is_some(), "app.js musí být v binárce");
    }

    #[test]
    fn csp_zakazuje_cizi_zdroje() {
        assert!(CSP.contains("default-src 'self'"));
        assert!(!CSP.contains("unsafe-inline"));
        assert!(!CSP.contains("unsafe-eval"));
        assert!(!CSP.contains("http://"));
    }
}
