//! Správní API — `/admin/api/v1/...`. Jen z loopbacku.
//!
//! Každý handler, který něco mění, bere extraktor `Spravce`. Tím se
//! automaticky vynutí přihlášení **a** kontrola CSRF — nedá se na to
//! zapomenout.

use super::error::{Chyba, Odpoved, Telo};
use super::extract::{KlientIp, Spravce};
use super::{blok, Stav};
use ad_core::model::*;
use ad_core::proto::*;
use ad_core::{AdError, ErrorCode};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

pub fn routes() -> Router<Stav> {
    Router::new()
        .route("/admin/api/v1/hello", get(hello))
        .route("/admin/api/v1/session", post(prihlas).delete(odhlas))
        .route("/admin/api/v1/me", get(kdo_jsem))
        .route("/admin/api/v1/status", get(stav_serveru))
        .route("/admin/api/v1/roles", post(nainstaluj_role))
        .route("/admin/api/v1/promote/precheck", post(precheck))
        .route("/admin/api/v1/promote", post(povys))
        .route("/admin/api/v1/demote", post(zrus_domenu))
        .route("/admin/api/v1/events", get(audit))
        // organizační jednotky
        .route("/admin/api/v1/ous", get(seznam_ou).post(vytvor_ou))
        .route("/admin/api/v1/ous/tree", get(strom))
        .route("/admin/api/v1/ous/{id}", get(ou_detail).patch(uprav_ou).delete(smaz_ou))
        .route("/admin/api/v1/ous/{id}/rename", post(prejmenuj_ou))
        // uživatelé
        .route("/admin/api/v1/users", get(seznam_uzivatelu).post(vytvor_uzivatele))
        .route(
            "/admin/api/v1/users/{id}",
            get(uzivatel_detail).patch(uprav_uzivatele).delete(smaz_uzivatele),
        )
        .route("/admin/api/v1/users/{id}/password", put(nastav_heslo))
        .route("/admin/api/v1/users/{id}/unlock", post(odemkni))
        .route("/admin/api/v1/users/{id}/move", post(presun_uzivatele))
        .route("/admin/api/v1/users/{id}/groups", get(skupiny_uzivatele))
        // skupiny
        .route("/admin/api/v1/groups", get(seznam_skupin).post(vytvor_skupinu))
        .route(
            "/admin/api/v1/groups/{id}",
            get(skupina_detail).patch(uprav_skupinu).delete(smaz_skupinu),
        )
        .route("/admin/api/v1/groups/{id}/move", post(presun_skupinu))
        .route(
            "/admin/api/v1/groups/{id}/members",
            get(clenove).post(pridej_cleny).delete(odeber_cleny),
        )
        // počítače
        .route("/admin/api/v1/computers", get(seznam_pocitacu))
        .route("/admin/api/v1/computers/{id}", get(pocitac_detail).delete(smaz_pocitac))
        .route("/admin/api/v1/computers/{id}/move", post(presun_pocitac))
        // zásady
        .route("/admin/api/v1/gpos", get(seznam_gpo).post(vytvor_gpo))
        .route("/admin/api/v1/gpos/effective", get(efektivni_zasada))
        .route("/admin/api/v1/gpos/links", get(odkazy))
        .route("/admin/api/v1/gpos/links/{id}", delete(odpoj_gpo))
        .route("/admin/api/v1/gpos/{id}", get(gpo_detail).patch(uprav_gpo).delete(smaz_gpo))
        .route("/admin/api/v1/gpos/{id}/links", post(pripoj_gpo))
        // DNS (server začne poslouchat ve fázi 4, data se dají spravovat už teď)
        .route("/admin/api/v1/dns/status", get(dns_stav))
        .route("/admin/api/v1/dns/forwarders", get(forwardery).put(nastav_forwardery))
        .route("/admin/api/v1/dns/zones", get(zony).post(vytvor_zonu))
        .route("/admin/api/v1/dns/zones/{id}", get(zona_detail).delete(smaz_zonu))
        .route("/admin/api/v1/dns/zones/{id}/records", get(zaznamy).post(vytvor_zaznam))
        .route("/admin/api/v1/dns/records/{id}", delete(smaz_zaznam))
        // Webové rozhraní zabalené v binárce. Musí být poslední —
        // bere na sebe všechny ostatní cesty.
        .fallback(super::web::soubor)
}

/// `GET /admin/api/v1/hello` — bez přihlášení, jen z loopbacku.
///
/// Přihlašovací obrazovka potřebuje vědět, jestli se má ptát na
/// jednorázový token, nebo na doménový účet. Proto tenhle jeden
/// koncový bod přihlášení nevyžaduje. Neprozrazuje nic, co by se
/// nedalo zjistit tím, že se server pokusíš použít.
async fn hello(State(stav): State<Stav>) -> Odpoved<Json<AdminHello>> {
    let store = stav.store.clone();
    Ok(Json(
        blok(move || {
            let stage = store.stav()?;
            let domena = store.domena()?;
            Ok(AdminHello {
                product: PRODUKT.to_string(),
                version: ad_core::VERZE.to_string(),
                stage,
                domain_dns_name: domena.as_ref().map(|d| d.dns_name.clone()),
                domain_short_name: domena.as_ref().map(|d| d.short_name.clone()),
                setup_token_active: store
                    .nastaveni(crate::store::schema::nastaveni::SETUP_TOKEN_HASH)?
                    .is_some(),
            })
        })
        .await?,
    ))
}

/// Co vidí přihlašovací obrazovka.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminHello {
    pub product: String,
    pub version: String,
    pub stage: ServerStage,
    pub domain_dns_name: Option<String>,
    pub domain_short_name: Option<String>,
    /// Platí ještě jednorázový token pro první přihlášení?
    pub setup_token_active: bool,
}

// =======================================================================
// DNS
// =======================================================================

async fn dns_stav(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<DnsStatusResponse>> {
    let store = stav.store.clone();
    let cfg = stav.config.clone();
    Ok(Json(
        blok(move || {
            let puvodni: Vec<String> = store
                .nastaveni(crate::store::schema::nastaveni::DNS_ORIGINAL)?
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            Ok(DnsStatusResponse {
                // Vlastní DNS server přijde ve fázi 4.
                running: false,
                listen: vec![cfg.dns.bind.to_string()],
                forwarders: store.forwardery()?,
                original_forwarders: puvodni,
                queries_total: 0,
                queries_forwarded: 0,
                queries_refused: 0,
                cache_entries: 0,
            })
        })
        .await?,
    ))
}

async fn forwardery(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<ForwardersRequest>> {
    let store = stav.store.clone();
    Ok(Json(ForwardersRequest { forwarders: blok(move || store.forwardery()).await? }))
}

async fn nastav_forwardery(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<ForwardersRequest>,
) -> Odpoved<Json<ForwardersRequest>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let seznam = req.forwarders.clone();
    blok(move || {
        store.nastav_forwardery(&seznam)?;
        store.zapis_audit("dns.forwarders", &jmeno, "", &ip_text, true, &seznam.join(", "))
    })
    .await?;
    Ok(Json(req))
}

async fn zony(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<Vec<ad_core::dns::Zone>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.zony()).await?))
}

async fn zona_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<ad_core::dns::Zone>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.zona(id)).await?))
}

async fn vytvor_zonu(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<CreateZoneRequest>,
) -> Odpoved<(StatusCode, Json<ad_core::dns::Zone>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let z = blok(move || {
        let z = store.vytvor_zonu(&req)?;
        store.zapis_audit(
            "dns.zone.create",
            &jmeno,
            &format!("zone:{}", z.name),
            &ip_text,
            true,
            "",
        )?;
        Ok(z)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(z)))
}

async fn smaz_zonu(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let n = store.smaz_zonu(id)?;
        store.zapis_audit("dns.zone.delete", &jmeno, &format!("zone:{n}"), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn zaznamy(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Vec<ad_core::dns::Record>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.zaznamy(id)).await?))
}

async fn vytvor_zaznam(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<CreateRecordRequest>,
) -> Odpoved<(StatusCode, Json<ad_core::dns::Record>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let z = blok(move || {
        let z = store.vytvor_zaznam(id, &req)?;
        store.zapis_audit(
            "dns.record.create",
            &jmeno,
            &format!("record:{} {}", z.name, z.data.typ().as_str()),
            &ip_text,
            true,
            "",
        )?;
        Ok(z)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(z)))
}

async fn smaz_zaznam(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let z = store.zaznam(id)?;
        store.smaz_zaznam(id)?;
        store.zapis_audit(
            "dns.record.delete",
            &jmeno,
            &format!("record:{}", z.name),
            &ip_text,
            true,
            "",
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

// =======================================================================
// Přihlášení
// =======================================================================

async fn prihlas(
    State(stav): State<Stav>,
    ip: KlientIp,
    Telo(req): Telo<AdminLoginRequest>,
) -> Odpoved<impl IntoResponse> {
    let store = stav.store.clone();
    let ip_text = ip.text();

    let (principal, popis) = match req {
        AdminLoginRequest::SetupToken { token } => {
            let s = store.clone();
            let ip2 = ip_text.clone();
            let t = token.odhal().to_string();
            blok(move || {
                s.zkontroluj_rychlost(&ip2)?;
                if !s.over_setup_token(&t)? {
                    s.zapis_audit("admin.login.failed", "setup-token", "", &ip2, false, "")?;
                    return Err(AdError::new(
                        ErrorCode::InvalidCredentials,
                        "jednorázový token neplatí (nebo už doména existuje)",
                    ));
                }
                Ok(())
            })
            .await?;
            (AdminPrincipal::Setup, "jednorázový token".to_string())
        }
        AdminLoginRequest::Password { username, password } => {
            let s = store.clone();
            let ip2 = ip_text.clone();
            let jmeno = username.clone();
            let heslo = password.odhal().to_string();
            let u = blok(move || s.over_spravce(&jmeno, &heslo, &ip2)).await?;
            (
                AdminPrincipal::User {
                    sam_account_name: u.sam_account_name.clone(),
                    display_name: u.display_name.clone(),
                    sid: u.sid,
                },
                u.sam_account_name,
            )
        }
    };

    let s = store.clone();
    let p = principal.clone();
    let ip2 = ip_text.clone();
    let (token, odpoved) = blok(move || s.vytvor_session(&p, &ip2)).await?;

    let s = store.clone();
    let ip3 = ip_text.clone();
    let popis2 = popis.clone();
    blok(move || s.zapis_audit("admin.login.ok", &popis2, "", &ip3, true, "")).await?;

    let mut hlavicky = HeaderMap::new();
    let bezpecne = if stav.config.admin.tls { "; Secure" } else { "" };
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{}",
        COOKIE_SESSION,
        token.odhal(),
        PLATNOST_SESSION_MIN * 60,
        bezpecne
    );
    hlavicky.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|e| Chyba(AdError::internal(format!("cookie: {e}"))))?,
    );
    Ok((hlavicky, Json(odpoved)))
}

async fn odhlas(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
) -> Odpoved<impl IntoResponse> {
    let s = stav.store.clone();
    let token = spravce.session_token.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        s.smaz_session(&token)?;
        s.zapis_audit("admin.logout", &jmeno, "", &ip_text, true, "")
    })
    .await?;

    let mut hlavicky = HeaderMap::new();
    hlavicky.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE_SESSION}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        ))
        .unwrap_or(HeaderValue::from_static("")),
    );
    Ok((hlavicky, Json(Ok2::default())))
}

/// `GET /admin/api/v1/me` — kdo je přihlášený, včetně CSRF tokenu.
///
/// Token se vrací schválně: po obnovení stránky ho prohlížeč v paměti
/// nemá a bez něj by se nedalo nic změnit. Cizí stránka si odpověď
/// přečíst nemůže — neposíláme žádné hlavičky CORS, takže ji prohlížeč
/// nepustí k obsahu. Session cookie má navíc `SameSite=Strict`.
async fn kdo_jsem(
    State(stav): State<Stav>,
    spravce: Spravce,
) -> Odpoved<Json<AdminSessionResponse>> {
    let store = stav.store.clone();
    let token = spravce.session_token.clone();
    let principal = spravce.principal.clone();
    let session = blok(move || {
        store
            .session(&token)?
            .ok_or_else(|| AdError::new(ErrorCode::SessionExpired, "přihlášení vypršelo"))
    })
    .await?;
    Ok(Json(AdminSessionResponse {
        principal,
        csrf_token: session.1,
        expires_at: ad_core::nyni() + time::Duration::minutes(PLATNOST_SESSION_MIN),
    }))
}

// =======================================================================
// Přehled
// =======================================================================

async fn stav_serveru(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<StatusResponse>> {
    let store = stav.store.clone();
    let cfg = stav.config.clone();
    let uptime = stav.start.elapsed().as_secs();
    let cesty = stav.cesty.clone();

    let odpoved = blok(move || {
        let stage = store.stav()?;
        let role = store.role()?;
        let domena = store.domena()?;
        let pocty = store.pocty()?;
        let otisk = store.nastaveni(crate::store::schema::nastaveni::CA_FINGERPRINT)?;

        let mut alerts = Vec::new();
        match stage {
            ServerStage::Fresh => alerts.push(Alert {
                code: "install_roles".into(),
                level: AlertLevel::Warning,
                title: "Přidat role a funkce".into(),
                detail: "Server zatím nemá žádnou roli. Začni průvodcem Přidat role a funkce."
                    .into(),
                action: Some("#/role".into()),
            }),
            ServerStage::RolesInstalled => {
                if role.directory {
                    alerts.push(Alert {
                        code: "promote_pending".into(),
                        level: AlertLevel::Warning,
                        title: "Povýšit server na řadič domény".into(),
                        detail: "Role doménových služeb je nainstalovaná, doména ještě není."
                            .into(),
                        action: Some("#/povyseni".into()),
                    });
                }
                if !role.dns {
                    alerts.push(Alert {
                        code: "dns_role_missing".into(),
                        level: AlertLevel::Info,
                        title: "Role DNS není nainstalovaná".into(),
                        detail: "Bez DNS si klienti doménu nenajdou podle jména.".into(),
                        action: Some("#/role".into()),
                    });
                }
            }
            ServerStage::DomainController => {
                if pocty.locked_users > 0 {
                    alerts.push(Alert {
                        code: "locked_users".into(),
                        level: AlertLevel::Info,
                        title: format!("Zamčené účty: {}", pocty.locked_users),
                        detail: "Účty se odemknou samy po uplynutí doby, nebo je odemkni ručně."
                            .into(),
                        action: Some("#/uzivatele?zamcene=1".into()),
                    });
                }
                if pocty.computers == 0 {
                    alerts.push(Alert {
                        code: "no_computers".into(),
                        level: AlertLevel::Info,
                        title: "Zatím není připojený žádný počítač".into(),
                        detail: "Na klientu spusť: ad-client join --server ... --fingerprint ..."
                            .into(),
                        action: None,
                    });
                }
            }
        }

        let mut listeners = vec![Listener {
            name: "admin".into(),
            address: cfg.admin.bind.to_string(),
            tls: cfg.admin.tls,
            running: true,
        }];
        let pki_je = crate::pki::SouboryPki::v(&cesty.pki()).existuji();
        listeners.push(Listener {
            name: "domain-api".into(),
            address: cfg.domain_api.bind.to_string(),
            tls: true,
            running: pki_je,
        });
        if cfg.dns.enabled {
            listeners.push(Listener {
                name: "dns".into(),
                address: cfg.dns.bind.to_string(),
                tls: false,
                // DNS server přijde ve fázi 4.
                running: false,
            });
        }

        Ok(StatusResponse {
            product: PRODUKT.to_string(),
            version: ad_core::VERZE.to_string(),
            stage,
            roles: role,
            domain: domena,
            counts: pocty,
            alerts,
            listeners,
            ca_fingerprint_sha256: otisk,
            uptime_seconds: uptime,
            hostname: super::hostname_stroje(),
            os: super::popis_os(),
            server_time: ad_core::nyni(),
        })
    })
    .await?;
    Ok(Json(odpoved))
}

async fn audit(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<EventsQuery>,
) -> Odpoved<Json<Page<AuditEvent>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.audit(&q)).await?))
}

// =======================================================================
// Role a povýšení
// =======================================================================

async fn nainstaluj_role(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<InstallRolesRequest>,
) -> Odpoved<Json<InstalledRoles>> {
    if !req.consent {
        return Err(Chyba(AdError::bad_request("bez souhlasu (consent) se nic neinstaluje")));
    }
    if !req.directory && !req.dns {
        return Err(Chyba(AdError::bad_request("nevybral jsi žádnou roli")));
    }
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let role = blok(move || {
        use crate::store::schema::nastaveni;
        if req.directory {
            store.nastav_bool(nastaveni::ROLE_DIRECTORY, true)?;
        }
        if req.dns {
            store.nastav_bool(nastaveni::ROLE_DNS, true)?;
        }
        store.zapis_audit(
            "roles.install",
            &jmeno,
            "",
            &ip_text,
            true,
            &format!("directory={}, dns={}", req.directory, req.dns),
        )?;
        store.role()
    })
    .await?;
    Ok(Json(role))
}

async fn precheck(
    State(stav): State<Stav>,
    _s: Spravce,
    Telo(req): Telo<PromoteRequest>,
) -> Odpoved<Json<PrecheckResponse>> {
    let store = stav.store.clone();
    let cesty = stav.cesty.clone();
    Ok(Json(blok(move || crate::domain::precheck(&store, &cesty, &req)).await?))
}

async fn povys(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<PromoteRequest>,
) -> Odpoved<Json<PromoteResponse>> {
    let store = stav.store.clone();
    let cesty = stav.cesty.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let odpoved =
        blok(move || crate::domain::promote(&store, &cesty, &req, &jmeno, &ip_text)).await?;

    // Teď existuje certifikát → nastartujeme doménové API.
    stav.restart_tls.send_modify(|v| *v += 1);
    tracing::info!(domena = %odpoved.domain.dns_name, "doména vytvořena");
    Ok(Json(odpoved))
}

async fn zrus_domenu(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<DemoteRequest>,
) -> Odpoved<Json<Ok2>> {
    spravce.vyzaduj_domenoveho().map_err(Chyba)?;
    let store = stav.store.clone();
    let cesty = stav.cesty.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        crate::domain::demote(
            &store,
            &cesty,
            &req.confirm_domain_name,
            req.wipe_database,
            &jmeno,
            &ip_text,
        )
    })
    .await?;
    stav.restart_tls.send_modify(|v| *v += 1);
    Ok(Json(Ok2::default()))
}

// =======================================================================
// Organizační jednotky
// =======================================================================

async fn seznam_ou(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<Vec<Ou>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.seznam_ou()).await?))
}

async fn strom(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<TreeNode>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.strom_ou()).await?))
}

async fn ou_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ou>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.ou(id)).await?))
}

async fn vytvor_ou(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<CreateOuRequest>,
) -> Odpoved<(StatusCode, Json<Ou>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let ou = blok(move || {
        let o = store.vytvor_ou(&req)?;
        store.zapis_audit("ou.create", &jmeno, &format!("ou:{}", o.path), &ip_text, true, "")?;
        Ok(o)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(ou)))
}

#[derive(serde::Deserialize)]
struct UpravOu {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    protected: Option<bool>,
}

async fn uprav_ou(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<UpravOu>,
) -> Odpoved<Json<Ou>> {
    let store = stav.store.clone();
    Ok(Json(
        blok(move || {
            store.uprav_ou_popis(id, req.description.as_deref().unwrap_or(""), req.protected)
        })
        .await?,
    ))
}

async fn prejmenuj_ou(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<RenameRequest>,
) -> Odpoved<Json<Ou>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.prejmenuj_ou(id, &req.new_name)).await?))
}

async fn smaz_ou(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let o = store.ou(id)?;
        store.smaz_ou(id)?;
        store.zapis_audit("ou.delete", &jmeno, &format!("ou:{}", o.path), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

// =======================================================================
// Uživatelé
// =======================================================================

async fn seznam_uzivatelu(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<ListQuery>,
) -> Odpoved<Json<Page<User>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.seznam_uzivatelu(&q)).await?))
}

async fn uzivatel_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<User>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.uzivatel(id)).await?))
}

async fn vytvor_uzivatele(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<CreateUserRequest>,
) -> Odpoved<(StatusCode, Json<User>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let u = blok(move || {
        let u = store.vytvor_uzivatele(&req)?;
        store.zapis_audit(
            "user.create",
            &jmeno,
            &format!("user:{}", u.sam_account_name),
            &ip_text,
            true,
            "",
        )?;
        Ok(u)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(u)))
}

async fn uprav_uzivatele(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<UpdateUserRequest>,
) -> Odpoved<Json<User>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    Ok(Json(
        blok(move || {
            let u = store.uprav_uzivatele(id, &req)?;
            store.zapis_audit(
                "user.update",
                &jmeno,
                &format!("user:{}", u.sam_account_name),
                &ip_text,
                true,
                "",
            )?;
            Ok(u)
        })
        .await?,
    ))
}

async fn nastav_heslo(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<SetPasswordRequest>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let u = store.uzivatel(id)?;
        store.nastav_heslo(
            id,
            req.new_password.odhal(),
            req.must_change_password,
            req.skip_history_check,
        )?;
        // Do auditu jde jen to, že se heslo změnilo. Nikdy ne heslo.
        store.zapis_audit(
            "user.password.set",
            &jmeno,
            &format!("user:{}", u.sam_account_name),
            &ip_text,
            true,
            if req.must_change_password { "vynucena změna při přihlášení" } else { "" },
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn odemkni(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let u = store.uzivatel(id)?;
        store.odemkni_uzivatele(id)?;
        store.zapis_audit(
            "user.unlock",
            &jmeno,
            &format!("user:{}", u.sam_account_name),
            &ip_text,
            true,
            "",
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn presun_uzivatele(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<MoveRequest>,
) -> Odpoved<Json<User>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.presun_uzivatele(id, req.target_ou_id)).await?))
}

async fn smaz_uzivatele(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let sam = store.smaz_uzivatele(id)?;
        store.zapis_audit("user.delete", &jmeno, &format!("user:{sam}"), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn skupiny_uzivatele(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Vec<String>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.skupiny_uzivatele(id)).await?))
}

// =======================================================================
// Skupiny
// =======================================================================

async fn seznam_skupin(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<ListQuery>,
) -> Odpoved<Json<Page<Group>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.seznam_skupin(&q)).await?))
}

async fn skupina_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Group>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.skupina(id)).await?))
}

async fn vytvor_skupinu(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<CreateGroupRequest>,
) -> Odpoved<(StatusCode, Json<Group>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let g = blok(move || {
        let g = store.vytvor_skupinu(&req)?;
        store.zapis_audit(
            "group.create",
            &jmeno,
            &format!("group:{}", g.name),
            &ip_text,
            true,
            "",
        )?;
        Ok(g)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(g)))
}

async fn smaz_skupinu(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let n = store.smaz_skupinu(id)?;
        store.zapis_audit("group.delete", &jmeno, &format!("group:{n}"), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

#[derive(serde::Deserialize)]
struct UpravSkupinu {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

async fn uprav_skupinu(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<UpravSkupinu>,
) -> Odpoved<Json<Group>> {
    let store = stav.store.clone();
    Ok(Json(
        blok(move || store.uprav_skupinu(id, req.name.as_deref(), req.description.as_deref()))
            .await?,
    ))
}

async fn presun_skupinu(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<MoveRequest>,
) -> Odpoved<Json<Group>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.presun_skupinu(id, req.target_ou_id)).await?))
}

async fn presun_pocitac(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<MoveRequest>,
) -> Odpoved<Json<Computer>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.presun_pocitac(id, req.target_ou_id)).await?))
}

async fn clenove(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Vec<GroupMember>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.clenove(id)).await?))
}

async fn pridej_cleny(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<MembersRequest>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let pocet = store.pridej_cleny(id, &req.members)?;
        let g = store.skupina(id)?;
        store.zapis_audit(
            "group.members.add",
            &jmeno,
            &format!("group:{}", g.name),
            &ip_text,
            true,
            &format!("přidáno {pocet}"),
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn odeber_cleny(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<MembersRequest>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let pocet = store.odeber_cleny(id, &req.members)?;
        let g = store.skupina(id)?;
        store.zapis_audit(
            "group.members.remove",
            &jmeno,
            &format!("group:{}", g.name),
            &ip_text,
            true,
            &format!("odebráno {pocet}"),
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

// =======================================================================
// Počítače
// =======================================================================

async fn seznam_pocitacu(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<ListQuery>,
) -> Odpoved<Json<Page<Computer>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.seznam_pocitacu(&q)).await?))
}

async fn pocitac_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Computer>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.pocitac(id)).await?))
}

async fn smaz_pocitac(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        store.zrus_tokeny_pocitace(id)?;
        let n = store.smaz_pocitac(id)?;
        store.zapis_audit("computer.delete", &jmeno, &format!("computer:{n}"), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

// =======================================================================
// Zásady
// =======================================================================

async fn seznam_gpo(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<ListQuery>,
) -> Odpoved<Json<Page<Gpo>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.seznam_gpo(&q)).await?))
}

async fn gpo_detail(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Gpo>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.gpo(id)).await?))
}

async fn vytvor_gpo(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Telo(req): Telo<CreateGpoRequest>,
) -> Odpoved<(StatusCode, Json<Gpo>)> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    let g = blok(move || {
        let g = store.vytvor_gpo(&req)?;
        store.zapis_audit("gpo.create", &jmeno, &format!("gpo:{}", g.name), &ip_text, true, "")?;
        Ok(g)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(g)))
}

async fn uprav_gpo(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
    Telo(req): Telo<UpdateGpoRequest>,
) -> Odpoved<Json<Gpo>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    Ok(Json(
        blok(move || {
            let g = store.uprav_gpo(id, &req)?;
            store.zapis_audit(
                "gpo.update",
                &jmeno,
                &format!("gpo:{}", g.name),
                &ip_text,
                true,
                "",
            )?;
            Ok(g)
        })
        .await?,
    ))
}

async fn smaz_gpo(
    State(stav): State<Stav>,
    spravce: Spravce,
    ip: KlientIp,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let jmeno = spravce.jmeno();
    let ip_text = ip.text();
    blok(move || {
        let n = store.smaz_gpo(id)?;
        store.zapis_audit("gpo.delete", &jmeno, &format!("gpo:{n}"), &ip_text, true, "")
    })
    .await?;
    Ok(Json(Ok2::default()))
}

async fn pripoj_gpo(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
    Telo(req): Telo<LinkGpoRequest>,
) -> Odpoved<(StatusCode, Json<GpoLink>)> {
    let store = stav.store.clone();
    let l = blok(move || store.pripoj_gpo(id, &req)).await?;
    Ok((StatusCode::CREATED, Json(l)))
}

async fn odpoj_gpo(
    State(stav): State<Stav>,
    _s: Spravce,
    Path(id): Path<i64>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    blok(move || store.odpoj_gpo(id)).await?;
    Ok(Json(Ok2::default()))
}

async fn odkazy(State(stav): State<Stav>, _s: Spravce) -> Odpoved<Json<Vec<GpoLink>>> {
    let store = stav.store.clone();
    Ok(Json(blok(move || store.odkazy_gpo(None)).await?))
}

#[derive(serde::Deserialize)]
struct DotazOu {
    #[serde(default)]
    ou_id: Option<i64>,
}

async fn efektivni_zasada(
    State(stav): State<Stav>,
    _s: Spravce,
    Query(q): Query<DotazOu>,
) -> Odpoved<Json<EffectivePolicyResponse>> {
    let store = stav.store.clone();
    Ok(Json(
        blok(move || {
            Ok(EffectivePolicyResponse {
                policy: store.efektivni_zasada(q.ou_id)?,
                serial: store.serial_zasad()?,
            })
        })
        .await?,
    ))
}
