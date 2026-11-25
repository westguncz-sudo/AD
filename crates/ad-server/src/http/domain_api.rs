//! Doménové API — `/api/v1/...`, vždy přes TLS. S tím mluví `ad-client`.
//!
//! **Co tady není a nebude:** žádný koncový bod, který by klientovi
//! řekl, aby něco spustil. Klient dostává jen data.

use super::error::{Chyba, Odpoved, Telo};
use super::extract::{KlientIp, Stroj};
use super::{blok, Stav};
use ad_core::model::ServerStage;
use ad_core::proto::*;
use ad_core::{names, secret, AdError, ErrorCode};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};

pub fn routes() -> Router<Stav> {
    Router::new()
        .route("/api/v1/hello", get(hello))
        .route("/api/v1/join", post(join))
        .route("/api/v1/unjoin", post(unjoin))
        .route("/api/v1/machine/token", post(token_pocitace))
        .route("/api/v1/machine/policy", get(zasady_pocitace))
        .route("/api/v1/auth/logon", post(logon))
        .route("/api/v1/auth/change-password", post(zmena_hesla))
        .route("/api/v1/auth/logoff", post(logoff))
        .route("/api/v1/heartbeat", post(heartbeat))
}

/// Ověří, že klient mluví naší verzí protokolu.
fn zkontroluj_protokol(hlavicky: &HeaderMap) -> Result<(), Chyba> {
    // Chybějící hlavička bereme jako aktuální verzi — ať se dá API
    // vyzkoušet jednoduchým curl bez dalších parametrů.
    let Some(v) = hlavicky.get(HLAVICKA_PROTO).and_then(|v| v.to_str().ok()) else {
        return Ok(());
    };
    let verze: u32 = v.trim().parse().map_err(|_| {
        Chyba(AdError::new(
            ErrorCode::ProtoVersionUnsupported,
            format!("hlavička {HLAVICKA_PROTO} není číslo"),
        ))
    })?;
    zkontroluj_verzi(verze).map_err(Chyba)
}

// =======================================================================
// Bez přihlášení
// =======================================================================

/// `GET /api/v1/hello` — jediný koncový bod bez přihlášení.
/// Záměrně neprozrazuje počty objektů ani jména.
async fn hello(State(stav): State<Stav>, hlavicky: HeaderMap) -> Odpoved<Json<HelloResponse>> {
    zkontroluj_protokol(&hlavicky)?;
    let store = stav.store.clone();
    let odpoved = blok(move || {
        let stage = store.stav()?;
        let domena = store.domena()?.map(|d| DomainPublic {
            dns_name: d.dns_name,
            short_name: d.short_name,
            dc_fqdn: d.dc_fqdn,
        });
        let otisk =
            store.nastaveni(crate::store::schema::nastaveni::CA_FINGERPRINT)?.unwrap_or_default();
        Ok(HelloResponse {
            product: PRODUKT.to_string(),
            version: ad_core::VERZE.to_string(),
            proto_min: PROTO_VERZE_MIN,
            proto_max: PROTO_VERZE,
            stage,
            domain: domena,
            ca_fingerprint_sha256: otisk,
            server_time: ad_core::nyni(),
        })
    })
    .await?;
    Ok(Json(odpoved))
}

/// `POST /api/v1/join` — připojení počítače do domény.
///
/// Autentizace heslem správce domény. Posílá se jednou; server si ho
/// neukládá a vrátí tajemství počítačového účtu.
async fn join(
    State(stav): State<Stav>,
    ip: KlientIp,
    hlavicky: HeaderMap,
    Telo(req): Telo<JoinRequest>,
) -> Odpoved<(StatusCode, Json<JoinResponse>)> {
    zkontroluj_protokol(&hlavicky)?;
    let store = stav.store.clone();
    let cesty = stav.cesty.clone();
    let ip_text = ip.text();
    let skutecna_ip = ip.0;

    let odpoved = blok(move || {
        if store.stav()? != ServerStage::DomainController {
            return Err(AdError::new(
                ErrorCode::DomainNotCreated,
                "server ještě není řadičem domény",
            ));
        }
        let domena = store.domena_nebo_chyba()?;

        // 1. Ověříme správce domény.
        let spravce =
            store.over_spravce(&req.admin_username, req.admin_password.odhal(), &ip_text)?;

        // 2. Jméno počítače.
        let jmeno = names::validuj_jmeno_pocitace(&req.computer_name)?;
        if store.pocitac_podle_jmena(&jmeno)?.is_some() {
            return Err(AdError::new(
                ErrorCode::MachineAlreadyJoined,
                format!(
                    "počítač {jmeno} už v doméně je — nejdřív ho odpoj \
                     nebo smaž ve správě"
                ),
            ));
        }

        // 3. OU. Výchozí je `Computers`.
        let ou_id = match req.ou_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(cesta) => {
                let c =
                    if cesta.starts_with('/') { cesta.to_string() } else { format!("/{cesta}") };
                Some(
                    store
                        .ou_podle_cesty(&c)?
                        .ok_or_else(|| AdError::not_found(format!("OU {c} neexistuje")))?
                        .id,
                )
            }
            None => store.ou_podle_cesty("/Computers")?.map(|o| o.id),
        };

        // 4. IP adresa. Klient si ji smí navrhnout, ale platí ta,
        //    ze které spojení opravdu přišlo.
        let navrzena = req.ip_address.as_deref().unwrap_or("");
        let pouzita = skutecna_ip.to_string();
        if !navrzena.is_empty() && navrzena != pouzita {
            store.zapis_audit(
                "computer.join.ip_mismatch",
                &spravce.sam_account_name,
                &format!("computer:{jmeno}"),
                &ip_text,
                true,
                &format!(
                    "klient hlásil {}, spojení přišlo z {}",
                    crate::store::objects::omez_text(navrzena, 45),
                    pouzita
                ),
            )?;
        }

        let (pocitac, tajemstvi) =
            store.vytvor_pocitac(&jmeno, ou_id, "", &req.os_name, &req.os_version, &pouzita)?;

        // 5. DNS záznamy počítače (zapisují se, i když DNS server
        //    poběží až od fáze 4).
        if let Err(e) = store.zapis_dns_pocitace(&pocitac, skutecna_ip) {
            tracing::warn!(chyba = %e, "DNS záznamy počítače se nepodařilo zapsat");
        }

        let ca_pem = crate::pki::ca_pem(&cesty.pki())?;
        let otisk = secret::otisk_z_pem(&ca_pem)?;

        store.zapis_audit(
            "computer.join",
            &spravce.sam_account_name,
            &format!("computer:{}", pocitac.name),
            &ip_text,
            true,
            &format!("OS: {}", crate::store::objects::omez_text(&req.os_name, 40)),
        )?;

        Ok(JoinResponse {
            machine_id: pocitac.guid,
            machine_secret: tajemstvi,
            computer: pocitac,
            domain: DomainPublic {
                dns_name: domena.dns_name,
                short_name: domena.short_name,
                dc_fqdn: domena.dc_fqdn,
            },
            dns_servers: vec![domena.dc_ip],
            ca_cert_pem: ca_pem,
            ca_fingerprint_sha256: otisk,
            policy_poll_seconds: INTERVAL_ZASAD_S,
        })
    })
    .await?;
    Ok((StatusCode::CREATED, Json(odpoved)))
}

/// `POST /api/v1/machine/token` — tajemství za krátkodobý token.
async fn token_pocitace(
    State(stav): State<Stav>,
    ip: KlientIp,
    hlavicky: HeaderMap,
    Telo(req): Telo<MachineTokenRequest>,
) -> Odpoved<Json<MachineTokenResponse>> {
    zkontroluj_protokol(&hlavicky)?;
    let store = stav.store.clone();
    let ip_text = ip.text();

    let odpoved = blok(move || {
        store.zkontroluj_rychlost(&ip_text)?;
        let Some(p) = store.pocitac_podle_guid(req.machine_id)? else {
            // Stejně spočítáme Argon2id, ať odpověď trvá stejně dlouho.
            let _ = ad_core::password::over(
                ad_core::password::haš_na_zdržení(),
                req.machine_secret.odhal(),
            );
            return Err(AdError::new(ErrorCode::MachineUnknown, "takový počítačový účet neznám"));
        };
        if !p.enabled {
            return Err(AdError::new(ErrorCode::AccountDisabled, "počítačový účet je vypnutý"));
        }
        let hash = store.hash_tajemstvi_pocitace(p.id)?;
        if !ad_core::password::over(&hash, req.machine_secret.odhal())? {
            store.zapis_audit(
                "machine.token.failed",
                &format!("machine:{}", p.name),
                "",
                &ip_text,
                false,
                "tajemství nesouhlasí",
            )?;
            return Err(AdError::new(
                ErrorCode::MachineSecretInvalid,
                "tajemství počítačového účtu nesouhlasí — připoj počítač znovu",
            ));
        }
        let (token, do_kdy) = store.vytvor_token_pocitace(p.id)?;
        store.oznac_videni(p.id, &ip_text, "", "")?;
        Ok(MachineTokenResponse {
            token,
            expires_at: do_kdy,
            policy_poll_seconds: INTERVAL_ZASAD_S,
        })
    })
    .await?;
    Ok(Json(odpoved))
}

/// `POST /api/v1/unjoin` — odpojení z domény.
async fn unjoin(
    State(stav): State<Stav>,
    stroj: Stroj,
    ip: KlientIp,
    Telo(req): Telo<UnjoinRequest>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let ip_text = ip.text();
    let id = stroj.computer.id;
    let jmeno = stroj.computer.name.clone();

    blok(move || {
        store.zrus_tokeny_pocitace(id)?;
        if req.remove_dns {
            if let Err(e) = store.smaz_dns_pocitace(&jmeno) {
                tracing::warn!(chyba = %e, "DNS záznamy počítače se nepodařilo smazat");
            }
        }
        store.smaz_pocitac(id)?;
        store.zapis_audit(
            "computer.unjoin",
            &format!("machine:{jmeno}"),
            &format!("computer:{jmeno}"),
            &ip_text,
            true,
            "",
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

/// `GET /api/v1/machine/policy` — zásady pro počítač.
async fn zasady_pocitace(
    State(stav): State<Stav>,
    stroj: Stroj,
    hlavicky: HeaderMap,
) -> Odpoved<axum::response::Response> {
    use axum::response::IntoResponse;
    let store = stav.store.clone();
    let ou = stroj.computer.ou_id;

    let (zasada, serial) = blok(move || {
        let z = store.efektivni_zasada(ou)?;
        let s = store.serial_zasad()?;
        Ok((z, s))
    })
    .await?;

    // Když klient už má aktuální verzi, nemusíme posílat nic.
    if let Some(etag) = hlavicky.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if etag.trim_matches('"') == serial.to_string() {
            return Ok(StatusCode::NOT_MODIFIED.into_response());
        }
    }

    let odpoved = PolicyResponse {
        policy: zasada,
        serial,
        generated_at: ad_core::nyni(),
        policy_poll_seconds: INTERVAL_ZASAD_S,
    };
    Ok(([(header::ETAG, format!("\"{serial}\""))], Json(odpoved)).into_response())
}

/// `POST /api/v1/auth/logon` — přihlášení doménového uživatele
/// v programu (ne do systému).
async fn logon(
    State(stav): State<Stav>,
    stroj: Stroj,
    ip: KlientIp,
    hlavicky: HeaderMap,
    Telo(req): Telo<LogonRequest>,
) -> Odpoved<Json<LogonResponse>> {
    zkontroluj_protokol(&hlavicky)?;
    let store = stav.store.clone();
    let ip_text = ip.text();
    let computer_id = stroj.computer.id;

    let odpoved = blok(move || {
        let p = store.prihlas(&req.username, req.password.odhal(), Some(computer_id), &ip_text)?;
        let skupiny = store.skupiny_uzivatele(p.user.id)?;
        let cesta_ou = match p.user.ou_id {
            None => "/".to_string(),
            Some(id) => store.ou(id).map(|o| o.path).unwrap_or_else(|_| "/".to_string()),
        };
        let serial = store.serial_zasad()?;
        // Zásady počítá server pro OU uživatele.
        Ok(LogonResponse {
            user: UserPublic {
                sam_account_name: p.user.sam_account_name.clone(),
                upn: p.user.upn.clone(),
                display_name: p.user.display_name.clone(),
                sid: p.user.sid,
                groups: skupiny,
                ou_path: cesta_ou,
            },
            ticket: p.ticket,
            ticket_expires_at: p.ticket_do,
            policy: p.policy,
            policy_serial: serial,
            must_change_password: p.must_change_password,
            password_expires_in_days: p.password_expires_in_days,
        })
    })
    .await?;
    Ok(Json(odpoved))
}

async fn zmena_hesla(
    State(stav): State<Stav>,
    _stroj: Stroj,
    ip: KlientIp,
    Telo(req): Telo<ChangePasswordRequest>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let ip_text = ip.text();
    blok(move || {
        store.zmen_heslo(
            &req.username,
            req.old_password.odhal(),
            req.new_password.odhal(),
            &ip_text,
        )
    })
    .await?;
    Ok(Json(Ok2::default()))
}

#[derive(serde::Deserialize)]
struct Logoff {
    ticket: secret::Tajne,
}

async fn logoff(
    State(stav): State<Stav>,
    _stroj: Stroj,
    Telo(req): Telo<Logoff>,
) -> Odpoved<Json<Ok2>> {
    let store = stav.store.clone();
    let t = req.ticket.odhal().to_string();
    blok(move || store.smaz_ticket(&t)).await?;
    Ok(Json(Ok2::default()))
}

async fn heartbeat(
    State(stav): State<Stav>,
    stroj: Stroj,
    ip: KlientIp,
    Telo(req): Telo<HeartbeatRequest>,
) -> Odpoved<Json<HeartbeatResponse>> {
    let store = stav.store.clone();
    let ip_text = ip.text();
    let id = stroj.computer.id;
    let odpoved = blok(move || {
        store.oznac_videni(id, &ip_text, &req.os_name, &req.os_version)?;
        let serial = store.serial_zasad()?;
        Ok(HeartbeatResponse {
            policy_changed: serial != req.policy_serial,
            policy_serial: serial,
            server_time: ad_core::nyni(),
        })
    })
    .await?;
    Ok(Json(odpoved))
}
