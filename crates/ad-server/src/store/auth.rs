//! Přihlašování, session, tokeny a zamykání účtů.
//!
//! Pravidla, která tady platí bez výjimky:
//! * tokeny se v databázi ukládají jen jako SHA-256,
//! * neexistující účet se ověřuje proti náhodnému hašování, aby odpověď
//!   trvala stejně dlouho (nedá se zjistit, kdo v doméně je),
//! * odpověď je vždy `invalid_credentials` — nikdy „špatné heslo“
//!   versus „takový uživatel není“.

use super::{cas_do_db, cas_z_db, db_chyba, Store};
use ad_core::ids::rid;
use ad_core::model::{Computer, User};
use ad_core::policy::EffectivePolicy;
use ad_core::proto::{AdminPrincipal, AdminSessionResponse};
use ad_core::{names, password, proto, secret, AdError, ErrorCode, Result};
use rusqlite::{params, OptionalExtension};
use time::{Duration, OffsetDateTime};

/// Kolik neúspěšných přihlášení z jedné IP ještě pustíme.
pub const LIMIT_POKUSU_IP: i64 = 10;
/// V jakém okně se pokusy z IP počítají (minuty).
pub const OKNO_POKUSU_MIN: i64 = 5;

/// Co se vrátí po úspěšném přihlášení uživatele.
#[derive(Debug)]
pub struct Prihlaseni {
    pub user: User,
    pub ticket: secret::Tajne,
    pub ticket_do: OffsetDateTime,
    pub policy: EffectivePolicy,
    pub must_change_password: bool,
    pub password_expires_in_days: Option<u16>,
}

impl Store {
    // ===================================================================
    // Omezení rychlosti podle IP
    // ===================================================================

    /// Projde, jen pokud z téhle IP nepřišlo příliš mnoho chyb.
    ///
    /// Tohle je nad zamykáním účtů: zamykání chrání jeden účet,
    /// tohle chrání doménu před hádáním hesel napříč účty.
    pub fn zkontroluj_rychlost(&self, ip: &str) -> Result<()> {
        let hranice = cas_do_db(ad_core::nyni() - Duration::minutes(OKNO_POKUSU_MIN));
        let c = self.lock();
        // Starší záznamy zahodíme, ať tabulka neroste.
        let stare = cas_do_db(ad_core::nyni() - Duration::hours(24));
        c.execute("DELETE FROM login_attempts WHERE at < ?1", [&stare]).map_err(db_chyba)?;
        let pocet: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM login_attempts WHERE ip = ?1 AND at >= ?2",
                params![ip, hranice],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        if pocet >= LIMIT_POKUSU_IP {
            return Err(AdError::new(
                ErrorCode::RateLimited,
                format!(
                    "z této adresy přišlo příliš mnoho neúspěšných přihlášení, \
                     zkus to za {OKNO_POKUSU_MIN} minut"
                ),
            ));
        }
        Ok(())
    }

    fn zapis_neuspech(&self, ip: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO login_attempts(ip, at) VALUES (?1, ?2)",
            params![ip, cas_do_db(ad_core::nyni())],
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    // ===================================================================
    // Jednorázový token pro první přihlášení
    // ===================================================================

    /// Zajistí, že existuje token pro první přihlášení do správy.
    /// Vrátí ho v otevřené podobě, **jen když ho právě vytvořila**.
    pub fn zajisti_setup_token(&self) -> Result<Option<String>> {
        use super::schema::nastaveni::SETUP_TOKEN_HASH;
        if self.domena()?.is_some() {
            // Doména existuje → přihlašuje se doménový správce.
            self.zrus_nastaveni(SETUP_TOKEN_HASH)?;
            return Ok(None);
        }
        if self.nastaveni(SETUP_TOKEN_HASH)?.is_some() {
            return Ok(None);
        }
        let token = secret::novy_token();
        self.nastav(SETUP_TOKEN_HASH, &secret::hash_tokenu(&token))?;
        Ok(Some(token))
    }

    /// Ověří jednorázový token. Platí jen dokud doména neexistuje.
    pub fn over_setup_token(&self, token: &str) -> Result<bool> {
        use super::schema::nastaveni::SETUP_TOKEN_HASH;
        if self.domena()?.is_some() {
            return Ok(false);
        }
        let Some(ulozeny) = self.nastaveni(SETUP_TOKEN_HASH)? else {
            return Ok(false);
        };
        Ok(secret::rovno_v_konstantnim_case(&ulozeny, &secret::hash_tokenu(token)))
    }

    // ===================================================================
    // Session správce
    // ===================================================================

    /// Vytvoří session správce. Vrací token do cookie a tělo odpovědi.
    pub fn vytvor_session(
        &self,
        principal: &AdminPrincipal,
        ip: &str,
    ) -> Result<(secret::Tajne, AdminSessionResponse)> {
        let token = secret::novy_token();
        let csrf = secret::novy_token();
        let nyni = ad_core::nyni();
        let do_kdy = nyni + Duration::minutes(proto::PLATNOST_SESSION_MIN);
        let json = serde_json::to_string(principal)
            .map_err(|e| AdError::internal(format!("principal: {e}")))?;

        let c = self.lock();
        c.execute(
            "INSERT INTO admin_sessions(token_hash, principal_json, csrf_token,
                 created_at, expires_at, created_ip)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                secret::hash_tokenu(&token),
                json,
                csrf,
                cas_do_db(nyni),
                cas_do_db(do_kdy),
                ip
            ],
        )
        .map_err(db_chyba)?;
        // Úklid starých session.
        c.execute("DELETE FROM admin_sessions WHERE expires_at < ?1", [cas_do_db(nyni)])
            .map_err(db_chyba)?;

        Ok((
            secret::Tajne::new(token),
            AdminSessionResponse {
                principal: principal.clone(),
                csrf_token: csrf,
                expires_at: do_kdy,
            },
        ))
    }

    /// Najde session podle tokenu z cookie. Zároveň jí prodlouží platnost.
    pub fn session(&self, token: &str) -> Result<Option<(AdminPrincipal, String)>> {
        let hash = secret::hash_tokenu(token);
        let nyni = ad_core::nyni();
        let c = self.lock();
        let nalezeno: Option<(String, String, String)> = c
            .query_row(
                "SELECT principal_json, csrf_token, expires_at FROM admin_sessions
                 WHERE token_hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db_chyba)?;
        let Some((json, csrf, do_kdy)) = nalezeno else {
            return Ok(None);
        };
        if cas_z_db(&do_kdy)? < nyni {
            c.execute("DELETE FROM admin_sessions WHERE token_hash = ?1", [&hash])
                .map_err(db_chyba)?;
            return Ok(None);
        }
        // Posuneme vypršení — session vyprší po hodině **nečinnosti**.
        c.execute(
            "UPDATE admin_sessions SET expires_at = ?1 WHERE token_hash = ?2",
            params![cas_do_db(nyni + Duration::minutes(proto::PLATNOST_SESSION_MIN)), &hash],
        )
        .map_err(db_chyba)?;

        let principal: AdminPrincipal = serde_json::from_str(&json)
            .map_err(|e| AdError::internal(format!("principal v databázi: {e}")))?;
        Ok(Some((principal, csrf)))
    }

    pub fn smaz_session(&self, token: &str) -> Result<()> {
        let c = self.lock();
        c.execute("DELETE FROM admin_sessions WHERE token_hash = ?1", [secret::hash_tokenu(token)])
            .map_err(db_chyba)?;
        Ok(())
    }

    /// Zruší všechny session — používá se po povýšení na řadič domény,
    /// kdy přestává platit přihlášení jednorázovým tokenem.
    pub fn smaz_vsechny_session(&self) -> Result<()> {
        let c = self.lock();
        c.execute("DELETE FROM admin_sessions", []).map_err(db_chyba)?;
        Ok(())
    }

    // ===================================================================
    // Tokeny počítačů
    // ===================================================================

    /// Vymění tajemství počítače za krátkodobý token.
    pub fn vytvor_token_pocitace(
        &self,
        computer_id: i64,
    ) -> Result<(secret::Tajne, OffsetDateTime)> {
        let token = secret::novy_token();
        let nyni = ad_core::nyni();
        let do_kdy = nyni + Duration::minutes(proto::PLATNOST_TOKENU_MIN);
        let c = self.lock();
        c.execute(
            "INSERT INTO machine_tokens(token_hash, computer_id, created_at, expires_at)
             VALUES (?1,?2,?3,?4)",
            params![secret::hash_tokenu(&token), computer_id, cas_do_db(nyni), cas_do_db(do_kdy)],
        )
        .map_err(db_chyba)?;
        c.execute("DELETE FROM machine_tokens WHERE expires_at < ?1", [cas_do_db(nyni)])
            .map_err(db_chyba)?;
        Ok((secret::Tajne::new(token), do_kdy))
    }

    /// Najde počítač podle tokenu z hlavičky `Authorization`.
    pub fn pocitac_podle_tokenu(&self, token: &str) -> Result<Option<Computer>> {
        let hash = secret::hash_tokenu(token);
        let nyni = ad_core::nyni();
        let id: Option<(i64, String)> = {
            let c = self.lock();
            c.query_row(
                "SELECT computer_id, expires_at FROM machine_tokens WHERE token_hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_chyba)?
        };
        let Some((computer_id, do_kdy)) = id else {
            return Ok(None);
        };
        if cas_z_db(&do_kdy)? < nyni {
            let c = self.lock();
            c.execute("DELETE FROM machine_tokens WHERE token_hash = ?1", [&hash])
                .map_err(db_chyba)?;
            return Ok(None);
        }
        let p = self.pocitac(computer_id)?;
        if !p.enabled {
            return Err(AdError::new(ErrorCode::AccountDisabled, "počítačový účet je vypnutý"));
        }
        Ok(Some(p))
    }

    /// Zneplatní všechny tokeny počítače (např. při odpojení z domény).
    pub fn zrus_tokeny_pocitace(&self, computer_id: i64) -> Result<()> {
        let c = self.lock();
        c.execute("DELETE FROM machine_tokens WHERE computer_id = ?1", [computer_id])
            .map_err(db_chyba)?;
        c.execute("DELETE FROM user_tickets WHERE computer_id = ?1", [computer_id])
            .map_err(db_chyba)?;
        Ok(())
    }

    // ===================================================================
    // Tickety uživatelů
    // ===================================================================

    /// Ticket se bude ověřovat u dalších dotazů za uživatele (fáze 5).
    #[allow(dead_code)]
    pub fn uzivatel_podle_ticketu(&self, token: &str) -> Result<Option<User>> {
        let hash = secret::hash_tokenu(token);
        let nalezeno: Option<(i64, String)> = {
            let c = self.lock();
            c.query_row(
                "SELECT user_id, expires_at FROM user_tickets WHERE token_hash = ?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_chyba)?
        };
        let Some((user_id, do_kdy)) = nalezeno else {
            return Ok(None);
        };
        if cas_z_db(&do_kdy)? < ad_core::nyni() {
            let c = self.lock();
            c.execute("DELETE FROM user_tickets WHERE token_hash = ?1", [&hash])
                .map_err(db_chyba)?;
            return Ok(None);
        }
        Ok(Some(self.uzivatel(user_id)?))
    }

    pub fn smaz_ticket(&self, token: &str) -> Result<()> {
        let c = self.lock();
        c.execute("DELETE FROM user_tickets WHERE token_hash = ?1", [secret::hash_tokenu(token)])
            .map_err(db_chyba)?;
        Ok(())
    }

    // ===================================================================
    // Přihlášení uživatele
    // ===================================================================

    /// Ověří jméno a heslo doménového uživatele.
    ///
    /// `computer_id` je počítač, ze kterého se přihlašuje (`None` jen
    /// u interního ověření správce). `ip` se zapisuje do auditu.
    pub fn prihlas(
        &self,
        prihlasovaci_jmeno: &str,
        heslo: &str,
        computer_id: Option<i64>,
        ip: &str,
    ) -> Result<Prihlaseni> {
        let domena = self.domena_nebo_chyba()?;
        self.zkontroluj_rychlost(ip)?;

        let (sam, zadana_domena) = names::rozdel_prihlaseni(prihlasovaci_jmeno);
        if let Some(d) = zadana_domena {
            let d = d.to_ascii_lowercase();
            if d != domena.dns_name.to_ascii_lowercase()
                && d != domena.short_name.to_ascii_lowercase()
            {
                self.zapis_neuspech(ip)?;
                self.zapis_audit(
                    "auth.logon.failed",
                    &omez(prihlasovaci_jmeno),
                    "",
                    ip,
                    false,
                    "jiná doména",
                )?;
                return Err(chyba_prihlaseni());
            }
        }
        let sam = sam.trim().to_ascii_lowercase();
        let uzivatel = self.uzivatel_podle_sam(&sam)?;

        // Neexistující účet: stejně spočítáme Argon2id, ať odpověď trvá
        // stejně dlouho jako u existujícího.
        let Some(u) = uzivatel else {
            let _ = password::over(password::haš_na_zdržení(), heslo);
            self.zapis_neuspech(ip)?;
            self.zapis_audit("auth.logon.failed", &omez(&sam), "", ip, false, "účet neexistuje")?;
            return Err(chyba_prihlaseni());
        };

        // Zamčení kontrolujeme před heslem — zamčený účet se nedá
        // „probudit“ ani správným heslem, dokud zamčení neskončí.
        if let Some(do_kdy) = u.locked_until {
            if do_kdy > ad_core::nyni() {
                self.zapis_audit(
                    "auth.logon.locked",
                    &u.sam_account_name,
                    "",
                    ip,
                    false,
                    "účet je zamčený",
                )?;
                return Err(AdError::new(
                    ErrorCode::AccountLocked,
                    format!(
                        "účet je zamčený do {}",
                        do_kdy
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default()
                    ),
                ));
            }
        }

        let hash = self.hash_hesla(u.id)?;
        let zasada = self.efektivni_zasada(u.ou_id)?;

        if !password::over(&hash, heslo)? {
            self.zapis_neuspech(ip)?;
            let zamceno = self.zapocitej_neuspech(u.id, &zasada.lockout)?;
            self.zapis_audit(
                "auth.logon.failed",
                &u.sam_account_name,
                "",
                ip,
                false,
                if zamceno { "špatné heslo, účet zamčen" } else { "špatné heslo" },
            )?;
            return Err(chyba_prihlaseni());
        }

        // Heslo souhlasí. Teprve teď řekneme, že je účet vypnutý —
        // kdybychom to řekli dřív, dalo by se zjišťovat, které účty
        // existují.
        if !u.enabled {
            self.zapis_audit(
                "auth.logon.disabled",
                &u.sam_account_name,
                "",
                ip,
                false,
                "účet je vypnutý",
            )?;
            return Err(AdError::new(ErrorCode::AccountDisabled, "účet je vypnutý"));
        }

        // Úspěch: vynulujeme počítadla a zapíšeme přihlášení.
        let nyni = ad_core::nyni();
        {
            let c = self.lock();
            c.execute(
                "UPDATE users SET failed_logons = 0, first_failed_at = NULL,
                     locked_until = NULL, last_logon_at = ?1 WHERE id = ?2",
                params![cas_do_db(nyni), u.id],
            )
            .map_err(db_chyba)?;
        }

        // Vypršení hesla.
        let (vyprsi_za, heslo_vyprselo) = self.stav_hesla(&u, &zasada);
        let musi_zmenit = u.must_change_password || heslo_vyprselo;

        // Ticket.
        let token = secret::novy_token();
        let do_kdy = nyni + Duration::minutes(proto::PLATNOST_TICKETU_MIN);
        {
            let c = self.lock();
            c.execute(
                "INSERT INTO user_tickets(token_hash, user_id, computer_id,
                     created_at, expires_at)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    secret::hash_tokenu(&token),
                    u.id,
                    computer_id,
                    cas_do_db(nyni),
                    cas_do_db(do_kdy)
                ],
            )
            .map_err(db_chyba)?;
            c.execute("DELETE FROM user_tickets WHERE expires_at < ?1", [cas_do_db(nyni)])
                .map_err(db_chyba)?;
        }

        let cil = match computer_id {
            Some(id) => format!("computer:{id}"),
            None => String::new(),
        };
        self.zapis_audit("auth.logon.ok", &u.sam_account_name, &cil, ip, true, "")?;

        let mut uzivatel = u;
        uzivatel.last_logon_at = Some(nyni);
        Ok(Prihlaseni {
            user: uzivatel,
            ticket: secret::Tajne::new(token),
            ticket_do: do_kdy,
            policy: zasada,
            must_change_password: musi_zmenit,
            password_expires_in_days: vyprsi_za,
        })
    }

    /// Kolik dní zbývá do vypršení hesla a jestli už vypršelo.
    fn stav_hesla(&self, u: &User, zasada: &EffectivePolicy) -> (Option<u16>, bool) {
        if u.password_never_expires || zasada.password.max_age_days == 0 {
            return (None, false);
        }
        let Some(nastaveno) = u.password_set_at else {
            // Neznámé datum — bezpečnější je vynutit změnu.
            return (Some(0), true);
        };
        let vyprsi = nastaveno + Duration::days(zasada.password.max_age_days as i64);
        let zbyva = (vyprsi - ad_core::nyni()).whole_days();
        if zbyva <= 0 {
            (Some(0), true)
        } else {
            (Some(zbyva.min(u16::MAX as i64) as u16), false)
        }
    }

    /// Zapíše neúspěšný pokus a případně účet zamkne. Vrací `true`,
    /// pokud se účet právě zamkl.
    fn zapocitej_neuspech(
        &self,
        user_id: i64,
        zasada: &ad_core::policy::LockoutPolicy,
    ) -> Result<bool> {
        if zasada.threshold == 0 {
            return Ok(false); // zamykání je vypnuté
        }
        let nyni = ad_core::nyni();
        let c = self.lock();
        let (pocet, prvni): (i64, Option<String>) = c
            .query_row(
                "SELECT failed_logons, first_failed_at FROM users WHERE id = ?1",
                [user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_chyba)?;

        // Okno vypršelo → počítáme znovu od jedné.
        let v_okne = match prvni.as_deref() {
            None => false,
            Some(t) => {
                let t = cas_z_db(t)?;
                nyni - t < Duration::minutes(zasada.window_minutes as i64)
            }
        };
        let novy_pocet = if v_okne { pocet + 1 } else { 1 };
        let prvni_cas = if v_okne { prvni } else { Some(cas_do_db(nyni)) };

        if novy_pocet >= zasada.threshold as i64 {
            let do_kdy = nyni + Duration::minutes(zasada.duration_minutes as i64);
            c.execute(
                "UPDATE users SET failed_logons = 0, first_failed_at = NULL,
                     locked_until = ?1 WHERE id = ?2",
                params![cas_do_db(do_kdy), user_id],
            )
            .map_err(db_chyba)?;
            return Ok(true);
        }
        c.execute(
            "UPDATE users SET failed_logons = ?1, first_failed_at = ?2 WHERE id = ?3",
            params![novy_pocet, prvni_cas, user_id],
        )
        .map_err(db_chyba)?;
        Ok(false)
    }

    /// Změna hesla uživatelem — vyžaduje staré heslo.
    pub fn zmen_heslo(
        &self,
        prihlasovaci_jmeno: &str,
        stare: &str,
        nove: &str,
        ip: &str,
    ) -> Result<()> {
        self.zkontroluj_rychlost(ip)?;
        let (sam, _) = names::rozdel_prihlaseni(prihlasovaci_jmeno);
        let sam = sam.to_ascii_lowercase();

        let Some(u) = self.uzivatel_podle_sam(&sam)? else {
            let _ = password::over(password::haš_na_zdržení(), stare);
            self.zapis_neuspech(ip)?;
            return Err(chyba_prihlaseni());
        };
        let hash = self.hash_hesla(u.id)?;
        if !password::over(&hash, stare)? {
            self.zapis_neuspech(ip)?;
            self.zapis_audit(
                "auth.password.failed",
                &u.sam_account_name,
                "",
                ip,
                false,
                "staré heslo nesouhlasí",
            )?;
            return Err(chyba_prihlaseni());
        }
        if !u.enabled {
            return Err(AdError::new(ErrorCode::AccountDisabled, "účet je vypnutý"));
        }
        if stare == nove {
            return Err(AdError::new(
                ErrorCode::PasswordPolicyViolation,
                "nové heslo musí být jiné než staré",
            ));
        }

        let zasada = self.efektivni_zasada(u.ou_id)?;
        // Minimální věk hesla: brání rychlému protočení historie.
        if zasada.password.min_age_days > 0 {
            if let Some(nastaveno) = u.password_set_at {
                let muze_od = nastaveno + Duration::days(zasada.password.min_age_days as i64);
                if muze_od > ad_core::nyni() {
                    return Err(AdError::new(
                        ErrorCode::PasswordPolicyViolation,
                        format!(
                            "heslo se smí měnit nejdřív po {} dnech",
                            zasada.password.min_age_days
                        ),
                    ));
                }
            }
        }
        let historie = self.historie_hesel(u.id, zasada.password.history_length)?;
        password::zkontroluj(nove, &zasada.password, Some(&u.sam_account_name), &historie)?;

        self.nastav_heslo(u.id, nove, false, true)?;
        self.zapis_audit("auth.password.changed", &u.sam_account_name, "", ip, true, "")?;
        Ok(())
    }

    /// Ověří, že jméno a heslo patří správci domény. Používá se při
    /// připojení počítače a při přihlášení do webové správy.
    pub fn over_spravce(&self, jmeno: &str, heslo: &str, ip: &str) -> Result<User> {
        let p = self.prihlas(jmeno, heslo, None, ip)?;
        if !self.je_ve_skupine_rid(p.user.id, rid::DOMAIN_ADMINS)? {
            self.zapis_audit(
                "auth.admin.denied",
                &p.user.sam_account_name,
                "",
                ip,
                false,
                "není ve skupině správců domény",
            )?;
            return Err(AdError::permission_denied("účet není ve skupině správců domény"));
        }
        Ok(p.user)
    }
}

/// Jediná chyba, kterou při neúspěšném přihlášení vracíme. Nikdy
/// neprozradíme, co přesně nesouhlasilo.
fn chyba_prihlaseni() -> AdError {
    AdError::new(ErrorCode::InvalidCredentials, "jméno nebo heslo nesouhlasí")
}

/// Zkrátí jméno z nedůvěryhodného vstupu, než ho zapíšeme do auditu.
fn omez(s: &str) -> String {
    super::objects::omez_text(s, 64)
}
