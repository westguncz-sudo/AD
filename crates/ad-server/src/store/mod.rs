//! Přístup k databázi.
//!
//! Všechna práce s SQLite je tady. Metody jsou **synchronní** — volají se
//! z `tokio::task::spawn_blocking`, aby neblokovaly asynchronní vlákna.
//! Je to jednodušší a předvídatelnější než asynchronní obal nad SQLite.
//!
//! Dotazy jsou vždy parametrizované (`?1`, `?2`). Nikde se nelepí vstup
//! do SQL textu — to je jediná spolehlivá obrana proti SQL injection.

pub mod auth;
pub mod dns;
pub mod gpo;
pub mod objects;
pub mod schema;

use ad_core::{AdError, ErrorCode, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Databáze domény.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

thread_local! {
    /// Drží tohle vlákno zámek databáze? Hlídá vnořené zamknutí.
    static DRZIM_ZAMEK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Zamčené spojení s databází. Chová se jako `Connection`.
pub(crate) struct Zamek<'a> {
    guard: MutexGuard<'a, Connection>,
}

impl std::ops::Deref for Zamek<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.guard
    }
}

impl std::ops::DerefMut for Zamek<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.guard
    }
}

impl Drop for Zamek<'_> {
    fn drop(&mut self) {
        DRZIM_ZAMEK.with(|d| d.set(false));
    }
}

impl Store {
    /// Otevře (nebo vytvoří) databázi na disku a spustí migrace.
    pub fn otevri(cesta: &Path) -> Result<Self> {
        let conn = Connection::open(cesta).map_err(|e| {
            AdError::internal(format!("databázi {} nelze otevřít: {e}", cesta.display()))
        })?;
        let s = Self { conn: Arc::new(Mutex::new(conn)) };
        s.nastav_pragma()?;
        s.migruj()?;
        Ok(s)
    }

    /// Databáze v paměti — pro testy.
    #[allow(dead_code)] // používají jen testy
    pub fn v_pameti() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AdError::internal(format!("databáze v paměti: {e}")))?;
        let s = Self { conn: Arc::new(Mutex::new(conn)) };
        s.nastav_pragma()?;
        s.migruj()?;
        Ok(s)
    }

    /// Zamkne spojení.
    ///
    /// Při „otrávení“ mutexu (panika v jiném vlákně) pokračujeme —
    /// databáze je konzistentní díky transakcím.
    ///
    /// # Pravidlo, které se nesmí porušit
    /// Spojení je za obyčejným mutexem, takže **není** reentrantní.
    /// Dokud držíš zámek, nesmíš zavolat jinou metodu `Store`, která si
    /// ho taky bere — program by se zasekl. Všechno, co potřebuješ
    /// z databáze, si zjisti **před** `lock()`.
    ///
    /// Aby se na to nedalo zapomenout, hlídáme to: druhé zamknutí ve
    /// stejném vlákně skončí panikou s vysvětlením. Panika se dá najít
    /// a opravit, zaseknutý server ne.
    pub(crate) fn lock(&self) -> Zamek<'_> {
        DRZIM_ZAMEK.with(|drzim| {
            if drzim.get() {
                panic!(
                    "vnořené zamknutí databáze ve stejném vlákně — \
                     metoda Store držící zámek zavolala jinou metodu Store. \
                     Zjisti si potřebná data před store.lock()."
                );
            }
            drzim.set(true);
        });
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Zamek { guard }
    }

    fn nastav_pragma(&self) -> Result<()> {
        let c = self.lock();
        // WAL: čtení neblokuje zápis, databáze se dá otevřít i nástrojem
        // sqlite3 při běhu serveru.
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    /// Spustí chybějící migrace podle `PRAGMA user_version`.
    fn migruj(&self) -> Result<()> {
        let mut c = self.lock();
        let verze: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db_chyba)?;
        if verze > schema::VERZE_SCHEMATU {
            return Err(AdError::internal(format!(
                "databáze je ve verzi {verze}, tento server umí nejvýš {}. \
                 Použij novější ad-server.",
                schema::VERZE_SCHEMATU
            )));
        }
        if verze < 1 {
            let tx = c.transaction().map_err(db_chyba)?;
            tx.execute_batch(schema::MIGRACE_1).map_err(db_chyba)?;
            tx.pragma_update(None, "user_version", 1).map_err(db_chyba)?;
            tx.commit().map_err(db_chyba)?;
            tracing::info!("databáze vytvořena, schéma verze 1");
        }
        Ok(())
    }

    /// Verze schématu v databázi.
    #[allow(dead_code)] // používají jen testy
    pub fn verze_schematu(&self) -> Result<i64> {
        let c = self.lock();
        c.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db_chyba)
    }

    // -------------------------------------------------------------------
    // Nastavení (klíč-hodnota)
    // -------------------------------------------------------------------

    pub fn nastaveni(&self, klic: &str) -> Result<Option<String>> {
        let c = self.lock();
        c.query_row("SELECT value FROM settings WHERE key = ?1", [klic], |r| r.get(0))
            .optional()
            .map_err(db_chyba)
    }

    pub fn nastav(&self, klic: &str, hodnota: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![klic, hodnota],
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    pub fn zrus_nastaveni(&self, klic: &str) -> Result<()> {
        let c = self.lock();
        c.execute("DELETE FROM settings WHERE key = ?1", [klic]).map_err(db_chyba)?;
        Ok(())
    }

    pub fn nastaveni_bool(&self, klic: &str) -> Result<bool> {
        Ok(self.nastaveni(klic)?.as_deref() == Some("1"))
    }

    pub fn nastav_bool(&self, klic: &str, hodnota: bool) -> Result<()> {
        self.nastav(klic, if hodnota { "1" } else { "0" })
    }

    /// Které role jsou nainstalované.
    pub fn role(&self) -> Result<ad_core::model::InstalledRoles> {
        Ok(ad_core::model::InstalledRoles {
            directory: self.nastaveni_bool(schema::nastaveni::ROLE_DIRECTORY)?,
            dns: self.nastaveni_bool(schema::nastaveni::ROLE_DNS)?,
        })
    }

    /// Sériové číslo zásad.
    pub fn serial_zasad(&self) -> Result<u64> {
        Ok(self
            .nastaveni(schema::nastaveni::POLICY_SERIAL)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0))
    }

    /// Zvýší sériové číslo zásad — klienti si pak stáhnou nové.
    pub fn zvys_serial_zasad(&self) -> Result<u64> {
        let nove = self.serial_zasad()? + 1;
        self.nastav(schema::nastaveni::POLICY_SERIAL, &nove.to_string())?;
        Ok(nove)
    }

    // -------------------------------------------------------------------
    // Doména
    // -------------------------------------------------------------------

    /// Vrátí doménu, nebo `None`, když server ještě není řadičem.
    pub fn domena(&self) -> Result<Option<ad_core::model::Domain>> {
        let c = self.lock();
        c.query_row(
            "SELECT dns_name, short_name, sid_a, sid_b, sid_c, dc_hostname, dc_fqdn,
                    dc_ip, created_at
             FROM domain WHERE id = 1",
            [],
            |r| {
                Ok(ad_core::model::Domain {
                    dns_name: r.get(0)?,
                    short_name: r.get(1)?,
                    domain_sid: ad_core::ids::DomainSid {
                        a: u32::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                        b: u32::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                        c: u32::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                    },
                    dc_hostname: r.get(5)?,
                    dc_fqdn: r.get(6)?,
                    dc_ip: r.get(7)?,
                    created_at: cas_z_db_row(r.get::<_, String>(8)?)?,
                })
            },
        )
        .optional()
        .map_err(db_chyba)
    }

    /// Doména, nebo chyba `domain_not_created`.
    pub fn domena_nebo_chyba(&self) -> Result<ad_core::model::Domain> {
        self.domena()?.ok_or_else(|| {
            AdError::new(
                ErrorCode::DomainNotCreated,
                "server ještě není řadičem domény — nejdřív ho povyš",
            )
        })
    }

    /// V jakém stavu server je.
    pub fn stav(&self) -> Result<ad_core::model::ServerStage> {
        use ad_core::model::ServerStage;
        if self.domena()?.is_some() {
            return Ok(ServerStage::DomainController);
        }
        let r = self.role()?;
        Ok(if r.directory || r.dns { ServerStage::RolesInstalled } else { ServerStage::Fresh })
    }

    /// Přidělí nový RID. Musí být v transakci spolu s vytvořením objektu.
    pub(crate) fn dalsi_rid(tx: &rusqlite::Transaction<'_>) -> Result<u32> {
        let rid: i64 = tx
            .query_row("SELECT next_rid FROM domain WHERE id = 1", [], |r| r.get(0))
            .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => AdError::new(
                ErrorCode::DomainNotCreated,
                "doména neexistuje, nelze přidělit identifikátor",
            ),
            jine => db_chyba(jine),
        })?;
        tx.execute("UPDATE domain SET next_rid = next_rid + 1 WHERE id = 1", [])
            .map_err(db_chyba)?;
        u32::try_from(rid).map_err(|_| AdError::internal("vyčerpaný prostor identifikátorů"))
    }

    // -------------------------------------------------------------------
    // Audit
    // -------------------------------------------------------------------

    /// Zapíše událost do auditu.
    ///
    /// `detail` nikdy nesmí obsahovat heslo ani token — proto se tam dává
    /// jen to, co se dá bezpečně zobrazit.
    pub fn zapis_audit(
        &self,
        action: &str,
        actor: &str,
        target: &str,
        source_ip: &str,
        success: bool,
        detail: &str,
    ) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO events(at, action, actor, target, source_ip, success, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                cas_do_db(ad_core::nyni()),
                action,
                actor,
                target,
                source_ip,
                success as i64,
                detail
            ],
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    /// Načte auditní log.
    pub fn audit(
        &self,
        dotaz: &ad_core::proto::EventsQuery,
    ) -> Result<ad_core::proto::Page<ad_core::model::AuditEvent>> {
        let limit = dotaz.limit.unwrap_or(100).clamp(1, 500) as i64;
        let offset = dotaz.offset.unwrap_or(0) as i64;
        let akce = dotaz.action.clone();
        let actor = dotaz.actor.clone();
        let jen_chyby = dotaz.only_failures.unwrap_or(false);

        let c = self.lock();
        let total: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM events
                 WHERE (?1 IS NULL OR action LIKE ?1 || '%')
                   AND (?2 IS NULL OR actor = ?2)
                   AND (?3 = 0 OR success = 0)",
                rusqlite::params![akce, actor, jen_chyby as i64],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;

        let mut stmt = c
            .prepare(
                "SELECT id, at, action, actor, target, source_ip, success, detail
                 FROM events
                 WHERE (?1 IS NULL OR action LIKE ?1 || '%')
                   AND (?2 IS NULL OR actor = ?2)
                   AND (?3 = 0 OR success = 0)
                 ORDER BY id DESC LIMIT ?4 OFFSET ?5",
            )
            .map_err(db_chyba)?;
        let radky = stmt
            .query_map(rusqlite::params![akce, actor, jen_chyby as i64, limit, offset], |r| {
                Ok(ad_core::model::AuditEvent {
                    id: r.get(0)?,
                    at: cas_z_db_row(r.get::<_, String>(1)?)?,
                    action: r.get(2)?,
                    actor: r.get(3)?,
                    target: r.get(4)?,
                    source_ip: r.get(5)?,
                    success: r.get::<_, i64>(6)? != 0,
                    detail: r.get(7)?,
                })
            })
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;

        Ok(ad_core::proto::Page {
            items: radky,
            total: total as u64,
            offset: offset as u64,
            limit: limit as u64,
        })
    }

    // -------------------------------------------------------------------
    // Soubory pro zásady (tapety)
    // -------------------------------------------------------------------

    /// Zapíše popis nahraného souboru.
    ///
    /// Bere rovnou `UploadAssetResponse`, protože to je přesně ten
    /// popis, co se o souboru zjistil — a osm volných parametrů by se
    /// dalo snadno prohodit.
    pub fn vloz_asset(
        &self,
        popis: &ad_core::proto::UploadAssetResponse,
        puvodni_jmeno: &str,
    ) -> Result<()> {
        let c = self.lock();
        c.execute(
            "INSERT INTO assets(id, sha256, size, format, width, height,
                 original_name, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                popis.asset_id.to_string(),
                popis.sha256,
                popis.size as i64,
                popis.format.pripona(),
                popis.width as i64,
                popis.height as i64,
                puvodni_jmeno,
                cas_do_db(ad_core::nyni())
            ],
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    pub fn asset(&self, id: ad_core::ids::Guid) -> Result<ad_core::proto::UploadAssetResponse> {
        let c = self.lock();
        c.query_row(
            "SELECT sha256, size, format, width, height FROM assets WHERE id = ?1",
            [id.to_string()],
            |r| {
                let format: String = r.get(2)?;
                Ok(ad_core::proto::UploadAssetResponse {
                    asset_id: id,
                    sha256: r.get(0)?,
                    size: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                    format: if format == "png" {
                        ad_core::policy::ImageFormat::Png
                    } else {
                        ad_core::policy::ImageFormat::Jpeg
                    },
                    width: u32::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                    height: u32::try_from(r.get::<_, i64>(4)?).unwrap_or(0),
                })
            },
        )
        .optional()
        .map_err(db_chyba)?
        .ok_or_else(|| AdError::not_found(format!("soubor {id} neexistuje")))
    }

    /// Počty objektů pro přehled.
    pub fn pocty(&self) -> Result<ad_core::proto::Counts> {
        let c = self.lock();
        let jeden = |sql: &str| -> Result<u64> {
            c.query_row(sql, [], |r| r.get::<_, i64>(0)).map(|x| x as u64).map_err(db_chyba)
        };
        let hranice = cas_do_db(ad_core::nyni() - time::Duration::hours(24));
        let online: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM computers WHERE last_seen_at IS NOT NULL
                 AND last_seen_at >= ?1",
                [&hranice],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        let nyni = cas_do_db(ad_core::nyni());
        let zamcene: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL
                 AND locked_until > ?1",
                [&nyni],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;

        Ok(ad_core::proto::Counts {
            users: jeden("SELECT COUNT(*) FROM users")?,
            groups: jeden("SELECT COUNT(*) FROM groups")?,
            ous: jeden("SELECT COUNT(*) FROM ou")?,
            computers: jeden("SELECT COUNT(*) FROM computers")?,
            gpos: jeden("SELECT COUNT(*) FROM gpos")?,
            zones: jeden("SELECT COUNT(*) FROM dns_zones")?,
            computers_online: online as u64,
            locked_users: zamcene as u64,
        })
    }
}

// -----------------------------------------------------------------------
// Pomocné funkce
// -----------------------------------------------------------------------

/// Přeloží chybu SQLite na naši chybu.
///
/// Porušení unikátnosti není „vnitřní chyba“, ale konflikt — uživatel
/// má dostat `409`, ne `500`.
pub fn db_chyba(e: rusqlite::Error) -> AdError {
    use rusqlite::ffi::ErrorCode as SqlKod;
    if let rusqlite::Error::SqliteFailure(f, ref zprava) = e {
        match f.code {
            SqlKod::ConstraintViolation => {
                let text = zprava.clone().unwrap_or_default();
                if text.contains("UNIQUE") {
                    return AdError::new(ErrorCode::Conflict, "takový objekt už existuje");
                }
                if text.contains("FOREIGN KEY") {
                    return AdError::new(
                        ErrorCode::Conflict,
                        "objekt je ještě někde použitý, nebo odkaz neexistuje",
                    );
                }
                return AdError::new(ErrorCode::Conflict, "porušené omezení databáze");
            }
            SqlKod::DatabaseBusy | SqlKod::DatabaseLocked => {
                return AdError::new(
                    ErrorCode::Internal,
                    "databáze je zaneprázdněná, zkus to znovu",
                )
            }
            _ => {}
        }
    }
    if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
        return AdError::not_found("objekt nenalezen");
    }
    AdError::internal(format!("databáze: {e}"))
}

/// Čas do databáze: RFC 3339 v UTC.
pub fn cas_do_db(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Čas z databáze.
pub fn cas_z_db(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|e| AdError::internal(format!("neplatný čas v databázi: {s} ({e})")))
}

/// Varianta pro použití uvnitř `query_row`, kde se vrací chyba SQLite.
pub(crate) fn cas_z_db_row(s: String) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(&s, &Rfc3339).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Volitelný čas z databáze.
pub(crate) fn cas_volitelne(s: Option<String>) -> rusqlite::Result<Option<OffsetDateTime>> {
    match s {
        None => Ok(None),
        Some(t) => cas_z_db_row(t).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn databaze_se_vytvori_a_ma_verzi() {
        let s = Store::v_pameti().unwrap();
        assert_eq!(s.verze_schematu().unwrap(), schema::VERZE_SCHEMATU);
        assert!(s.domena().unwrap().is_none());
        assert_eq!(s.stav().unwrap(), ad_core::model::ServerStage::Fresh);
    }

    #[test]
    fn nastaveni_se_uklada() {
        let s = Store::v_pameti().unwrap();
        assert!(s.nastaveni("neco").unwrap().is_none());
        s.nastav("neco", "1").unwrap();
        assert_eq!(s.nastaveni("neco").unwrap().as_deref(), Some("1"));
        s.nastav("neco", "2").unwrap();
        assert_eq!(s.nastaveni("neco").unwrap().as_deref(), Some("2"));
        s.zrus_nastaveni("neco").unwrap();
        assert!(s.nastaveni("neco").unwrap().is_none());
    }

    #[test]
    fn stav_podle_roli() {
        let s = Store::v_pameti().unwrap();
        s.nastav_bool(schema::nastaveni::ROLE_DNS, true).unwrap();
        assert_eq!(s.stav().unwrap(), ad_core::model::ServerStage::RolesInstalled);
        assert!(s.role().unwrap().dns);
        assert!(!s.role().unwrap().directory);
    }

    #[test]
    fn serial_zasad_roste() {
        let s = Store::v_pameti().unwrap();
        assert_eq!(s.serial_zasad().unwrap(), 0);
        assert_eq!(s.zvys_serial_zasad().unwrap(), 1);
        assert_eq!(s.zvys_serial_zasad().unwrap(), 2);
        assert_eq!(s.serial_zasad().unwrap(), 2);
    }

    #[test]
    fn audit_se_zapise_a_precte() {
        let s = Store::v_pameti().unwrap();
        s.zapis_audit("user.create", "SKOLA\\administrator", "user:jan", "127.0.0.1", true, "")
            .unwrap();
        s.zapis_audit("auth.logon", "jan", "", "192.168.56.20", false, "špatné heslo").unwrap();
        let vse = s.audit(&Default::default()).unwrap();
        assert_eq!(vse.total, 2);
        assert_eq!(vse.items[0].action, "auth.logon", "nejnovější první");

        let chyby = s
            .audit(&ad_core::proto::EventsQuery { only_failures: Some(true), ..Default::default() })
            .unwrap();
        assert_eq!(chyby.total, 1);

        let podle_akce = s
            .audit(&ad_core::proto::EventsQuery {
                action: Some("user.".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(podle_akce.total, 1);
    }

    #[test]
    fn cas_tam_a_zpet() {
        let t = time::macros::datetime!(2026-11-25 18:30:00 UTC);
        let s = cas_do_db(t);
        assert_eq!(s, "2026-11-25T18:30:00Z");
        assert_eq!(cas_z_db(&s).unwrap(), t);
        assert!(cas_z_db("25.11.2026").is_err());
    }

    #[test]
    fn unikatnost_je_konflikt_ne_vnitrni_chyba() {
        let s = Store::v_pameti().unwrap();
        {
            let c = s.lock();
            c.execute("INSERT INTO settings(key, value) VALUES ('x','1')", []).unwrap();
            let e = c.execute("INSERT INTO settings(key, value) VALUES ('x','2')", []).unwrap_err();
            assert_eq!(db_chyba(e).code, ErrorCode::Conflict);
        }
    }

    #[test]
    #[should_panic(expected = "vnořené zamknutí")]
    fn vnorene_zamknuti_spadne_misto_zaseknuti() {
        // Přesně tahle chyba zasekla server při povyšování domény.
        // Teď spadne hned a je vidět, kde.
        let s = Store::v_pameti().unwrap();
        let _drzim = s.lock();
        let _ = s.nastaveni("cokoli");
    }

    #[test]
    fn po_uvolneni_se_da_zamknout_znovu() {
        let s = Store::v_pameti().unwrap();
        {
            let _z = s.lock();
        }
        s.nastav("x", "1").unwrap();
        assert_eq!(s.nastaveni("x").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn pocty_na_prazdne_databazi() {
        let s = Store::v_pameti().unwrap();
        let p = s.pocty().unwrap();
        assert_eq!(p.users, 0);
        assert_eq!(p.zones, 0);
    }
}
