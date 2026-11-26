//! Zásady skupiny v databázi a jejich vyhodnocení.
//!
//! Samo vyhodnocení (co přebíjí co) je v `ad_core::policy::vyhodnot` —
//! tady jen posbíráme správné GPO ve správném pořadí. Díky tomu se
//! pravidla dají testovat bez databáze a klient je má stejná.

use super::{cas_do_db, cas_z_db_row, db_chyba, Store};
use ad_core::model::{Gpo, GpoLink, GpoTarget};
use ad_core::policy::{EffectivePolicy, GpoKVyhodnoceni, PolicySet};
use ad_core::proto::{self, ListQuery, Page};
use ad_core::{names, AdError, Result};
use rusqlite::{params, OptionalExtension, Row};

const SLOUPCE_GPO: &str =
    "id, guid, name, description, enabled, settings_json, created_at, modified_at";

fn gpo_z_radku(r: &Row<'_>) -> rusqlite::Result<Gpo> {
    let json: String = r.get(5)?;
    let settings: PolicySet = serde_json::from_str(&json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Gpo {
        id: r.get(0)?,
        guid: r.get::<_, String>(1)?.parse().map_err(|e: ad_core::ids::GuidError| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                format!("neplatný GUID: {e}").into(),
            )
        })?,
        name: r.get(2)?,
        description: r.get(3)?,
        enabled: r.get::<_, i64>(4)? != 0,
        settings,
        created_at: cas_z_db_row(r.get::<_, String>(6)?)?,
        modified_at: cas_z_db_row(r.get::<_, String>(7)?)?,
    })
}

impl Store {
    /// Vyhodnotí zásady platné pro objekt v dané OU.
    ///
    /// Pořadí: nejdřív GPO připojené na doménu, pak OU od korene k listu.
    /// Co je blíž objektu, přebíjí; vynucené (`enforced`) přebíjí vše.
    pub fn efektivni_zasada(&self, ou_id: Option<i64>) -> Result<EffectivePolicy> {
        // Bez domény nemá cenu nic hledat — vrátíme výchozí hodnoty,
        // aby šlo zakládat účty i při povyšování serveru.
        if self.domena()?.is_none() {
            return Ok(EffectivePolicy::default());
        }
        let mut retez: Vec<GpoKVyhodnoceni> = Vec::new();
        retez.extend(self.gpo_pro_cil(GpoTarget::Domain, "/")?);
        for ou in self.cesta_ou(ou_id)? {
            let cesta = ou.path.clone();
            retez.extend(self.gpo_pro_cil(GpoTarget::Ou { ou_id: ou.id }, &cesta)?);
        }
        let vysledek = ad_core::policy::vyhodnot(&retez);
        // Pojistka: kdyby se do databáze dostala nesmyslná zásada
        // (ruční zápis do SQLite), nepošleme ji klientovi.
        if let Err(e) = vysledek.validuj() {
            tracing::warn!(chyba = %e, "zásada v databázi je neplatná, použité výchozí hodnoty");
            return Ok(EffectivePolicy::default());
        }
        Ok(vysledek)
    }

    fn gpo_pro_cil(&self, cil: GpoTarget, popis_cile: &str) -> Result<Vec<GpoKVyhodnoceni>> {
        let c = self.lock();
        let (scope, ou) = match cil {
            GpoTarget::Domain => ("domain", None),
            GpoTarget::Ou { ou_id } => ("ou", Some(ou_id)),
        };
        let mut stmt = c
            .prepare(
                "SELECT g.guid, g.name, g.settings_json, l.enforced
                 FROM gpo_links l JOIN gpos g ON g.id = l.gpo_id
                 WHERE l.scope = ?1 AND IFNULL(l.ou_id, -1) = IFNULL(?2, -1)
                   AND l.enabled = 1 AND g.enabled = 1
                 ORDER BY l.ord ASC, l.id ASC",
            )
            .map_err(db_chyba)?;
        let radky: Vec<(String, String, String, i64)> = stmt
            .query_map(params![scope, ou], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;

        let mut vysledek = Vec::new();
        for (guid, jmeno, json, enforced) in radky {
            let policy: PolicySet = match serde_json::from_str(&json) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(gpo = %jmeno, chyba = %e, "zásadu nelze přečíst, přeskakuji");
                    continue;
                }
            };
            vysledek.push(GpoKVyhodnoceni {
                guid: guid.parse().unwrap_or_else(|_| ad_core::ids::novy_guid()),
                name: jmeno,
                linked_at: popis_cile.to_string(),
                enforced: enforced != 0,
                policy,
            });
        }
        Ok(vysledek)
    }

    pub fn gpo(&self, id: i64) -> Result<Gpo> {
        let c = self.lock();
        c.query_row(&format!("SELECT {SLOUPCE_GPO} FROM gpos WHERE id = ?1"), [id], gpo_z_radku)
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::not_found(format!("zásada {id} neexistuje")))
    }

    pub fn seznam_gpo(&self, q: &ListQuery) -> Result<Page<Gpo>> {
        let c = self.lock();
        let total: i64 =
            c.query_row("SELECT COUNT(*) FROM gpos", [], |r| r.get(0)).map_err(db_chyba)?;
        let mut stmt = c
            .prepare(&format!("SELECT {SLOUPCE_GPO} FROM gpos ORDER BY name LIMIT ?1 OFFSET ?2"))
            .map_err(db_chyba)?;
        let items = stmt
            .query_map(params![q.limit() as i64, q.offset() as i64], gpo_z_radku)
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(Page { items, total: total as u64, offset: q.offset(), limit: q.limit() })
    }

    pub fn vytvor_gpo(&self, req: &proto::CreateGpoRequest) -> Result<Gpo> {
        let jmeno = names::validuj_jmeno_objektu(&req.name)?;
        let popis = names::validuj_popis(&req.description)?;
        req.settings.validuj()?;
        let json = serde_json::to_string(&req.settings)
            .map_err(|e| AdError::internal(format!("zásadu nelze serializovat: {e}")))?;
        let guid = ad_core::ids::novy_guid();
        let nyni = cas_do_db(ad_core::nyni());

        let c = self.lock();
        c.execute(
            "INSERT INTO gpos(guid, name, description, enabled, settings_json,
                 created_at, modified_at)
             VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![guid.to_string(), jmeno, popis, req.enabled as i64, json, nyni],
        )
        .map_err(db_chyba)?;
        let id = c.last_insert_rowid();
        drop(c);
        self.zvys_serial_zasad()?;
        self.gpo(id)
    }

    pub fn uprav_gpo(&self, id: i64, req: &proto::UpdateGpoRequest) -> Result<Gpo> {
        let stara = self.gpo(id)?;
        let jmeno = match &req.name {
            Some(v) => names::validuj_jmeno_objektu(v)?,
            None => stara.name.clone(),
        };
        let popis = match &req.description {
            Some(v) => names::validuj_popis(v)?,
            None => stara.description.clone(),
        };
        let nastaveni = match &req.settings {
            Some(s) => {
                s.validuj()?;
                s.clone()
            }
            None => stara.settings.clone(),
        };
        let json = serde_json::to_string(&nastaveni)
            .map_err(|e| AdError::internal(format!("zásadu nelze serializovat: {e}")))?;

        let c = self.lock();
        c.execute(
            "UPDATE gpos SET name=?1, description=?2, enabled=?3, settings_json=?4,
                 modified_at=?5 WHERE id=?6",
            params![
                jmeno,
                popis,
                req.enabled.unwrap_or(stara.enabled) as i64,
                json,
                cas_do_db(ad_core::nyni()),
                id
            ],
        )
        .map_err(db_chyba)?;
        drop(c);
        self.zvys_serial_zasad()?;
        self.gpo(id)
    }

    pub fn smaz_gpo(&self, id: i64) -> Result<String> {
        let g = self.gpo(id)?;
        let c = self.lock();
        c.execute("DELETE FROM gpos WHERE id = ?1", [id]).map_err(db_chyba)?;
        drop(c);
        self.zvys_serial_zasad()?;
        Ok(g.name)
    }

    /// Připojí zásadu k doméně nebo OU.
    pub fn pripoj_gpo(&self, gpo_id: i64, req: &proto::LinkGpoRequest) -> Result<GpoLink> {
        let g = self.gpo(gpo_id)?;
        let (scope, ou) = match req.target {
            GpoTarget::Domain => ("domain", None),
            GpoTarget::Ou { ou_id } => {
                self.ou(ou_id)?;
                ("ou", Some(ou_id))
            }
        };
        let c = self.lock();
        let dalsi: i64 = c
            .query_row(
                "SELECT COALESCE(MAX(ord), 0) + 1 FROM gpo_links
                 WHERE scope = ?1 AND IFNULL(ou_id, -1) = IFNULL(?2, -1)",
                params![scope, ou],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        c.execute(
            "INSERT INTO gpo_links(gpo_id, scope, ou_id, ord, enforced, enabled)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![gpo_id, scope, ou, dalsi, req.enforced as i64, req.enabled as i64],
        )
        .map_err(db_chyba)?;
        let id = c.last_insert_rowid();
        drop(c);
        self.zvys_serial_zasad()?;
        Ok(GpoLink {
            id,
            gpo_id,
            gpo_guid: g.guid,
            gpo_name: g.name,
            target: req.target,
            order: dalsi as u32,
            enforced: req.enforced,
            enabled: req.enabled,
        })
    }

    pub fn odpoj_gpo(&self, link_id: i64) -> Result<()> {
        let c = self.lock();
        let kolik =
            c.execute("DELETE FROM gpo_links WHERE id = ?1", [link_id]).map_err(db_chyba)?;
        drop(c);
        if kolik == 0 {
            return Err(AdError::not_found("takové připojení zásady neexistuje"));
        }
        self.zvys_serial_zasad()?;
        Ok(())
    }

    /// Všechna připojení zásad, případně jen pro jeden cíl.
    pub fn odkazy_gpo(&self, cil: Option<GpoTarget>) -> Result<Vec<GpoLink>> {
        let c = self.lock();
        let (scope, ou) = match cil {
            None => (None, None),
            Some(GpoTarget::Domain) => (Some("domain"), None),
            Some(GpoTarget::Ou { ou_id }) => (Some("ou"), Some(ou_id)),
        };
        let mut stmt = c
            .prepare(
                "SELECT l.id, l.gpo_id, g.guid, g.name, l.scope, l.ou_id, l.ord,
                        l.enforced, l.enabled
                 FROM gpo_links l JOIN gpos g ON g.id = l.gpo_id
                 WHERE (?1 IS NULL OR l.scope = ?1)
                   AND (?1 IS NULL OR IFNULL(l.ou_id, -1) = IFNULL(?2, -1))
                 ORDER BY l.scope, l.ou_id, l.ord",
            )
            .map_err(db_chyba)?;
        let v = stmt
            .query_map(params![scope, ou], |r| {
                let scope: String = r.get(4)?;
                let ou_id: Option<i64> = r.get(5)?;
                Ok(GpoLink {
                    id: r.get(0)?,
                    gpo_id: r.get(1)?,
                    gpo_guid: r
                        .get::<_, String>(2)?
                        .parse()
                        .unwrap_or_else(|_| ad_core::ids::novy_guid()),
                    gpo_name: r.get(3)?,
                    target: if scope == "domain" {
                        GpoTarget::Domain
                    } else {
                        GpoTarget::Ou { ou_id: ou_id.unwrap_or(0) }
                    },
                    order: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(1),
                    enforced: r.get::<_, i64>(7)? != 0,
                    enabled: r.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }
}
