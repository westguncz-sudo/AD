//! Objekty domény: organizační jednotky, uživatelé, skupiny, počítače.
//!
//! Pozor na jednu věc: `password_hash` ani `secret_hash` se **nikdy**
//! nedostanou do struktur z `ad_core::model`. Ty se posílají do API,
//! a co v nich není, to nemůže uniknout.

use super::{cas_do_db, cas_volitelne, cas_z_db_row, db_chyba, Store};
use ad_core::ids::{rid, DomainSid, Guid};
use ad_core::model::*;
use ad_core::names;
use ad_core::proto::{self, ListQuery, Page, Scope, TreeNode};
use ad_core::{password, secret, AdError, ErrorCode, Result};
use rusqlite::{params, params_from_iter, OptionalExtension, Row};

/// Nejhlubší povolené zanoření OU. Pojistka proti nekonečné smyčce,
/// kdyby se v databázi objevil cyklus.
const MAX_HLOUBKA_OU: usize = 32;

const SLOUPCE_OU: &str = "id, guid, name, parent_id, path, description, protected, created_at";

const SLOUPCE_UZIVATELE: &str = "id, guid, rid, sam, display_name, given_name, surname, email, \
     description, ou_id, enabled, must_change_password, password_never_expires, \
     password_set_at, last_logon_at, locked_until, builtin, created_at";

const SLOUPCE_SKUPINY: &str =
    "id, guid, rid, sam, name, description, kind, ou_id, builtin, created_at";

const SLOUPCE_POCITACE: &str = "id, guid, rid, name, dns_name, description, ou_id, enabled, \
     os_name, os_version, last_ip, joined_at, last_seen_at";

fn ou_z_radku(r: &Row<'_>) -> rusqlite::Result<Ou> {
    Ok(Ou {
        id: r.get(0)?,
        guid: guid_z_textu(r.get::<_, String>(1)?)?,
        name: r.get(2)?,
        parent_id: r.get(3)?,
        path: r.get(4)?,
        description: r.get(5)?,
        protected: r.get::<_, i64>(6)? != 0,
        created_at: cas_z_db_row(r.get::<_, String>(7)?)?,
    })
}

fn uzivatel_z_radku(r: &Row<'_>, sid: DomainSid) -> rusqlite::Result<User> {
    let r_rid = u32::try_from(r.get::<_, i64>(2)?).unwrap_or(0);
    let sam: String = r.get(3)?;
    Ok(User {
        id: r.get(0)?,
        guid: guid_z_textu(r.get::<_, String>(1)?)?,
        sid: sid.sid(r_rid),
        sam_account_name: sam.clone(),
        upn: String::new(), // doplní se v `dopln_upn`
        display_name: r.get(4)?,
        given_name: r.get(5)?,
        surname: r.get(6)?,
        email: r.get(7)?,
        description: r.get(8)?,
        ou_id: r.get(9)?,
        enabled: r.get::<_, i64>(10)? != 0,
        must_change_password: r.get::<_, i64>(11)? != 0,
        password_never_expires: r.get::<_, i64>(12)? != 0,
        password_set_at: cas_volitelne(r.get(13)?)?,
        last_logon_at: cas_volitelne(r.get(14)?)?,
        locked_until: cas_volitelne(r.get(15)?)?,
        builtin: r.get::<_, i64>(16)? != 0,
        created_at: cas_z_db_row(r.get::<_, String>(17)?)?,
    })
}

fn skupina_z_radku(r: &Row<'_>, sid: DomainSid) -> rusqlite::Result<Group> {
    let kind: String = r.get(6)?;
    Ok(Group {
        id: r.get(0)?,
        guid: guid_z_textu(r.get::<_, String>(1)?)?,
        sid: sid.sid(u32::try_from(r.get::<_, i64>(2)?).unwrap_or(0)),
        sam_account_name: r.get(3)?,
        name: r.get(4)?,
        description: r.get(5)?,
        kind: if kind == "distribution" { GroupKind::Distribution } else { GroupKind::Security },
        ou_id: r.get(7)?,
        builtin: r.get::<_, i64>(8)? != 0,
        member_count: 0,
        created_at: cas_z_db_row(r.get::<_, String>(9)?)?,
    })
}

fn pocitac_z_radku(r: &Row<'_>, sid: DomainSid) -> rusqlite::Result<Computer> {
    Ok(Computer {
        id: r.get(0)?,
        guid: guid_z_textu(r.get::<_, String>(1)?)?,
        sid: sid.sid(u32::try_from(r.get::<_, i64>(2)?).unwrap_or(0)),
        name: r.get(3)?,
        dns_name: r.get(4)?,
        description: r.get(5)?,
        ou_id: r.get(6)?,
        enabled: r.get::<_, i64>(7)? != 0,
        os_name: r.get(8)?,
        os_version: r.get(9)?,
        last_ip: r.get(10)?,
        joined_at: cas_z_db_row(r.get::<_, String>(11)?)?,
        last_seen_at: cas_volitelne(r.get(12)?)?,
    })
}

fn guid_z_textu(s: String) -> rusqlite::Result<Guid> {
    s.parse::<Guid>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("neplatný GUID v databázi: {e}").into(),
        )
    })
}

impl Store {
    // ===================================================================
    // Organizační jednotky
    // ===================================================================

    pub fn ou(&self, id: i64) -> Result<Ou> {
        let c = self.lock();
        c.query_row(&format!("SELECT {SLOUPCE_OU} FROM ou WHERE id = ?1"), [id], ou_z_radku)
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::not_found(format!("organizační jednotka {id} neexistuje")))
    }

    pub fn ou_podle_cesty(&self, cesta: &str) -> Result<Option<Ou>> {
        let c = self.lock();
        c.query_row(&format!("SELECT {SLOUPCE_OU} FROM ou WHERE path = ?1"), [cesta], ou_z_radku)
            .optional()
            .map_err(db_chyba)
    }

    pub fn seznam_ou(&self) -> Result<Vec<Ou>> {
        let c = self.lock();
        let mut stmt =
            c.prepare(&format!("SELECT {SLOUPCE_OU} FROM ou ORDER BY path")).map_err(db_chyba)?;
        let v = stmt
            .query_map([], ou_z_radku)
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    /// Cesta od korene k dané OU včetně. Pro vyhodnocení zásad.
    pub fn cesta_ou(&self, ou_id: Option<i64>) -> Result<Vec<Ou>> {
        let mut vysledek: Vec<Ou> = Vec::new();
        let mut aktualni = ou_id;
        let mut pojistka = 0;
        while let Some(id) = aktualni {
            pojistka += 1;
            if pojistka > MAX_HLOUBKA_OU {
                return Err(AdError::internal("strom OU je příliš hluboký nebo obsahuje cyklus"));
            }
            let o = self.ou(id)?;
            aktualni = o.parent_id;
            vysledek.push(o);
        }
        vysledek.reverse();
        Ok(vysledek)
    }

    /// Všechna id OU v podstromu včetně zadané.
    pub fn potomci_ou(&self, ou_id: i64) -> Result<Vec<i64>> {
        let koren = self.ou(ou_id)?;
        let c = self.lock();
        let predpona = format!("{}/", koren.path);
        let mut stmt = c
            .prepare("SELECT id FROM ou WHERE id = ?1 OR path LIKE ?2 || '%'")
            .map_err(db_chyba)?;
        let v = stmt
            .query_map(params![ou_id, predpona], |r| r.get::<_, i64>(0))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    pub fn vytvor_ou(&self, req: &proto::CreateOuRequest) -> Result<Ou> {
        let jmeno = names::validuj_jmeno_objektu(&req.name)?;
        let popis = names::validuj_popis(&req.description)?;
        if jmeno.contains('/') {
            return Err(AdError::invalid_name("jméno OU nesmí obsahovat lomítko"));
        }

        let cesta_rodice = match req.parent_id {
            None => String::new(),
            Some(p) => {
                let rodic = self.ou(p)?;
                if self.cesta_ou(Some(p))?.len() >= MAX_HLOUBKA_OU {
                    return Err(AdError::out_of_range("strom OU je příliš hluboký"));
                }
                rodic.path
            }
        };
        let cesta = format!("{cesta_rodice}/{jmeno}");
        let guid = ad_core::ids::novy_guid();
        let nyni = cas_do_db(ad_core::nyni());

        let c = self.lock();
        c.execute(
            "INSERT INTO ou(guid, name, parent_id, path, description, protected, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                guid.to_string(),
                jmeno,
                req.parent_id,
                cesta,
                popis,
                req.protected as i64,
                nyni
            ],
        )
        .map_err(db_chyba)?;
        let id = c.last_insert_rowid();
        drop(c);
        self.ou(id)
    }

    /// Přejmenuje OU. Musí se přepsat i `path` všech potomků.
    pub fn prejmenuj_ou(&self, id: i64, nove_jmeno: &str) -> Result<Ou> {
        let jmeno = names::validuj_jmeno_objektu(nove_jmeno)?;
        if jmeno.contains('/') {
            return Err(AdError::invalid_name("jméno OU nesmí obsahovat lomítko"));
        }
        let stara = self.ou(id)?;
        let rodic = match stara.parent_id {
            None => String::new(),
            Some(p) => self.ou(p)?.path,
        };
        let nova_cesta = format!("{rodic}/{jmeno}");

        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        tx.execute(
            "UPDATE ou SET name = ?1, path = ?2 WHERE id = ?3",
            params![jmeno, nova_cesta, id],
        )
        .map_err(db_chyba)?;
        // Potomkům přepíšeme předponu cesty.
        tx.execute(
            "UPDATE ou SET path = ?1 || SUBSTR(path, LENGTH(?2) + 1)
             WHERE path LIKE ?2 || '/%'",
            params![nova_cesta, stara.path],
        )
        .map_err(db_chyba)?;
        tx.commit().map_err(db_chyba)?;
        drop(c);
        self.ou(id)
    }

    pub fn uprav_ou_popis(&self, id: i64, popis: &str, chraneno: Option<bool>) -> Result<Ou> {
        let popis = names::validuj_popis(popis)?;
        let c = self.lock();
        c.execute(
            "UPDATE ou SET description = ?1, protected = COALESCE(?2, protected) WHERE id = ?3",
            params![popis, chraneno.map(|b| b as i64), id],
        )
        .map_err(db_chyba)?;
        drop(c);
        self.ou(id)
    }

    pub fn smaz_ou(&self, id: i64) -> Result<()> {
        let o = self.ou(id)?;
        if o.protected {
            return Err(AdError::conflict(format!(
                "OU {} je chráněná proti smazání — nejdřív ochranu vypni",
                o.name
            )));
        }
        let c = self.lock();
        let deti: i64 = c
            .query_row("SELECT COUNT(*) FROM ou WHERE parent_id = ?1", [id], |r| r.get(0))
            .map_err(db_chyba)?;
        let objekty: i64 = c
            .query_row(
                "SELECT (SELECT COUNT(*) FROM users WHERE ou_id = ?1)
                      + (SELECT COUNT(*) FROM groups WHERE ou_id = ?1)
                      + (SELECT COUNT(*) FROM computers WHERE ou_id = ?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        if deti > 0 || objekty > 0 {
            return Err(AdError::conflict(format!(
                "OU {} není prázdná: {deti} podřízených OU, {objekty} objektů",
                o.name
            )));
        }
        c.execute("DELETE FROM ou WHERE id = ?1", [id]).map_err(db_chyba)?;
        Ok(())
    }

    /// Strom OU pro levý panel ve správě.
    pub fn strom_ou(&self) -> Result<TreeNode> {
        let domena = self.domena_nebo_chyba()?;
        let vsechny = self.seznam_ou()?;
        let pocty = self.pocty_objektu_v_ou()?;

        fn postav(
            rodic: Option<i64>,
            vsechny: &[Ou],
            pocty: &std::collections::HashMap<Option<i64>, u64>,
        ) -> Vec<TreeNode> {
            vsechny
                .iter()
                .filter(|o| o.parent_id == rodic)
                .map(|o| TreeNode {
                    ou_id: Some(o.id),
                    name: o.name.clone(),
                    path: o.path.clone(),
                    protected: o.protected,
                    object_count: pocty.get(&Some(o.id)).copied().unwrap_or(0),
                    children: postav(Some(o.id), vsechny, pocty),
                })
                .collect()
        }

        Ok(TreeNode {
            ou_id: None,
            name: domena.dns_name,
            path: "/".to_string(),
            protected: true,
            object_count: pocty.get(&None).copied().unwrap_or(0),
            children: postav(None, &vsechny, &pocty),
        })
    }

    fn pocty_objektu_v_ou(&self) -> Result<std::collections::HashMap<Option<i64>, u64>> {
        let c = self.lock();
        let mut mapa: std::collections::HashMap<Option<i64>, u64> = Default::default();
        for tabulka in ["users", "groups", "computers"] {
            let mut stmt = c
                .prepare(&format!("SELECT ou_id, COUNT(*) FROM {tabulka} GROUP BY ou_id"))
                .map_err(db_chyba)?;
            let radky = stmt
                .query_map([], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, i64>(1)?)))
                .map_err(db_chyba)?;
            for radek in radky {
                let (ou, pocet) = radek.map_err(db_chyba)?;
                *mapa.entry(ou).or_insert(0) += pocet as u64;
            }
        }
        Ok(mapa)
    }

    // ===================================================================
    // Uživatelé
    // ===================================================================

    /// Doplní UPN a cestu k OU — to se nedá vyčíst z jednoho řádku.
    fn dopln_upn(&self, mut u: User, fqdn: &str) -> User {
        u.upn = names::upn(&u.sam_account_name, fqdn);
        u
    }

    pub fn uzivatel(&self, id: i64) -> Result<User> {
        let d = self.domena_nebo_chyba()?;
        let c = self.lock();
        let u = c
            .query_row(&format!("SELECT {SLOUPCE_UZIVATELE} FROM users WHERE id = ?1"), [id], |r| {
                uzivatel_z_radku(r, d.domain_sid)
            })
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::not_found(format!("uživatel {id} neexistuje")))?;
        drop(c);
        Ok(self.dopln_upn(u, &d.dns_name))
    }

    pub fn uzivatel_podle_sam(&self, sam: &str) -> Result<Option<User>> {
        let sam = sam.to_ascii_lowercase();
        let d = self.domena_nebo_chyba()?;
        let c = self.lock();
        let u = c
            .query_row(
                &format!("SELECT {SLOUPCE_UZIVATELE} FROM users WHERE sam = ?1"),
                [&sam],
                |r| uzivatel_z_radku(r, d.domain_sid),
            )
            .optional()
            .map_err(db_chyba)?;
        drop(c);
        Ok(u.map(|u| self.dopln_upn(u, &d.dns_name)))
    }

    /// Haš hesla uživatele. Jediné místo, kde se čte — a nevrací se nikam
    /// do API.
    pub(crate) fn hash_hesla(&self, user_id: i64) -> Result<String> {
        let c = self.lock();
        c.query_row("SELECT password_hash FROM users WHERE id = ?1", [user_id], |r| r.get(0))
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::not_found("uživatel neexistuje"))
    }

    pub fn seznam_uzivatelu(&self, q: &ListQuery) -> Result<Page<User>> {
        let d = self.domena_nebo_chyba()?;
        let (kde, mut hodnoty) = self.filtr_seznamu(q)?;
        let limit = q.limit() as i64;
        let offset = q.offset() as i64;

        let c = self.lock();
        let total: i64 = c
            .query_row(
                &format!("SELECT COUNT(*) FROM users WHERE {kde}"),
                params_from_iter(hodnoty.iter()),
                |r| r.get(0),
            )
            .map_err(db_chyba)?;

        let sql = format!(
            "SELECT {SLOUPCE_UZIVATELE} FROM users WHERE {kde}
             ORDER BY sam LIMIT ?{} OFFSET ?{}",
            hodnoty.len() + 1,
            hodnoty.len() + 2
        );
        hodnoty.push(Box::new(limit));
        hodnoty.push(Box::new(offset));
        let mut stmt = c.prepare(&sql).map_err(db_chyba)?;
        let items = stmt
            .query_map(params_from_iter(hodnoty.iter()), |r| uzivatel_z_radku(r, d.domain_sid))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        drop(stmt);
        drop(c);

        Ok(Page {
            items: items.into_iter().map(|u| self.dopln_upn(u, &d.dns_name)).collect(),
            total: total as u64,
            offset: q.offset(),
            limit: q.limit(),
        })
    }

    /// Složí `WHERE` pro seznamy. Placeholdery generujeme my, hodnoty se
    /// vážou parametry — žádné lepení vstupu do SQL.
    fn filtr_seznamu(&self, q: &ListQuery) -> Result<(String, Vec<Box<dyn rusqlite::ToSql>>)> {
        let mut casti: Vec<String> = Vec::new();
        let mut hodnoty: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(text) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if text.chars().count() > 100 {
                return Err(AdError::out_of_range("hledaný text je příliš dlouhý"));
            }
            let vzor = format!("%{}%", text.to_lowercase());
            casti.push(format!(
                "(LOWER(sam) LIKE ?{0} OR LOWER(COALESCE(display_name, '')) LIKE ?{0}
                  OR LOWER(COALESCE(description, '')) LIKE ?{0})",
                hodnoty.len() + 1
            ));
            hodnoty.push(Box::new(vzor));
        }

        match (q.ou_id, q.scope) {
            // Bez `ou_id` se nefiltruje podle umístění vůbec — to je
            // potřeba pro hledání napříč doménou.
            (None, _) => {}
            // `ou_id=0` znamená „přímo pod doménou“. Nula není platné id
            // žádné OU, takže se nedá splést s existující jednotkou,
            // a v SQL se `ou_id IS NULL` jinak zapsat nedá.
            (Some(0), _) => casti.push("ou_id IS NULL".to_string()),
            (Some(id), Scope::Level) => {
                casti.push(format!("ou_id = ?{}", hodnoty.len() + 1));
                hodnoty.push(Box::new(id));
            }
            (Some(id), Scope::Subtree) => {
                let ids = self.potomci_ou(id)?;
                let zacatek = hodnoty.len() + 1;
                let placeholdery: Vec<String> =
                    (0..ids.len()).map(|i| format!("?{}", zacatek + i)).collect();
                casti.push(format!("ou_id IN ({})", placeholdery.join(", ")));
                for i in ids {
                    hodnoty.push(Box::new(i));
                }
            }
        }

        let kde = if casti.is_empty() { "1 = 1".to_string() } else { casti.join(" AND ") };
        Ok((kde, hodnoty))
    }

    /// Vytvoří uživatele. Heslo se ověří proti platné zásadě a uloží
    /// jako Argon2id.
    pub fn vytvor_uzivatele(&self, req: &proto::CreateUserRequest) -> Result<User> {
        let sam = names::validuj_prihlasovaci_jmeno(&req.sam_account_name)?;
        if names::je_vyhrazene_jmeno(&sam) {
            return Err(AdError::new(
                ErrorCode::ReservedName,
                format!("jméno {sam} je vyhrazené systémem"),
            ));
        }
        let jmeno = names::validuj_popis(&req.given_name)?;
        let prijmeni = names::validuj_popis(&req.surname)?;
        let email = names::validuj_popis(&req.email)?;
        let popis = names::validuj_popis(&req.description)?;
        if let Some(ou) = req.ou_id {
            self.ou(ou)?;
        }

        let zasada = self.efektivni_zasada(req.ou_id)?;
        password::zkontroluj(req.password.odhal(), &zasada.password, Some(&sam), &[])?;
        let hash = password::zahasuj(req.password.odhal())?;

        let zobrazovane = match &req.display_name {
            Some(d) if !d.trim().is_empty() => names::validuj_popis(d)?,
            _ => {
                let spojene = format!("{jmeno} {prijmeni}").trim().to_string();
                if spojene.is_empty() {
                    sam.clone()
                } else {
                    spojene
                }
            }
        };

        let guid = ad_core::ids::novy_guid();
        let nyni = cas_do_db(ad_core::nyni());
        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        let novy_rid = Store::dalsi_rid(&tx)?;
        tx.execute(
            "INSERT INTO users(guid, rid, sam, password_hash, display_name, given_name,
                 surname, email, description, ou_id, enabled, must_change_password,
                 password_never_expires, password_set_at, builtin, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,0,?15)",
            params![
                guid.to_string(),
                novy_rid as i64,
                sam,
                hash,
                zobrazovane,
                jmeno,
                prijmeni,
                email,
                popis,
                req.ou_id,
                req.enabled as i64,
                req.must_change_password as i64,
                req.password_never_expires as i64,
                nyni,
                nyni
            ],
        )
        .map_err(db_chyba)?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO password_history(user_id, password_hash, set_at) VALUES (?1,?2,?3)",
            params![id, self::prazdny_ok(&tx, id)?, nyni],
        )
        .ok();
        // Každý uživatel je ve skupině Domain Users.
        if let Some(du) = skupina_podle_rid(&tx, rid::DOMAIN_USERS)? {
            tx.execute(
                "INSERT OR IGNORE INTO group_members(group_id, member_kind, member_id, added_at)
                 VALUES (?1, 'user', ?2, ?3)",
                params![du, id, nyni],
            )
            .map_err(db_chyba)?;
        }
        for g in &req.groups {
            tx.execute(
                "INSERT OR IGNORE INTO group_members(group_id, member_kind, member_id, added_at)
                 VALUES (?1, 'user', ?2, ?3)",
                params![g, id, nyni],
            )
            .map_err(db_chyba)?;
        }
        tx.commit().map_err(db_chyba)?;
        drop(c);
        self.uzivatel(id)
    }

    pub fn uprav_uzivatele(&self, id: i64, req: &proto::UpdateUserRequest) -> Result<User> {
        let stary = self.uzivatel(id)?;
        if let Some(Some(ou)) = req.ou_id {
            self.ou(ou)?;
        }
        let jmeno = match &req.given_name {
            Some(v) => names::validuj_popis(v)?,
            None => stary.given_name.clone(),
        };
        let prijmeni = match &req.surname {
            Some(v) => names::validuj_popis(v)?,
            None => stary.surname.clone(),
        };
        let zobrazovane = match &req.display_name {
            Some(v) => names::validuj_popis(v)?,
            None => stary.display_name.clone(),
        };
        let email = match &req.email {
            Some(v) => names::validuj_popis(v)?,
            None => stary.email.clone(),
        };
        let popis = match &req.description {
            Some(v) => names::validuj_popis(v)?,
            None => stary.description.clone(),
        };
        let enabled = req.enabled.unwrap_or(stary.enabled);
        if stary.builtin && !enabled && stary.sid.rid == rid::ADMINISTRATOR {
            return Err(AdError::conflict(
                "vestavěný účet správce se nedá vypnout — zamkl bys sám sebe",
            ));
        }
        let ou = match req.ou_id {
            Some(v) => v,
            None => stary.ou_id,
        };

        let c = self.lock();
        c.execute(
            "UPDATE users SET given_name=?1, surname=?2, display_name=?3, email=?4,
                 description=?5, enabled=?6, must_change_password=?7,
                 password_never_expires=?8, ou_id=?9
             WHERE id = ?10",
            params![
                jmeno,
                prijmeni,
                zobrazovane,
                email,
                popis,
                enabled as i64,
                req.must_change_password.unwrap_or(stary.must_change_password) as i64,
                req.password_never_expires.unwrap_or(stary.password_never_expires) as i64,
                ou,
                id
            ],
        )
        .map_err(db_chyba)?;
        drop(c);
        self.uzivatel(id)
    }

    /// Nastaví heslo správcem.
    pub fn nastav_heslo(
        &self,
        id: i64,
        nove: &str,
        musi_zmenit: bool,
        preskocit_historii: bool,
    ) -> Result<()> {
        let u = self.uzivatel(id)?;
        let zasada = self.efektivni_zasada(u.ou_id)?;
        let historie = if preskocit_historii {
            Vec::new()
        } else {
            self.historie_hesel(id, zasada.password.history_length)?
        };
        password::zkontroluj(nove, &zasada.password, Some(&u.sam_account_name), &historie)?;
        let hash = password::zahasuj(nove)?;
        let nyni = cas_do_db(ad_core::nyni());

        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        tx.execute(
            "UPDATE users SET password_hash = ?1, password_set_at = ?2,
                 must_change_password = ?3, failed_logons = 0, first_failed_at = NULL,
                 locked_until = NULL
             WHERE id = ?4",
            params![hash, nyni, musi_zmenit as i64, id],
        )
        .map_err(db_chyba)?;
        tx.execute(
            "INSERT INTO password_history(user_id, password_hash, set_at) VALUES (?1,?2,?3)",
            params![id, hash, nyni],
        )
        .map_err(db_chyba)?;
        // Historii držíme krátkou — 24 je strop ze zásady.
        tx.execute(
            "DELETE FROM password_history WHERE user_id = ?1 AND id NOT IN
                (SELECT id FROM password_history WHERE user_id = ?1 ORDER BY id DESC LIMIT 24)",
            params![id],
        )
        .map_err(db_chyba)?;
        tx.commit().map_err(db_chyba)?;
        Ok(())
    }

    pub(crate) fn historie_hesel(&self, id: i64, kolik: u8) -> Result<Vec<String>> {
        if kolik == 0 {
            return Ok(Vec::new());
        }
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT password_hash FROM password_history WHERE user_id = ?1
                 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(db_chyba)?;
        let v = stmt
            .query_map(params![id, kolik as i64], |r| r.get::<_, String>(0))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    pub fn odemkni_uzivatele(&self, id: i64) -> Result<()> {
        let c = self.lock();
        let zmeneno = c
            .execute(
                "UPDATE users SET locked_until = NULL, failed_logons = 0,
                     first_failed_at = NULL WHERE id = ?1",
                [id],
            )
            .map_err(db_chyba)?;
        if zmeneno == 0 {
            return Err(AdError::not_found("uživatel neexistuje"));
        }
        Ok(())
    }

    pub fn smaz_uzivatele(&self, id: i64) -> Result<String> {
        let u = self.uzivatel(id)?;
        if u.builtin {
            return Err(AdError::conflict(format!(
                "{} je vestavěný účet a nedá se smazat (dá se vypnout)",
                u.sam_account_name
            )));
        }
        let c = self.lock();
        c.execute("DELETE FROM users WHERE id = ?1", [id]).map_err(db_chyba)?;
        c.execute("DELETE FROM group_members WHERE member_kind = 'user' AND member_id = ?1", [id])
            .map_err(db_chyba)?;
        Ok(u.sam_account_name)
    }

    pub fn presun_uzivatele(&self, id: i64, ou: Option<i64>) -> Result<User> {
        if let Some(o) = ou {
            self.ou(o)?;
        }
        let c = self.lock();
        c.execute("UPDATE users SET ou_id = ?1 WHERE id = ?2", params![ou, id])
            .map_err(db_chyba)?;
        drop(c);
        self.uzivatel(id)
    }

    // ===================================================================
    // Skupiny
    // ===================================================================

    pub fn skupina(&self, id: i64) -> Result<Group> {
        let d = self.domena_nebo_chyba()?;
        let c = self.lock();
        let mut g = c
            .query_row(&format!("SELECT {SLOUPCE_SKUPINY} FROM groups WHERE id = ?1"), [id], |r| {
                skupina_z_radku(r, d.domain_sid)
            })
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::not_found(format!("skupina {id} neexistuje")))?;
        g.member_count = c
            .query_row("SELECT COUNT(*) FROM group_members WHERE group_id = ?1", [id], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(db_chyba)? as u32;
        Ok(g)
    }

    /// Hledání skupiny podle přihlašovacího jména (použije web ve fázi 3).
    #[allow(dead_code)]
    pub fn skupina_podle_sam(&self, sam: &str) -> Result<Option<Group>> {
        let d = self.domena_nebo_chyba()?;
        let sam = sam.to_ascii_lowercase();
        let c = self.lock();
        c.query_row(&format!("SELECT {SLOUPCE_SKUPINY} FROM groups WHERE sam = ?1"), [&sam], |r| {
            skupina_z_radku(r, d.domain_sid)
        })
        .optional()
        .map_err(db_chyba)
    }

    pub fn seznam_skupin(&self, q: &ListQuery) -> Result<Page<Group>> {
        let d = self.domena_nebo_chyba()?;
        let mut casti: Vec<String> = Vec::new();
        let mut hodnoty: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(text) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let vzor = format!("%{}%", text.to_lowercase());
            casti.push(format!(
                "(LOWER(sam) LIKE ?{0} OR LOWER(name) LIKE ?{0})",
                hodnoty.len() + 1
            ));
            hodnoty.push(Box::new(vzor));
        }
        match q.ou_id {
            None => {}
            Some(0) => casti.push("ou_id IS NULL".to_string()),
            Some(ou) => {
                casti.push(format!("ou_id = ?{}", hodnoty.len() + 1));
                hodnoty.push(Box::new(ou));
            }
        }
        let kde = if casti.is_empty() { "1 = 1".to_string() } else { casti.join(" AND ") };

        let c = self.lock();
        let total: i64 = c
            .query_row(
                &format!("SELECT COUNT(*) FROM groups WHERE {kde}"),
                params_from_iter(hodnoty.iter()),
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        let sql = format!(
            "SELECT {SLOUPCE_SKUPINY} FROM groups WHERE {kde} ORDER BY name
             LIMIT ?{} OFFSET ?{}",
            hodnoty.len() + 1,
            hodnoty.len() + 2
        );
        hodnoty.push(Box::new(q.limit() as i64));
        hodnoty.push(Box::new(q.offset() as i64));
        let mut stmt = c.prepare(&sql).map_err(db_chyba)?;
        let mut items = stmt
            .query_map(params_from_iter(hodnoty.iter()), |r| skupina_z_radku(r, d.domain_sid))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        for g in &mut items {
            g.member_count = c
                .query_row("SELECT COUNT(*) FROM group_members WHERE group_id = ?1", [g.id], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(db_chyba)? as u32;
        }
        Ok(Page { items, total: total as u64, offset: q.offset(), limit: q.limit() })
    }

    pub fn vytvor_skupinu(&self, req: &proto::CreateGroupRequest) -> Result<Group> {
        let jmeno = names::validuj_jmeno_objektu(&req.name)?;
        let sam = match &req.sam_account_name {
            Some(s) => names::validuj_prihlasovaci_jmeno(s)?,
            None => odvod_sam_skupiny(&jmeno)?,
        };
        if names::je_vyhrazene_jmeno(&sam) {
            return Err(AdError::new(ErrorCode::ReservedName, format!("jméno {sam} je vyhrazené")));
        }
        let popis = names::validuj_popis(&req.description)?;
        if let Some(ou) = req.ou_id {
            self.ou(ou)?;
        }
        let guid = ad_core::ids::novy_guid();
        let nyni = cas_do_db(ad_core::nyni());
        let kind = match req.kind {
            GroupKind::Security => "security",
            GroupKind::Distribution => "distribution",
        };

        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        let novy_rid = Store::dalsi_rid(&tx)?;
        tx.execute(
            "INSERT INTO groups(guid, rid, sam, name, description, kind, ou_id, builtin, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8)",
            params![guid.to_string(), novy_rid as i64, sam, jmeno, popis, kind, req.ou_id, nyni],
        )
        .map_err(db_chyba)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(db_chyba)?;
        drop(c);
        self.skupina(id)
    }

    pub fn smaz_skupinu(&self, id: i64) -> Result<String> {
        let g = self.skupina(id)?;
        if g.builtin {
            return Err(AdError::conflict(format!(
                "{} je vestavěná skupina a nedá se smazat",
                g.name
            )));
        }
        let c = self.lock();
        c.execute("DELETE FROM groups WHERE id = ?1", [id]).map_err(db_chyba)?;
        Ok(g.name)
    }

    pub fn uprav_skupinu(
        &self,
        id: i64,
        jmeno: Option<&str>,
        popis: Option<&str>,
    ) -> Result<Group> {
        let stara = self.skupina(id)?;
        if stara.builtin && jmeno.is_some() {
            return Err(AdError::conflict("vestavěná skupina se nedá přejmenovat"));
        }
        let nove_jmeno = match jmeno {
            Some(j) => names::validuj_jmeno_objektu(j)?,
            None => stara.name.clone(),
        };
        let novy_popis = match popis {
            Some(p) => names::validuj_popis(p)?,
            None => stara.description.clone(),
        };
        let c = self.lock();
        c.execute(
            "UPDATE groups SET name = ?1, description = ?2 WHERE id = ?3",
            params![nove_jmeno, novy_popis, id],
        )
        .map_err(db_chyba)?;
        drop(c);
        self.skupina(id)
    }

    pub fn presun_skupinu(&self, id: i64, ou: Option<i64>) -> Result<Group> {
        if let Some(o) = ou {
            self.ou(o)?;
        }
        self.skupina(id)?;
        let c = self.lock();
        c.execute("UPDATE groups SET ou_id = ?1 WHERE id = ?2", params![ou, id])
            .map_err(db_chyba)?;
        drop(c);
        self.skupina(id)
    }

    pub fn presun_pocitac(&self, id: i64, ou: Option<i64>) -> Result<Computer> {
        if let Some(o) = ou {
            self.ou(o)?;
        }
        self.pocitac(id)?;
        let c = self.lock();
        c.execute("UPDATE computers SET ou_id = ?1 WHERE id = ?2", params![ou, id])
            .map_err(db_chyba)?;
        drop(c);
        self.pocitac(id)
    }

    pub fn clenove(&self, group_id: i64) -> Result<Vec<GroupMember>> {
        let d = self.domena_nebo_chyba()?;
        self.skupina(group_id)?;
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT member_kind, member_id FROM group_members WHERE group_id = ?1
                 ORDER BY member_kind, member_id",
            )
            .map_err(db_chyba)?;
        let zaznamy: Vec<(String, i64)> = stmt
            .query_map([group_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        let mut vysledek = Vec::new();
        for (druh, id) in zaznamy {
            let (tabulka, sloupec, kind) = match druh.as_str() {
                "user" => ("users", "sam", MemberKind::User),
                "group" => ("groups", "name", MemberKind::Group),
                _ => ("computers", "name", MemberKind::Computer),
            };
            let nalezeno: Option<(String, i64)> = c
                .query_row(
                    &format!("SELECT {sloupec}, rid FROM {tabulka} WHERE id = ?1"),
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db_chyba)?;
            if let Some((jmeno, r)) = nalezeno {
                vysledek.push(GroupMember {
                    kind,
                    id,
                    sid: d.domain_sid.sid(u32::try_from(r).unwrap_or(0)),
                    name: jmeno,
                });
            }
        }
        Ok(vysledek)
    }

    pub fn pridej_cleny(&self, group_id: i64, clenove: &[proto::MemberRef]) -> Result<usize> {
        self.skupina(group_id)?;
        let nyni = cas_do_db(ad_core::nyni());
        let mut pridano = 0;
        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        for m in clenove {
            let druh = druh_textem(m.kind);
            // Zabráníme tomu, aby skupina byla členem sebe sama.
            if m.kind == MemberKind::Group && m.id == group_id {
                return Err(AdError::conflict("skupina nemůže být členem sebe sama"));
            }
            if m.kind == MemberKind::Group && je_cyklus(&tx, m.id, group_id)? {
                return Err(AdError::conflict("takové členství by vytvořilo kruh ve skupinách"));
            }
            let existuje: i64 = tx
                .query_row(
                    &format!("SELECT COUNT(*) FROM {} WHERE id = ?1", tabulka_pro(m.kind)),
                    [m.id],
                    |r| r.get(0),
                )
                .map_err(db_chyba)?;
            if existuje == 0 {
                return Err(AdError::not_found(format!("člen {} {} neexistuje", druh, m.id)));
            }
            pridano += tx
                .execute(
                    "INSERT OR IGNORE INTO group_members(group_id, member_kind, member_id, added_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![group_id, druh, m.id, nyni],
                )
                .map_err(db_chyba)?;
        }
        tx.commit().map_err(db_chyba)?;
        Ok(pridano)
    }

    pub fn odeber_cleny(&self, group_id: i64, clenove: &[proto::MemberRef]) -> Result<usize> {
        let g = self.skupina(group_id)?;
        let mut odebrano = 0;
        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        for m in clenove {
            // Poslední správce domény nesmí zmizet, jinak se do správy
            // nikdo nedostane.
            if g.sid.rid == rid::DOMAIN_ADMINS {
                let pocet: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM group_members WHERE group_id = ?1",
                        [group_id],
                        |r| r.get(0),
                    )
                    .map_err(db_chyba)?;
                if pocet <= 1 {
                    return Err(AdError::conflict(
                        "ve skupině správců domény musí zůstat alespoň jeden člen",
                    ));
                }
            }
            odebrano += tx
                .execute(
                    "DELETE FROM group_members WHERE group_id = ?1 AND member_kind = ?2
                     AND member_id = ?3",
                    params![group_id, druh_textem(m.kind), m.id],
                )
                .map_err(db_chyba)?;
        }
        tx.commit().map_err(db_chyba)?;
        Ok(odebrano)
    }

    /// Jména skupin, ve kterých uživatel je — **včetně vnořených**.
    pub fn skupiny_uzivatele(&self, user_id: i64) -> Result<Vec<String>> {
        let ids = self.skupiny_uzivatele_ids(user_id)?;
        let c = self.lock();
        let mut jmena = Vec::new();
        for id in ids {
            let j: Option<String> = c
                .query_row("SELECT name FROM groups WHERE id = ?1", [id], |r| r.get(0))
                .optional()
                .map_err(db_chyba)?;
            if let Some(j) = j {
                jmena.push(j);
            }
        }
        jmena.sort();
        Ok(jmena)
    }

    /// Id skupin uživatele včetně vnořených (průchod do šířky).
    pub fn skupiny_uzivatele_ids(&self, user_id: i64) -> Result<Vec<i64>> {
        let c = self.lock();
        let mut k_prozkoumani: Vec<i64> = {
            let mut stmt = c
                .prepare(
                    "SELECT group_id FROM group_members
                     WHERE member_kind = 'user' AND member_id = ?1",
                )
                .map_err(db_chyba)?;
            let v: Vec<i64> = stmt
                .query_map([user_id], |r| r.get::<_, i64>(0))
                .map_err(db_chyba)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db_chyba)?;
            v
        };
        let mut nalezene: Vec<i64> = Vec::new();
        let mut pojistka = 0;
        while let Some(g) = k_prozkoumani.pop() {
            pojistka += 1;
            if pojistka > 1000 {
                return Err(AdError::internal("příliš mnoho vnořených skupin"));
            }
            if nalezene.contains(&g) {
                continue;
            }
            nalezene.push(g);
            let mut stmt = c
                .prepare(
                    "SELECT group_id FROM group_members
                     WHERE member_kind = 'group' AND member_id = ?1",
                )
                .map_err(db_chyba)?;
            let nadrazene: Vec<i64> = stmt
                .query_map([g], |r| r.get::<_, i64>(0))
                .map_err(db_chyba)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db_chyba)?;
            k_prozkoumani.extend(nadrazene);
        }
        Ok(nalezene)
    }

    /// Je uživatel ve skupině s daným RID (např. správci domény)?
    pub fn je_ve_skupine_rid(&self, user_id: i64, hledany_rid: u32) -> Result<bool> {
        let ids = self.skupiny_uzivatele_ids(user_id)?;
        let c = self.lock();
        for id in ids {
            let r: Option<i64> = c
                .query_row("SELECT rid FROM groups WHERE id = ?1", [id], |x| x.get(0))
                .optional()
                .map_err(db_chyba)?;
            if r == Some(hledany_rid as i64) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ===================================================================
    // Počítače
    // ===================================================================

    pub fn pocitac(&self, id: i64) -> Result<Computer> {
        let d = self.domena_nebo_chyba()?;
        let c = self.lock();
        c.query_row(&format!("SELECT {SLOUPCE_POCITACE} FROM computers WHERE id = ?1"), [id], |r| {
            pocitac_z_radku(r, d.domain_sid)
        })
        .optional()
        .map_err(db_chyba)?
        .ok_or_else(|| AdError::not_found(format!("počítač {id} neexistuje")))
    }

    pub fn pocitac_podle_guid(&self, guid: Guid) -> Result<Option<Computer>> {
        let d = self.domena_nebo_chyba()?;
        let c = self.lock();
        c.query_row(
            &format!("SELECT {SLOUPCE_POCITACE} FROM computers WHERE guid = ?1"),
            [guid.to_string()],
            |r| pocitac_z_radku(r, d.domain_sid),
        )
        .optional()
        .map_err(db_chyba)
    }

    pub fn pocitac_podle_jmena(&self, jmeno: &str) -> Result<Option<Computer>> {
        let d = self.domena_nebo_chyba()?;
        let jmeno = jmeno.to_ascii_uppercase();
        let c = self.lock();
        c.query_row(
            &format!("SELECT {SLOUPCE_POCITACE} FROM computers WHERE name = ?1"),
            [&jmeno],
            |r| pocitac_z_radku(r, d.domain_sid),
        )
        .optional()
        .map_err(db_chyba)
    }

    pub(crate) fn hash_tajemstvi_pocitace(&self, id: i64) -> Result<String> {
        let c = self.lock();
        c.query_row("SELECT secret_hash FROM computers WHERE id = ?1", [id], |r| r.get(0))
            .optional()
            .map_err(db_chyba)?
            .ok_or_else(|| AdError::new(ErrorCode::MachineUnknown, "počítač neexistuje"))
    }

    pub fn seznam_pocitacu(&self, q: &ListQuery) -> Result<Page<Computer>> {
        let d = self.domena_nebo_chyba()?;
        let mut casti: Vec<String> = Vec::new();
        let mut hodnoty: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(text) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let vzor = format!("%{}%", text.to_lowercase());
            casti.push(format!(
                "(LOWER(name) LIKE ?{0} OR LOWER(dns_name) LIKE ?{0})",
                hodnoty.len() + 1
            ));
            hodnoty.push(Box::new(vzor));
        }
        match q.ou_id {
            None => {}
            Some(0) => casti.push("ou_id IS NULL".to_string()),
            Some(ou) => {
                casti.push(format!("ou_id = ?{}", hodnoty.len() + 1));
                hodnoty.push(Box::new(ou));
            }
        }
        let kde = if casti.is_empty() { "1 = 1".to_string() } else { casti.join(" AND ") };
        let c = self.lock();
        let total: i64 = c
            .query_row(
                &format!("SELECT COUNT(*) FROM computers WHERE {kde}"),
                params_from_iter(hodnoty.iter()),
                |r| r.get(0),
            )
            .map_err(db_chyba)?;
        let sql = format!(
            "SELECT {SLOUPCE_POCITACE} FROM computers WHERE {kde} ORDER BY name
             LIMIT ?{} OFFSET ?{}",
            hodnoty.len() + 1,
            hodnoty.len() + 2
        );
        hodnoty.push(Box::new(q.limit() as i64));
        hodnoty.push(Box::new(q.offset() as i64));
        let mut stmt = c.prepare(&sql).map_err(db_chyba)?;
        let items = stmt
            .query_map(params_from_iter(hodnoty.iter()), |r| pocitac_z_radku(r, d.domain_sid))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(Page { items, total: total as u64, offset: q.offset(), limit: q.limit() })
    }

    /// Vytvoří počítačový účet a vrátí ho spolu s tajemstvím.
    /// Tajemství se vrací **jen tady** a nikdy se nedá přečíst znovu.
    pub fn vytvor_pocitac(
        &self,
        jmeno: &str,
        ou_id: Option<i64>,
        popis: &str,
        os_name: &str,
        os_version: &str,
        ip: &str,
    ) -> Result<(Computer, secret::Tajne)> {
        let d = self.domena_nebo_chyba()?;
        let jmeno = names::validuj_jmeno_pocitace(jmeno)?;
        let popis = names::validuj_popis(popis)?;
        if let Some(ou) = ou_id {
            self.ou(ou)?;
        }
        let tajemstvi = secret::nove_tajemstvi_pocitace();
        // Tajemství je 256 bitů náhody od nás, ale i tak ho hašujeme
        // Argon2id — kdyby někdo přečetl databázi, nesmí se vydávat
        // za počítač.
        let hash = password::zahasuj(&tajemstvi)?;
        let guid = ad_core::ids::novy_guid();
        let nyni = cas_do_db(ad_core::nyni());
        let dns_name = format!("{}.{}", jmeno.to_ascii_lowercase(), d.dns_name);

        let mut c = self.lock();
        let tx = c.transaction().map_err(db_chyba)?;
        let novy_rid = Store::dalsi_rid(&tx)?;
        tx.execute(
            "INSERT INTO computers(guid, rid, name, dns_name, secret_hash, description,
                 ou_id, enabled, os_name, os_version, last_ip, joined_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,1,?8,?9,?10,?11)",
            params![
                guid.to_string(),
                novy_rid as i64,
                jmeno,
                dns_name,
                hash,
                popis,
                ou_id,
                omez_text(os_name, 80),
                omez_text(os_version, 40),
                omez_text(ip, 45),
                nyni
            ],
        )
        .map_err(db_chyba)?;
        let id = tx.last_insert_rowid();
        if let Some(dc) = skupina_podle_rid(&tx, rid::DOMAIN_COMPUTERS)? {
            tx.execute(
                "INSERT OR IGNORE INTO group_members(group_id, member_kind, member_id, added_at)
                 VALUES (?1, 'computer', ?2, ?3)",
                params![dc, id, nyni],
            )
            .map_err(db_chyba)?;
        }
        tx.commit().map_err(db_chyba)?;
        drop(c);
        Ok((self.pocitac(id)?, secret::Tajne::new(tajemstvi)))
    }

    /// Zapíše, že se počítač ohlásil.
    pub fn oznac_videni(&self, id: i64, ip: &str, os_name: &str, os_version: &str) -> Result<()> {
        let c = self.lock();
        c.execute(
            "UPDATE computers SET last_seen_at = ?1, last_ip = ?2,
                 os_name = CASE WHEN ?3 = '' THEN os_name ELSE ?3 END,
                 os_version = CASE WHEN ?4 = '' THEN os_version ELSE ?4 END
             WHERE id = ?5",
            params![
                cas_do_db(ad_core::nyni()),
                omez_text(ip, 45),
                omez_text(os_name, 80),
                omez_text(os_version, 40),
                id
            ],
        )
        .map_err(db_chyba)?;
        Ok(())
    }

    pub fn smaz_pocitac(&self, id: i64) -> Result<String> {
        let p = self.pocitac(id)?;
        let c = self.lock();
        c.execute("DELETE FROM computers WHERE id = ?1", [id]).map_err(db_chyba)?;
        c.execute(
            "DELETE FROM group_members WHERE member_kind = 'computer' AND member_id = ?1",
            [id],
        )
        .map_err(db_chyba)?;
        Ok(p.name)
    }
}

// -----------------------------------------------------------------------
// Pomocné
// -----------------------------------------------------------------------

/// Zkrátí text od klienta na rozumnou délku. Klient si může napsat
/// cokoli, ale do databáze se vejde jen tolik.
pub(crate) fn omez_text(s: &str, max: usize) -> String {
    let cisty: String = s.chars().filter(|c| !c.is_control()).collect();
    cisty.chars().take(max).collect()
}

fn tabulka_pro(k: MemberKind) -> &'static str {
    match k {
        MemberKind::User => "users",
        MemberKind::Group => "groups",
        MemberKind::Computer => "computers",
    }
}

fn druh_textem(k: MemberKind) -> &'static str {
    match k {
        MemberKind::User => "user",
        MemberKind::Group => "group",
        MemberKind::Computer => "computer",
    }
}

/// Odvodí přihlašovací jméno skupiny z jejího jména.
pub fn odvod_sam_skupiny(jmeno: &str) -> Result<String> {
    let mut s = String::new();
    for c in jmeno.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if matches!(c, ' ' | '-' | '_' | '.') && !s.ends_with('-') {
            s.push('-');
        } else if !c.is_ascii() {
            // Diakritika: hrubé zjednodušení pro čeština -> ASCII.
            s.push(match c {
                'á' | 'ä' | 'à' => 'a',
                'č' => 'c',
                'ď' => 'd',
                'é' | 'ě' | 'ë' => 'e',
                'í' | 'ï' => 'i',
                'ň' => 'n',
                'ó' | 'ö' => 'o',
                'ř' => 'r',
                'š' => 's',
                'ť' => 't',
                'ú' | 'ů' | 'ü' => 'u',
                'ý' => 'y',
                'ž' => 'z',
                _ => '-',
            });
        }
    }
    let s = s.trim_matches('-').to_string();
    let s: String = s.chars().take(names::MAX_SAM).collect();
    names::validuj_prihlasovaci_jmeno(&s)
}

fn skupina_podle_rid(tx: &rusqlite::Transaction<'_>, r: u32) -> Result<Option<i64>> {
    tx.query_row("SELECT id FROM groups WHERE rid = ?1", [r as i64], |x| x.get(0))
        .optional()
        .map_err(db_chyba)
}

/// Pomůcka pro zápis prvního hesla do historie — vrátí haš, který už
/// je v `users`.
fn prazdny_ok(tx: &rusqlite::Transaction<'_>, user_id: i64) -> Result<String> {
    tx.query_row("SELECT password_hash FROM users WHERE id = ?1", [user_id], |r| r.get(0))
        .map_err(db_chyba)
}

/// Vedlo by členství `vnorena` v `nadrazena` ke kruhu?
fn je_cyklus(tx: &rusqlite::Transaction<'_>, vnorena: i64, nadrazena: i64) -> Result<bool> {
    // Hledáme, jestli `nadrazena` není (tranzitivně) členem `vnorena`.
    let mut front = vec![nadrazena];
    let mut videne: Vec<i64> = Vec::new();
    let mut pojistka = 0;
    while let Some(g) = front.pop() {
        pojistka += 1;
        if pojistka > 1000 {
            return Err(AdError::internal("příliš mnoho vnořených skupin"));
        }
        if g == vnorena {
            return Ok(true);
        }
        if videne.contains(&g) {
            continue;
        }
        videne.push(g);
        let mut stmt = tx
            .prepare(
                "SELECT member_id FROM group_members WHERE group_id = ?1 AND member_kind = 'group'",
            )
            .map_err(db_chyba)?;
        let deti: Vec<i64> = stmt
            .query_map([g], |r| r.get::<_, i64>(0))
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        front.extend(deti);
    }
    Ok(false)
}
