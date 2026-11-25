//! DNS zóny a záznamy v databázi.
//!
//! Vlastní DNS server (fáze 4) z tohohle staví odpovědi. Tady je jen
//! práce s daty — zakládání zón, záznamy a automatická registrace
//! počítačů při připojení do domény.

use super::{cas_do_db, db_chyba, Store};
use ad_core::dns::{self, Record, RecordData, Zone, ZoneKind};
use ad_core::model::Computer;
use ad_core::proto::{CreateRecordRequest, CreateZoneRequest};
use ad_core::{AdError, ErrorCode, Result};
use rusqlite::{params, OptionalExtension, Row};
use std::net::{IpAddr, Ipv4Addr};

const SLOUPCE_ZONY: &str = "id, name, kind, serial, primary_ns, rname, refresh, retry, \
     expire, minimum, managed";

fn zona_z_radku(r: &Row<'_>) -> rusqlite::Result<Zone> {
    let kind: String = r.get(2)?;
    Ok(Zone {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: if kind == "reverse" { ZoneKind::Reverse } else { ZoneKind::Forward },
        serial: u32::try_from(r.get::<_, i64>(3)?).unwrap_or(1),
        primary_ns: r.get(4)?,
        rname: r.get(5)?,
        refresh: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(3600),
        retry: u32::try_from(r.get::<_, i64>(7)?).unwrap_or(600),
        expire: u32::try_from(r.get::<_, i64>(8)?).unwrap_or(604_800),
        minimum: u32::try_from(r.get::<_, i64>(9)?).unwrap_or(3600),
        managed: r.get::<_, i64>(10)? != 0,
    })
}

fn zaznam_z_radku(r: &Row<'_>) -> rusqlite::Result<Record> {
    let json: String = r.get(4)?;
    let data: RecordData = serde_json::from_str(&json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            format!("neplatná data DNS záznamu: {e}").into(),
        )
    })?;
    Ok(Record {
        id: r.get(0)?,
        zone_id: r.get(1)?,
        name: r.get(2)?,
        ttl: u32::try_from(r.get::<_, i64>(3)?).unwrap_or(3600),
        data,
        managed: r.get::<_, i64>(5)? != 0,
    })
}

impl Store {
    pub fn zony(&self) -> Result<Vec<Zone>> {
        let c = self.lock();
        let mut stmt = c
            .prepare(&format!("SELECT {SLOUPCE_ZONY} FROM dns_zones ORDER BY kind, name"))
            .map_err(db_chyba)?;
        let v = stmt
            .query_map([], zona_z_radku)
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    pub fn zona(&self, id: i64) -> Result<Zone> {
        let c = self.lock();
        c.query_row(
            &format!("SELECT {SLOUPCE_ZONY} FROM dns_zones WHERE id = ?1"),
            [id],
            zona_z_radku,
        )
        .optional()
        .map_err(db_chyba)?
        .ok_or_else(|| AdError::new(ErrorCode::ZoneNotFound, format!("zóna {id} neexistuje")))
    }

    pub fn zona_podle_jmena(&self, jmeno: &str) -> Result<Option<Zone>> {
        let jmeno = jmeno.trim_end_matches('.').to_ascii_lowercase();
        let c = self.lock();
        c.query_row(
            &format!("SELECT {SLOUPCE_ZONY} FROM dns_zones WHERE name = ?1"),
            [&jmeno],
            zona_z_radku,
        )
        .optional()
        .map_err(db_chyba)
    }

    /// Najde zónu, do které jméno patří — nejdelší shoda vyhrává.
    pub fn zona_pro_jmeno(&self, plne_jmeno: &str) -> Result<Option<Zone>> {
        let mut nejlepsi: Option<Zone> = None;
        for z in self.zony()? {
            if dns::patri_do_zony(plne_jmeno, &z.name) {
                match &nejlepsi {
                    Some(stara) if stara.name.len() >= z.name.len() => {}
                    _ => nejlepsi = Some(z),
                }
            }
        }
        Ok(nejlepsi)
    }

    pub fn zaznamy(&self, zone_id: i64) -> Result<Vec<Record>> {
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT id, zone_id, name, ttl, rdata_json, managed FROM dns_records
                 WHERE zone_id = ?1 ORDER BY name, rtype",
            )
            .map_err(db_chyba)?;
        let v = stmt
            .query_map([zone_id], zaznam_z_radku)
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    /// Najde záznamy pro dotaz — to používá DNS server ve fázi 4.
    #[allow(dead_code)]
    pub fn najdi_zaznamy(&self, zone_id: i64, jmeno: &str, typ: &str) -> Result<Vec<Record>> {
        let c = self.lock();
        let mut stmt = c
            .prepare(
                "SELECT id, zone_id, name, ttl, rdata_json, managed FROM dns_records
                 WHERE zone_id = ?1 AND name = ?2 AND rtype = ?3",
            )
            .map_err(db_chyba)?;
        let v = stmt
            .query_map(params![zone_id, jmeno, typ], zaznam_z_radku)
            .map_err(db_chyba)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_chyba)?;
        Ok(v)
    }

    pub fn vytvor_zonu(&self, req: &CreateZoneRequest) -> Result<Zone> {
        let d = self.domena_nebo_chyba()?;
        let jmeno = match req.kind {
            ZoneKind::Forward => {
                let j = req
                    .name
                    .as_deref()
                    .ok_or_else(|| AdError::bad_request("dopředná zóna potřebuje jméno"))?;
                let k = ad_core::names::validuj_jmeno_domeny(j)?;
                k.fqdn
            }
            ZoneKind::Reverse => {
                let sit = req.network.as_deref().ok_or_else(|| {
                    AdError::bad_request("reverzní zóna potřebuje síť, např. 192.168.56.0/24")
                })?;
                let (adresa, prefix) = rozdel_cidr(sit)?;
                dns::reverzni_zona_ipv4(adresa, prefix)?
            }
        };
        if self.zona_podle_jmena(&jmeno)?.is_some() {
            return Err(AdError::conflict(format!("zóna {jmeno} už existuje")));
        }
        let nyni = cas_do_db(ad_core::nyni());
        let c = self.lock();
        c.execute(
            "INSERT INTO dns_zones(name, kind, serial, primary_ns, rname, managed, created_at)
             VALUES (?1, ?2, 1, ?3, ?4, 0, ?5)",
            params![
                jmeno,
                if req.kind == ZoneKind::Reverse { "reverse" } else { "forward" },
                d.dc_fqdn,
                format!("hostmaster.{}", d.dns_name),
                nyni
            ],
        )
        .map_err(db_chyba)?;
        let id = c.last_insert_rowid();
        drop(c);
        self.zona(id)
    }

    pub fn smaz_zonu(&self, id: i64) -> Result<String> {
        let z = self.zona(id)?;
        if z.managed {
            return Err(AdError::conflict(format!(
                "zóna {} patří doméně a nedá se smazat, dokud doména existuje",
                z.name
            )));
        }
        let c = self.lock();
        c.execute("DELETE FROM dns_zones WHERE id = ?1", [id]).map_err(db_chyba)?;
        Ok(z.name)
    }

    pub fn vytvor_zaznam(&self, zone_id: i64, req: &CreateRecordRequest) -> Result<Record> {
        let z = self.zona(zone_id)?;
        let jmeno = dns::validuj_jmeno_zaznamu(&req.name)?;
        let ttl = req.ttl.unwrap_or(dns::VYCHOZI_TTL);
        dns::validuj_ttl(ttl)?;
        req.data.validuj()?;

        // CNAME nesmí být tam, kde je jiný záznam, a naopak.
        let existujici = self.zaznamy(zone_id)?;
        let je_cname = matches!(req.data, RecordData::Cname { .. });
        for e in &existujici {
            if e.name != jmeno {
                continue;
            }
            let e_cname = matches!(e.data, RecordData::Cname { .. });
            if je_cname || e_cname {
                return Err(AdError::new(
                    ErrorCode::RecordConflict,
                    format!("na jméně {jmeno} už je záznam, CNAME nemůže existovat vedle jiných"),
                ));
            }
        }

        let json = serde_json::to_string(&req.data)
            .map_err(|e| AdError::internal(format!("záznam: {e}")))?;
        let nyni = cas_do_db(ad_core::nyni());
        let c = self.lock();
        c.execute(
            "INSERT INTO dns_records(zone_id, name, rtype, ttl, rdata_json, managed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![zone_id, jmeno, req.data.typ().as_str(), ttl, json, nyni],
        )
        .map_err(db_chyba)?;
        let id = c.last_insert_rowid();
        c.execute("UPDATE dns_zones SET serial = serial + 1 WHERE id = ?1", [zone_id])
            .map_err(db_chyba)?;
        drop(c);
        let _ = z;
        self.zaznam(id)
    }

    pub fn zaznam(&self, id: i64) -> Result<Record> {
        let c = self.lock();
        c.query_row(
            "SELECT id, zone_id, name, ttl, rdata_json, managed FROM dns_records WHERE id = ?1",
            [id],
            zaznam_z_radku,
        )
        .optional()
        .map_err(db_chyba)?
        .ok_or_else(|| AdError::not_found(format!("záznam {id} neexistuje")))
    }

    pub fn smaz_zaznam(&self, id: i64) -> Result<()> {
        let z = self.zaznam(id)?;
        if z.managed {
            return Err(AdError::conflict(
                "tenhle záznam spravuje server sám (řadič nebo registrace klienta)",
            ));
        }
        let c = self.lock();
        c.execute("DELETE FROM dns_records WHERE id = ?1", [id]).map_err(db_chyba)?;
        c.execute("UPDATE dns_zones SET serial = serial + 1 WHERE id = ?1", [z.zone_id])
            .map_err(db_chyba)?;
        Ok(())
    }

    /// Forwardery — kam přeposílat dotazy, na které neumíme odpovědět.
    pub fn forwardery(&self) -> Result<Vec<String>> {
        let Some(json) = self.nastaveni(super::schema::nastaveni::DNS_FORWARDERS)? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&json).unwrap_or_default())
    }

    pub fn nastav_forwardery(&self, adresy: &[String]) -> Result<()> {
        for a in adresy {
            if a.parse::<IpAddr>().is_err() {
                return Err(AdError::bad_request(format!(
                    "{a} není IP adresa — forwarder musí být adresa, ne jméno"
                )));
            }
        }
        if adresy.len() > 4 {
            return Err(AdError::out_of_range("nejvýš čtyři forwardery"));
        }
        self.nastav(
            super::schema::nastaveni::DNS_FORWARDERS,
            &serde_json::to_string(adresy).unwrap_or_else(|_| "[]".into()),
        )
    }

    /// Zapíše A a PTR záznam počítače, který se právě připojil.
    ///
    /// Záznamy jsou `managed` — ručně se nemažou, zmizí při odpojení.
    pub fn zapis_dns_pocitace(&self, pocitac: &Computer, ip: IpAddr) -> Result<()> {
        let IpAddr::V4(v4) = ip else {
            return Ok(()); // IPv6 registraci zatím neděláme
        };
        let d = self.domena_nebo_chyba()?;
        let nyni = cas_do_db(ad_core::nyni());
        let kratke = pocitac.name.to_ascii_lowercase();

        // Dopředná zóna
        if let Some(z) = self.zona_podle_jmena(&d.dns_name)? {
            let data = RecordData::A { address: v4 };
            let json = serde_json::to_string(&data).unwrap_or_default();
            let c = self.lock();
            // Starý záznam stejného jména nahradíme — počítač mohl
            // dostat jinou adresu.
            c.execute(
                "DELETE FROM dns_records WHERE zone_id = ?1 AND name = ?2 AND rtype = 'A'
                 AND managed = 1",
                params![z.id, kratke],
            )
            .map_err(db_chyba)?;
            c.execute(
                "INSERT INTO dns_records(zone_id, name, rtype, ttl, rdata_json, managed, created_at)
                 VALUES (?1, ?2, 'A', ?3, ?4, 1, ?5)",
                params![z.id, kratke, dns::VYCHOZI_TTL, json, nyni],
            )
            .map_err(db_chyba)?;
            c.execute("UPDATE dns_zones SET serial = serial + 1 WHERE id = ?1", [z.id])
                .map_err(db_chyba)?;
        }

        // Reverzní zóna — najdeme tu, do které adresa patří.
        let ptr_jmeno = dns::ptr_jmeno(v4);
        if let Some(z) = self.zona_pro_jmeno(&ptr_jmeno)? {
            if z.kind == ZoneKind::Reverse {
                let relativni = dns::ptr_relativne(v4, &z.name)?;
                let data = RecordData::Ptr { target: pocitac.dns_name.clone() };
                let json = serde_json::to_string(&data).unwrap_or_default();
                let c = self.lock();
                c.execute(
                    "DELETE FROM dns_records WHERE zone_id = ?1 AND name = ?2 AND rtype = 'PTR'
                     AND managed = 1",
                    params![z.id, relativni],
                )
                .map_err(db_chyba)?;
                c.execute(
                    "INSERT INTO dns_records(zone_id, name, rtype, ttl, rdata_json, managed, created_at)
                     VALUES (?1, ?2, 'PTR', ?3, ?4, 1, ?5)",
                    params![z.id, relativni, dns::VYCHOZI_TTL, json, nyni],
                )
                .map_err(db_chyba)?;
                c.execute("UPDATE dns_zones SET serial = serial + 1 WHERE id = ?1", [z.id])
                    .map_err(db_chyba)?;
            }
        }
        Ok(())
    }

    /// Smaže DNS záznamy počítače při odpojení z domény.
    pub fn smaz_dns_pocitace(&self, jmeno_pocitace: &str) -> Result<()> {
        let d = self.domena_nebo_chyba()?;
        let kratke = jmeno_pocitace.to_ascii_lowercase();
        let fqdn = format!("{kratke}.{}", d.dns_name);

        let c = self.lock();
        // A záznam
        c.execute(
            "DELETE FROM dns_records WHERE name = ?1 AND rtype = 'A' AND managed = 1",
            params![kratke],
        )
        .map_err(db_chyba)?;
        // PTR záznamy, které na počítač ukazují
        let vzor = format!("%\"{fqdn}\"%");
        c.execute(
            "DELETE FROM dns_records WHERE rtype = 'PTR' AND managed = 1
             AND rdata_json LIKE ?1",
            params![vzor],
        )
        .map_err(db_chyba)?;
        Ok(())
    }
}

/// Rozdělí `192.168.56.0/24` na adresu a masku.
fn rozdel_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (adresa, prefix) =
        s.split_once('/').ok_or_else(|| AdError::bad_request("síť zadej jako 192.168.56.0/24"))?;
    let adresa: Ipv4Addr = adresa
        .trim()
        .parse()
        .map_err(|_| AdError::bad_request(format!("{adresa} není platná IPv4 adresa")))?;
    let prefix: u8 =
        prefix.trim().parse().map_err(|_| AdError::bad_request("maska musí být číslo"))?;
    Ok((adresa, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_se_rozdeli() {
        let (a, p) = rozdel_cidr("192.168.56.0/24").unwrap();
        assert_eq!(a, Ipv4Addr::new(192, 168, 56, 0));
        assert_eq!(p, 24);
        assert!(rozdel_cidr("192.168.56.0").is_err());
        assert!(rozdel_cidr("neco/24").is_err());
    }

    #[test]
    fn forwardery_musi_byt_ip() {
        let s = Store::v_pameti().unwrap();
        assert!(s.nastav_forwardery(&["1.1.1.1".into()]).is_ok());
        assert_eq!(s.forwardery().unwrap(), vec!["1.1.1.1".to_string()]);
        assert!(s.nastav_forwardery(&["dns.google".into()]).is_err());
        assert!(s
            .nastav_forwardery(&[
                "1.1.1.1".into(),
                "8.8.8.8".into(),
                "9.9.9.9".into(),
                "1.0.0.1".into(),
                "8.8.4.4".into()
            ])
            .is_err());
    }
}
