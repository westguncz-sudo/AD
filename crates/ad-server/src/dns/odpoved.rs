//! Sestavení odpovědi z našich zón.
//!
//! Tahle část se vůbec nedotýká sítě — bere dotaz a databázi a vrací
//! záznamy. Díky tomu se dá celá logika otestovat bez poslouchání na
//! portu 53.
//!
//! `hickory-proto` používáme jen na skládání a rozebírání paketů.
//! Rozhodování, co je v zóně a co ne, je náš kód.

use crate::store::Store;
use ad_core::dns as model;
use ad_core::Result;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Kolikrát nejvýš půjdeme po řetězu CNAME uvnitř zóny.
const MAX_CNAME: usize = 8;

/// Hotová autoritativní odpověď.
#[derive(Debug, Default)]
pub struct Odpoved {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub rcode: ResponseCode,
}

/// Odpoví na dotaz z našich zón.
///
/// Vrací `Ok(None)`, když jméno do žádné naší zóny nepatří — pak se
/// dotaz může přeposlat dál.
pub fn autoritativni(store: &Store, jmeno: &Name, typ: RecordType) -> Result<Option<Odpoved>> {
    let plne = normalizuj(jmeno);

    let Some(zona) = store.zona_pro_jmeno(&plne)? else {
        return Ok(None);
    };
    let zaznamy = store.zaznamy(zona.id)?;
    let soa = soa_zony(&zona)?;

    let mut odpoved = Odpoved::default();
    let mut hledane_plne = plne.clone();
    let mut hledany_typ = typ;
    let mut existuje_jmeno = false;

    for kolo in 0..=MAX_CNAME {
        let rel = relativni(&hledane_plne, &zona.name);
        let na_jmene: Vec<&model::Record> = zaznamy.iter().filter(|z| z.name == rel).collect();
        if !na_jmene.is_empty() {
            existuje_jmeno = true;
        }

        // Vrchol zóny má SOA a NS i bez uloženého záznamu.
        if rel == "@" && hledany_typ == RecordType::SOA {
            existuje_jmeno = true;
            odpoved.answers.push(Record::from_rdata(
                jmeno_dns(&zona.name)?,
                zona.minimum,
                RData::SOA(soa.clone()),
            ));
            break;
        }

        let shoda: Vec<&model::Record> =
            na_jmene.iter().copied().filter(|z| typ_zaznamu(&z.data) == hledany_typ).collect();

        if !shoda.is_empty() {
            for z in shoda {
                odpoved.answers.push(Record::from_rdata(
                    jmeno_dns(&hledane_plne)?,
                    z.ttl,
                    na_rdata(&z.data)?,
                ));
            }
            break;
        }

        // Není přímá shoda — zkusíme CNAME. To je jediný záznam, který
        // dotaz přesměruje na jiné jméno.
        let cname = na_jmene.iter().find_map(|z| match &z.data {
            model::RecordData::Cname { target } => Some((z.ttl, target.clone())),
            _ => None,
        });
        match cname {
            Some((ttl, cil)) if hledany_typ != RecordType::CNAME => {
                odpoved.answers.push(Record::from_rdata(
                    jmeno_dns(&hledane_plne)?,
                    ttl,
                    RData::CNAME(CNAME(jmeno_dns(&cil)?)),
                ));
                if kolo == MAX_CNAME {
                    // Řetěz CNAME je moc dlouhý — zacyklené odkazy
                    // nebudeme donekonečna následovat.
                    odpoved.rcode = ResponseCode::ServFail;
                    return Ok(Some(odpoved));
                }
                if !model::patri_do_zony(&cil, &zona.name) {
                    // Cíl je mimo naši zónu; víc poradit neumíme.
                    break;
                }
                hledane_plne = cil;
                hledany_typ = typ;
                continue;
            }
            _ => break,
        }
    }

    if odpoved.answers.is_empty() {
        // Jméno existuje, ale ne v tomhle typu (NODATA), nebo neexistuje
        // vůbec (NXDOMAIN). V obou případech přikládáme SOA, aby si
        // tazatel mohl zapamatovat, jak dlouho to platí.
        if !existuje_jmeno {
            odpoved.rcode = ResponseCode::NXDomain;
        }
        odpoved.authority.push(Record::from_rdata(
            jmeno_dns(&zona.name)?,
            zona.minimum,
            RData::SOA(soa),
        ));
        return Ok(Some(odpoved));
    }

    // Ke jménům v odpovědi přibalíme jejich adresy, ať se tazatel
    // nemusí ptát podruhé.
    let mut cile: Vec<String> = Vec::new();
    for a in &odpoved.answers {
        match a.data() {
            RData::SRV(srv) => cile.push(normalizuj(srv.target())),
            RData::MX(mx) => cile.push(normalizuj(mx.exchange())),
            RData::NS(ns) => cile.push(normalizuj(&ns.0)),
            _ => {}
        }
    }
    for cil in cile {
        if !model::patri_do_zony(&cil, &zona.name) {
            continue;
        }
        let rel = relativni(&cil, &zona.name);
        for z in zaznamy.iter().filter(|z| z.name == rel) {
            if matches!(z.data, model::RecordData::A { .. } | model::RecordData::Aaaa { .. }) {
                odpoved.additional.push(Record::from_rdata(
                    jmeno_dns(&cil)?,
                    z.ttl,
                    na_rdata(&z.data)?,
                ));
            }
        }
    }

    // NS zóny do sekce authority, jak se to dělá.
    if odpoved.rcode == ResponseCode::NoError {
        for z in zaznamy.iter().filter(|z| z.name == "@") {
            if let model::RecordData::Ns { .. } = z.data {
                odpoved.authority.push(Record::from_rdata(
                    jmeno_dns(&zona.name)?,
                    z.ttl,
                    na_rdata(&z.data)?,
                ));
            }
        }
    }

    Ok(Some(odpoved))
}

/// Jméno bez tečky na konci, malými písmeny.
pub fn normalizuj(jmeno: &Name) -> String {
    jmeno.to_lowercase().to_string().trim_end_matches('.').to_string()
}

/// Relativní jméno v zóně, `@` pro vrchol.
fn relativni(plne: &str, zona: &str) -> String {
    if plne == zona {
        "@".to_string()
    } else {
        plne.strip_suffix(&format!(".{zona}")).unwrap_or(plne).to_string()
    }
}

/// Text na absolutní DNS jméno.
fn jmeno_dns(s: &str) -> Result<Name> {
    Name::from_utf8(format!("{}.", s.trim_end_matches('.')))
        .map_err(|e| ad_core::AdError::internal(format!("neplatné DNS jméno {s}: {e}")))
}

fn soa_zony(z: &ad_core::dns::Zone) -> Result<SOA> {
    Ok(SOA::new(
        jmeno_dns(&z.primary_ns)?,
        jmeno_dns(&z.rname)?,
        z.serial,
        z.refresh as i32,
        z.retry as i32,
        z.expire as i32,
        z.minimum,
    ))
}

/// Náš typ záznamu na typ v protokolu.
pub fn typ_zaznamu(d: &model::RecordData) -> RecordType {
    match d {
        model::RecordData::A { .. } => RecordType::A,
        model::RecordData::Aaaa { .. } => RecordType::AAAA,
        model::RecordData::Cname { .. } => RecordType::CNAME,
        model::RecordData::Ptr { .. } => RecordType::PTR,
        model::RecordData::Srv { .. } => RecordType::SRV,
        model::RecordData::Txt { .. } => RecordType::TXT,
        model::RecordData::Ns { .. } => RecordType::NS,
        model::RecordData::Mx { .. } => RecordType::MX,
    }
}

/// Naše data záznamu na data v protokolu.
fn na_rdata(d: &model::RecordData) -> Result<RData> {
    Ok(match d {
        model::RecordData::A { address } => RData::A(A(*address)),
        model::RecordData::Aaaa { address } => RData::AAAA(AAAA(*address)),
        model::RecordData::Cname { target } => RData::CNAME(CNAME(jmeno_dns(target)?)),
        model::RecordData::Ptr { target } => RData::PTR(PTR(jmeno_dns(target)?)),
        model::RecordData::Ns { target } => RData::NS(NS(jmeno_dns(target)?)),
        model::RecordData::Mx { preference, target } => {
            RData::MX(MX::new(*preference, jmeno_dns(target)?))
        }
        model::RecordData::Srv { priority, weight, port, target } => {
            RData::SRV(SRV::new(*priority, *weight, *port, jmeno_dns(target)?))
        }
        model::RecordData::Txt { text } => RData::TXT(TXT::new(vec![text.clone()])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ad_core::proto::CreateRecordRequest;

    /// Databáze s doménou a pár záznamy.
    ///
    /// Řadič má adresu 127.0.0.1, aby prošla kontrola předpokladů
    /// i na stroji bez síťové karty v testovací síti. Reverzní zónu
    /// pro 192.168.56.0/24 si přidáme ručně, ať je co zkoušet.
    fn prostredi() -> Store {
        let store = Store::v_pameti().unwrap();
        store.nastav_bool(crate::store::schema::nastaveni::ROLE_DIRECTORY, true).unwrap();
        store.nastav_bool(crate::store::schema::nastaveni::ROLE_DNS, true).unwrap();

        // Každý test má vlastní adresář, protože běží souběžně.
        let dir = std::env::temp_dir().join(format!(
            "ad-dns-test-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..10]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cesty = crate::config::Cesty::nove(Some(dir.clone()), Some(dir.join("c.toml")));
        let req = ad_core::proto::PromoteRequest {
            domain_dns_name: "skola.internal".into(),
            short_name: None,
            dc_hostname: "DC01".into(),
            dc_ip: "127.0.0.1".into(),
            administrator_password: ad_core::secret::Tajne::new("Spravce-Heslo1"),
            dns: ad_core::proto::PromoteDnsOptions {
                create_reverse: false,
                reverse_prefix: 24,
                forwarders: vec![],
                enable_server: false,
            },
            confirm: true,
        };
        crate::domain::promote(
            &store,
            &cesty,
            &req,
            crate::domain::StavDns { bezi: false, port: 15353 },
            "test",
            "127.0.0.1",
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let zona = store.zona_podle_jmena("skola.internal").unwrap().unwrap();
        let zaznam = |jmeno: &str, data: model::RecordData| {
            store
                .vytvor_zaznam(
                    zona.id,
                    &CreateRecordRequest { name: jmeno.into(), ttl: Some(600), data },
                )
                .unwrap();
        };
        zaznam("tiskarna", model::RecordData::A { address: "192.168.56.50".parse().unwrap() });
        zaznam("web", model::RecordData::Cname { target: "dc01.skola.internal".into() });
        zaznam("@", model::RecordData::Txt { text: "skolni domena".into() });

        // Reverzní zóna pro školní síť.
        let rev = store
            .vytvor_zonu(&ad_core::proto::CreateZoneRequest {
                name: None,
                kind: model::ZoneKind::Reverse,
                network: Some("192.168.56.0/24".into()),
            })
            .unwrap();
        store
            .vytvor_zaznam(
                rev.id,
                &CreateRecordRequest {
                    name: "10".into(),
                    ttl: Some(600),
                    data: model::RecordData::Ptr { target: "dc01.skola.internal".into() },
                },
            )
            .unwrap();
        store
    }

    fn zeptej(store: &Store, jmeno: &str, typ: RecordType) -> Option<Odpoved> {
        let n = Name::from_utf8(jmeno).unwrap();
        autoritativni(store, &n, typ).unwrap()
    }

    #[test]
    fn zaznam_a_radice() {
        let s = prostredi();
        let o = zeptej(&s, "dc01.skola.internal.", RecordType::A).unwrap();
        assert_eq!(o.rcode, ResponseCode::NoError);
        assert_eq!(o.answers.len(), 1);
        match o.answers[0].data() {
            RData::A(a) => assert_eq!(a.0.to_string(), "127.0.0.1"),
            jine => panic!("čekal jsem A, dostal {jine:?}"),
        }
        assert!(!o.authority.is_empty(), "v authority má být NS zóny");
    }

    #[test]
    fn velikost_pismen_nerozhoduje() {
        let s = prostredi();
        let o = zeptej(&s, "DC01.Skola.Internal.", RecordType::A).unwrap();
        assert_eq!(o.answers.len(), 1);
    }

    #[test]
    fn srv_zaznam_s_adresou_v_additional() {
        let s = prostredi();
        let o = zeptej(&s, "_ad._tcp.skola.internal.", RecordType::SRV).unwrap();
        assert_eq!(o.answers.len(), 1);
        match o.answers[0].data() {
            RData::SRV(srv) => {
                assert_eq!(srv.port(), ad_core::proto::PORT_TLS);
                assert_eq!(srv.target().to_string(), "dc01.skola.internal.");
            }
            jine => panic!("čekal jsem SRV, dostal {jine:?}"),
        }
        // Adresa cíle musí přijít rovnou, ať se klient neptá dvakrát.
        assert_eq!(o.additional.len(), 1, "chybí adresa cíle v additional");
    }

    #[test]
    fn reverzni_zaznam() {
        let s = prostredi();
        let o = zeptej(&s, "10.56.168.192.in-addr.arpa.", RecordType::PTR).unwrap();
        assert_eq!(o.answers.len(), 1);
        match o.answers[0].data() {
            RData::PTR(p) => assert_eq!(p.0.to_string(), "dc01.skola.internal."),
            jine => panic!("čekal jsem PTR, dostal {jine:?}"),
        }
    }

    #[test]
    fn cname_se_nasleduje_uvnitr_zony() {
        let s = prostredi();
        let o = zeptej(&s, "web.skola.internal.", RecordType::A).unwrap();
        assert_eq!(o.answers.len(), 2, "CNAME i cílový A záznam");
        assert!(matches!(o.answers[0].data(), RData::CNAME(_)));
        assert!(matches!(o.answers[1].data(), RData::A(_)));
    }

    #[test]
    fn soa_na_vrcholu_zony() {
        let s = prostredi();
        let o = zeptej(&s, "skola.internal.", RecordType::SOA).unwrap();
        assert_eq!(o.answers.len(), 1);
        match o.answers[0].data() {
            RData::SOA(soa) => {
                assert_eq!(soa.mname().to_string(), "dc01.skola.internal.");
                assert!(soa.serial() >= 1);
            }
            jine => panic!("čekal jsem SOA, dostal {jine:?}"),
        }
    }

    #[test]
    fn txt_na_vrcholu() {
        let s = prostredi();
        let o = zeptej(&s, "skola.internal.", RecordType::TXT).unwrap();
        assert_eq!(o.answers.len(), 1);
    }

    #[test]
    fn neexistujici_jmeno_je_nxdomain() {
        let s = prostredi();
        let o = zeptej(&s, "neni.skola.internal.", RecordType::A).unwrap();
        assert_eq!(o.rcode, ResponseCode::NXDomain);
        assert!(o.answers.is_empty());
        assert_eq!(o.authority.len(), 1, "SOA v authority");
        assert!(matches!(o.authority[0].data(), RData::SOA(_)));
    }

    #[test]
    fn existujici_jmeno_bez_toho_typu_neni_nxdomain() {
        let s = prostredi();
        let o = zeptej(&s, "tiskarna.skola.internal.", RecordType::AAAA).unwrap();
        assert_eq!(o.rcode, ResponseCode::NoError, "NODATA, ne NXDOMAIN");
        assert!(o.answers.is_empty());
        assert_eq!(o.authority.len(), 1);
    }

    #[test]
    fn cizi_jmeno_neni_nase() {
        let s = prostredi();
        assert!(zeptej(&s, "seznam.cz.", RecordType::A).is_none());
        assert!(zeptej(&s, "jina.internal.", RecordType::A).is_none());
    }

    #[test]
    fn podobne_jmeno_zony_neoklame() {
        let s = prostredi();
        // „xskola.internal" nesmí spadnout do zóny „skola.internal".
        assert!(zeptej(&s, "neco.xskola.internal.", RecordType::A).is_none());
    }

    #[test]
    fn normalizace_jmena() {
        let n = Name::from_utf8("DC01.Skola.Internal.").unwrap();
        assert_eq!(normalizuj(&n), "dc01.skola.internal");
    }
}
