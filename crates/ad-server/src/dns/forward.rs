//! Přeposílání dotazů dál a krátká paměť na odpovědi.
//!
//! Na co neumíme odpovědět ze svých zón, se zeptáme nadřazeného DNS
//! (typicky toho, co měl systém nastavený před námi). Odpověď si na
//! chvíli zapamatujeme, aby se tentýž dotaz neposílal pořád dokola.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::Record;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Jak dlouho čekáme na odpověď od jednoho nadřazeného serveru.
const CEKANI: Duration = Duration::from_millis(2500);
/// Nejkratší doba, po kterou si odpověď necháme.
const MIN_TTL: u32 = 10;
/// Nejdelší doba, po kterou si odpověď necháme (hodina).
const MAX_TTL: u32 = 3600;
/// Kolik odpovědí si nejvýš pamatujeme.
const MAX_POLOZEK: usize = 2000;

#[derive(PartialEq, Eq, Hash, Clone)]
struct Klic {
    jmeno: String,
    typ: u16,
}

struct Polozka {
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    rcode: ResponseCode,
    ulozeno: Instant,
    plati_do: Instant,
}

/// Přeposílač s vlastní pamětí.
pub struct Preposilac {
    cache: Mutex<HashMap<Klic, Polozka>>,
}

/// Co se z přeposílání vrátilo.
pub struct Vysledek {
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
    pub rcode: ResponseCode,
    /// Odpověď jsme měli zapamatovanou, nikam jsme se neptali.
    pub z_cache: bool,
}

impl Default for Preposilac {
    fn default() -> Self {
        Self::new()
    }
}

impl Preposilac {
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }

    pub fn pocet_v_cache(&self) -> u64 {
        self.cache.lock().map(|c| c.len() as u64).unwrap_or(0)
    }

    /// Vyprázdní paměť — třeba když se změní forwardery.
    pub fn vycisti(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// Zeptá se nadřazených serverů. Zkouší je po řadě, první odpověď
    /// vyhrává.
    pub async fn preposli(&self, servery: &[IpAddr], dotaz: &Query) -> Option<Vysledek> {
        let klic = Klic {
            jmeno: dotaz.name().to_lowercase().to_string(),
            typ: u16::from(dotaz.query_type()),
        };

        if let Some(v) = self.z_pameti(&klic) {
            return Some(v);
        }

        for server in servery {
            match self.zeptej_se(*server, dotaz).await {
                Some(odpoved) => {
                    let v = Vysledek {
                        answers: odpoved.answers().to_vec(),
                        authority: odpoved.name_servers().to_vec(),
                        additional: odpoved
                            .additionals()
                            .iter()
                            .filter(|r| r.record_type() != hickory_proto::rr::RecordType::OPT)
                            .cloned()
                            .collect(),
                        rcode: odpoved.response_code(),
                        z_cache: false,
                    };
                    // Zapamatujeme si jen odpovědi, které dávají smysl.
                    if matches!(v.rcode, ResponseCode::NoError | ResponseCode::NXDomain) {
                        self.zapamatuj(klic, &v);
                    }
                    return Some(v);
                }
                None => continue,
            }
        }
        None
    }

    fn z_pameti(&self, klic: &Klic) -> Option<Vysledek> {
        let mut cache = self.cache.lock().ok()?;
        let polozka = cache.get(klic)?;
        let nyni = Instant::now();
        if polozka.plati_do <= nyni {
            cache.remove(klic);
            return None;
        }
        // Odpočítáme, jak dlouho už odpověď ležíme — jinak bychom
        // tazatelům tvrdili, že platí déle, než doopravdy platí.
        let ubehlo = nyni.duration_since(polozka.ulozeno).as_secs() as u32;
        let uprav = |zaznamy: &[Record]| -> Vec<Record> {
            zaznamy
                .iter()
                .map(|r| {
                    let mut kopie = r.clone();
                    kopie.set_ttl(r.ttl().saturating_sub(ubehlo).max(1));
                    kopie
                })
                .collect()
        };
        Some(Vysledek {
            answers: uprav(&polozka.answers),
            authority: uprav(&polozka.authority),
            additional: uprav(&polozka.additional),
            rcode: polozka.rcode,
            z_cache: true,
        })
    }

    fn zapamatuj(&self, klic: Klic, v: &Vysledek) {
        let nejkratsi = v
            .answers
            .iter()
            .chain(v.authority.iter())
            .map(|r| r.ttl())
            .min()
            .unwrap_or(MIN_TTL)
            .clamp(MIN_TTL, MAX_TTL);

        let Ok(mut cache) = self.cache.lock() else { return };
        if cache.len() >= MAX_POLOZEK {
            // Nejdřív zahodíme, co už stejně neplatí.
            let nyni = Instant::now();
            cache.retain(|_, p| p.plati_do > nyni);
            // Když to nestačilo, uvolníme místo hrubou silou. Paměť
            // nesmí růst donekonečna.
            if cache.len() >= MAX_POLOZEK {
                let kolik = cache.len() / 4;
                let k_zahozeni: Vec<Klic> = cache.keys().take(kolik).cloned().collect();
                for k in k_zahozeni {
                    cache.remove(&k);
                }
            }
        }
        let nyni = Instant::now();
        cache.insert(
            klic,
            Polozka {
                answers: v.answers.clone(),
                authority: v.authority.clone(),
                additional: v.additional.clone(),
                rcode: v.rcode,
                ulozeno: nyni,
                plati_do: nyni + Duration::from_secs(nejkratsi as u64),
            },
        );
    }

    async fn zeptej_se(&self, server: IpAddr, dotaz: &Query) -> Option<Message> {
        let mut zprava = Message::new();
        let id = nahodne_id();
        zprava
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(dotaz.clone());

        let data = zprava.to_vec().ok()?;
        let cil = SocketAddr::new(server, 53);
        let mistni: SocketAddr =
            if server.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };

        let socket = UdpSocket::bind(mistni).await.ok()?;
        socket.send_to(&data, cil).await.ok()?;

        let mut buf = vec![0u8; 4096];
        loop {
            let (delka, odkud) =
                match tokio::time::timeout(CEKANI, socket.recv_from(&mut buf)).await {
                    Ok(Ok(v)) => v,
                    _ => return None,
                };
            // Odpověď musí přijít od toho, koho jsme se ptali, mít naše
            // číslo dotazu a tutéž otázku. Jinak je to pokus o podvržení.
            if odkud.ip() != server {
                continue;
            }
            let Ok(odpoved) = Message::from_vec(&buf[..delka]) else { continue };
            if odpoved.id() != id {
                continue;
            }
            if odpoved.queries().first() != Some(dotaz) {
                continue;
            }
            return Some(odpoved);
        }
    }
}

fn nahodne_id() -> u16 {
    let mut b = [0u8; 2];
    ad_core::rand_bytes(&mut b);
    u16::from_le_bytes(b)
}

/// Je adresa z vnitřní sítě?
///
/// Přeposíláme jen pro klienty z vnitřních sítí. Otevřený přeposílač
/// dostupný z internetu se dá zneužít k zesílení útoku: útočník pošle
/// malý dotaz s podvrženou adresou oběti a velká odpověď letí na ni.
pub fn je_vnitrni(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let s = v6.segments()[0];
            // fc00::/7 (unikátní místní) a fe80::/10 (link-local)
            (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{rdata::A, Name, RData, RecordType};

    fn dotaz(jmeno: &str) -> Query {
        Query::query(Name::from_utf8(jmeno).unwrap(), RecordType::A)
    }

    fn vysledek(ttl: u32) -> Vysledek {
        Vysledek {
            answers: vec![Record::from_rdata(
                Name::from_utf8("pokus.example.").unwrap(),
                ttl,
                RData::A(A("203.0.113.5".parse().unwrap())),
            )],
            authority: vec![],
            additional: vec![],
            rcode: ResponseCode::NoError,
            z_cache: false,
        }
    }

    #[test]
    fn vnitrni_adresy() {
        assert!(je_vnitrni("127.0.0.1".parse().unwrap()));
        assert!(je_vnitrni("192.168.56.20".parse().unwrap()));
        assert!(je_vnitrni("10.1.2.3".parse().unwrap()));
        assert!(je_vnitrni("172.16.0.1".parse().unwrap()));
        assert!(je_vnitrni("169.254.1.1".parse().unwrap()));
        assert!(je_vnitrni("::1".parse().unwrap()));
        assert!(je_vnitrni("fd00::1".parse().unwrap()));
        assert!(je_vnitrni("fe80::1".parse().unwrap()));

        assert!(!je_vnitrni("8.8.8.8".parse().unwrap()));
        assert!(!je_vnitrni("203.0.113.5".parse().unwrap()));
        assert!(!je_vnitrni("2001:db8::1".parse().unwrap()));
        // 172.32 už je veřejná — hranice privátního rozsahu je /12.
        assert!(!je_vnitrni("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn cache_vrati_ulozenou_odpoved() {
        let p = Preposilac::new();
        let q = dotaz("pokus.example.");
        let klic =
            Klic { jmeno: q.name().to_lowercase().to_string(), typ: u16::from(q.query_type()) };
        p.zapamatuj(klic.clone(), &vysledek(300));
        assert_eq!(p.pocet_v_cache(), 1);

        let z = p.z_pameti(&klic).unwrap();
        assert!(z.z_cache);
        assert_eq!(z.answers.len(), 1);
        assert!(z.answers[0].ttl() <= 300);
    }

    #[test]
    fn cache_se_da_vycistit() {
        let p = Preposilac::new();
        let q = dotaz("pokus.example.");
        let klic = Klic { jmeno: q.name().to_string(), typ: u16::from(q.query_type()) };
        p.zapamatuj(klic, &vysledek(300));
        p.vycisti();
        assert_eq!(p.pocet_v_cache(), 0);
    }

    #[test]
    fn kratke_ttl_se_zvedne_na_minimum() {
        let p = Preposilac::new();
        let q = dotaz("pokus.example.");
        let klic = Klic { jmeno: q.name().to_string(), typ: u16::from(q.query_type()) };
        // TTL 1 s by znamenalo, že cache je k ničemu.
        p.zapamatuj(klic.clone(), &vysledek(1));
        let cache = p.cache.lock().unwrap();
        let polozka = cache.get(&klic).unwrap();
        let platnost = polozka.plati_do.duration_since(polozka.ulozeno).as_secs();
        assert_eq!(platnost, MIN_TTL as u64);
    }

    #[test]
    fn dlouhe_ttl_se_zkrati_na_maximum() {
        let p = Preposilac::new();
        let q = dotaz("pokus.example.");
        let klic = Klic { jmeno: q.name().to_string(), typ: u16::from(q.query_type()) };
        p.zapamatuj(klic.clone(), &vysledek(86400));
        let cache = p.cache.lock().unwrap();
        let polozka = cache.get(&klic).unwrap();
        let platnost = polozka.plati_do.duration_since(polozka.ulozeno).as_secs();
        assert_eq!(platnost, MAX_TTL as u64);
    }

    #[test]
    fn nahodna_id_se_lisi() {
        let mut videna = std::collections::HashSet::new();
        for _ in 0..50 {
            videna.insert(nahodne_id());
        }
        assert!(videna.len() > 40, "čísla dotazů musí být náhodná");
    }
}
