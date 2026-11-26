//! Vlastní DNS server.
//!
//! Poslouchá na UDP i TCP, odpovídá ze svých zón a na ostatní dotazy
//! se ptá nadřazeného serveru. Pakety skládá a rozebírá `hickory-proto`;
//! rozhodování, co odpovědět, je náš kód (`odpoved.rs`).
//!
//! # Co server **nedělá** a proč
//! * **Nepřenáší zóny** (AXFR/IXFR) — kdokoli by si jinak stáhl seznam
//!   všech počítačů v síti. Odpovídá `REFUSED`.
//! * **Neodpovídá na dotaz typu ANY** — jedna malá otázka by vyvolala
//!   velkou odpověď a dala se zneužít k zesílení útoku.
//! * **Nepřeposílá pro kohokoli.** Dotazy mimo naše zóny vyřizuje jen
//!   klientům z vnitřní sítě. Otevřený přeposílač na internetu je
//!   zbraň, ne služba.
//! * **Neumí rekurzi sám od sebe** — jen se zeptá nadřazeného serveru.
//!   Psát vlastní rekurzivní resolver by znamenalo řešit kořenové
//!   servery, DNSSEC a spoustu dalšího; to do školního projektu nepatří
//!   a nepředstíráme to.

pub mod forward;
pub mod odpoved;

use crate::store::Store;
use ad_core::{AdError, Result};
use forward::Preposilac;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

/// Největší odpověď přes UDP bez EDNS (podle RFC 1035).
const UDP_BEZ_EDNS: usize = 512;
/// Strop pro EDNS. Větší pakety se v sítích často fragmentují a ztrácejí.
const UDP_MAX_EDNS: u16 = 1232;
/// Kolik dotazů vyřídíme v jednom TCP spojení, než ho zavřeme.
const TCP_MAX_DOTAZU: usize = 16;
/// Jak dlouho čekáme na další dotaz v TCP spojení.
const TCP_CEKANI: Duration = Duration::from_secs(10);

/// Počitadla pro přehled ve správě.
#[derive(Default)]
pub struct DnsStav {
    pub bezi: AtomicBool,
    pub dotazy: AtomicU64,
    pub autoritativni: AtomicU64,
    pub preposlane: AtomicU64,
    pub z_cache: AtomicU64,
    pub odmitnute: AtomicU64,
    pub nxdomain: AtomicU64,
    pub chyby: AtomicU64,
    naslouchani: std::sync::Mutex<Vec<String>>,
    pub preposilac: Preposilac,
}

impl DnsStav {
    pub fn naslouchani(&self) -> Vec<String> {
        self.naslouchani.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn nastav_naslouchani(&self, hodnoty: Vec<String>) {
        if let Ok(mut v) = self.naslouchani.lock() {
            *v = hodnoty;
        }
    }
}

/// Spustí DNS server a běží, dokud nepřijde pokyn k vypnutí.
pub async fn spust(
    store: Store,
    stav: Arc<DnsStav>,
    adresa: SocketAddr,
    jen_vnitrni_preposilani: bool,
    mut vypni: watch::Receiver<bool>,
) -> Result<()> {
    let udp = UdpSocket::bind(adresa).await.map_err(|e| chyba_portu(adresa, e))?;
    let tcp = TcpListener::bind(adresa).await.map_err(|e| chyba_portu(adresa, e))?;

    stav.bezi.store(true, Ordering::Relaxed);
    stav.nastav_naslouchani(vec![format!("{adresa} (UDP)"), format!("{adresa} (TCP)")]);
    tracing::info!(adresa = %adresa, "DNS server poslouchá");

    let udp = Arc::new(udp);
    let mut buf = vec![0u8; 4096];

    let vysledek = loop {
        tokio::select! {
            _ = vypni.changed() => {
                if *vypni.borrow() { break Ok(()); }
            }
            prijato = udp.recv_from(&mut buf) => {
                let (delka, odkud) = match prijato {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(chyba = %e, "chyba při čtení z UDP");
                        continue;
                    }
                };
                let data = buf[..delka].to_vec();
                let (store, stav, udp) = (store.clone(), stav.clone(), udp.clone());
                tokio::spawn(async move {
                    if let Some(odpoved) =
                        obsluz(&store, &stav, &data, odkud.ip(), false, jen_vnitrni_preposilani).await
                    {
                        let _ = udp.send_to(&odpoved, odkud).await;
                    }
                });
            }
            prijato = tcp.accept() => {
                let (proud, odkud) = match prijato {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(chyba = %e, "chyba při přijímání TCP spojení");
                        continue;
                    }
                };
                let (store, stav) = (store.clone(), stav.clone());
                tokio::spawn(async move {
                    if let Err(e) =
                        obsluz_tcp(store, stav, proud, odkud.ip(), jen_vnitrni_preposilani).await
                    {
                        tracing::debug!(klient = %odkud, chyba = %e, "TCP spojení skončilo");
                    }
                });
            }
        }
    };

    stav.bezi.store(false, Ordering::Relaxed);
    stav.nastav_naslouchani(Vec::new());
    tracing::info!("DNS server končí");
    vysledek
}

fn chyba_portu(adresa: SocketAddr, e: std::io::Error) -> AdError {
    if e.kind() == std::io::ErrorKind::PermissionDenied && adresa.port() < 1024 {
        AdError::internal(format!(
            "na {adresa} nelze poslouchat: port pod 1024 potřebuje oprávnění. \
             Na Linuxu buď spusť server jako služba, nebo přidej binárce právo: \
             sudo setcap 'cap_net_bind_service=+ep' /cesta/k/ad-server"
        ))
    } else {
        AdError::internal(format!("na {adresa} nelze poslouchat: {e}"))
    }
}

/// Jedno TCP spojení. Zprávy mají před sebou dvoubajtovou délku.
async fn obsluz_tcp(
    store: Store,
    stav: Arc<DnsStav>,
    mut proud: tokio::net::TcpStream,
    klient: IpAddr,
    jen_vnitrni: bool,
) -> std::io::Result<()> {
    for _ in 0..TCP_MAX_DOTAZU {
        let mut delka = [0u8; 2];
        match tokio::time::timeout(TCP_CEKANI, proud.read_exact(&mut delka)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // konec spojení nebo čekání
        }
        let delka = u16::from_be_bytes(delka) as usize;
        if delka == 0 || delka > 8192 {
            return Ok(());
        }
        let mut data = vec![0u8; delka];
        if tokio::time::timeout(TCP_CEKANI, proud.read_exact(&mut data)).await.is_err() {
            return Ok(());
        }

        let Some(odpoved) = obsluz(&store, &stav, &data, klient, true, jen_vnitrni).await else {
            return Ok(());
        };
        proud.write_all(&(odpoved.len() as u16).to_be_bytes()).await?;
        proud.write_all(&odpoved).await?;
        proud.flush().await?;
    }
    Ok(())
}

/// Vyřídí jeden dotaz. Vrací hotové bajty odpovědi, nebo `None`,
/// když se odpovídat nemá.
async fn obsluz(
    store: &Store,
    stav: &DnsStav,
    data: &[u8],
    klient: IpAddr,
    pres_tcp: bool,
    jen_vnitrni: bool,
) -> Option<Vec<u8>> {
    let dotaz = match Message::from_vec(data) {
        Ok(m) => m,
        Err(_) => {
            // Na nerozluštitelný paket se nedá odpovědět ani chybou —
            // neznáme ani číslo dotazu.
            stav.chyby.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };

    // Na odpovědi se neodpovídá. Jinak by si dva servery mohly posílat
    // zprávy donekonečna.
    if dotaz.message_type() != MessageType::Query {
        return None;
    }
    stav.dotazy.fetch_add(1, Ordering::Relaxed);

    let max_odpoved = if pres_tcp {
        u16::MAX as usize
    } else {
        match dotaz.extensions() {
            Some(e) => (e.max_payload().clamp(UDP_BEZ_EDNS as u16, UDP_MAX_EDNS)) as usize,
            None => UDP_BEZ_EDNS,
        }
    };

    if dotaz.op_code() != OpCode::Query {
        return zabal(odmitni(&dotaz, ResponseCode::NotImp, stav), max_odpoved);
    }
    let otazky = dotaz.queries();
    if otazky.len() != 1 {
        return zabal(odmitni(&dotaz, ResponseCode::FormErr, stav), max_odpoved);
    }
    let otazka = otazky[0].clone();

    if otazka.query_class() != DNSClass::IN {
        return zabal(odmitni(&dotaz, ResponseCode::NotImp, stav), max_odpoved);
    }
    // Přenos zóny a dotaz ANY odmítáme — viz poznámka v hlavičce modulu.
    if matches!(otazka.query_type(), RecordType::AXFR | RecordType::IXFR | RecordType::ANY) {
        tracing::debug!(klient = %klient, typ = ?otazka.query_type(), "odmítnutý typ dotazu");
        return zabal(odmitni(&dotaz, ResponseCode::Refused, stav), max_odpoved);
    }

    // --- naše zóny ---
    let (s, jmeno, typ) = (store.clone(), otazka.name().clone(), otazka.query_type());
    let nase = tokio::task::spawn_blocking(move || odpoved::autoritativni(&s, &jmeno, typ))
        .await
        .ok()
        .and_then(|v| match v {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(chyba = %e.message, "chyba při hledání v zóně");
                None
            }
        });

    let mut odp = zaklad_odpovedi(&dotaz);

    if let Some(o) = nase {
        stav.autoritativni.fetch_add(1, Ordering::Relaxed);
        if o.rcode == ResponseCode::NXDomain {
            stav.nxdomain.fetch_add(1, Ordering::Relaxed);
        }
        odp.set_authoritative(true);
        odp.set_response_code(o.rcode);
        odp.add_answers(o.answers);
        odp.add_name_servers(o.authority);
        odp.add_additionals(o.additional);
        dopln_edns(&mut odp, &dotaz, max_odpoved);
        return zabal(odp, max_odpoved);
    }

    // --- mimo naše zóny: přeposlat ---
    let forwardery = nacti_forwardery(store).await;

    if !dotaz.recursion_desired() || forwardery.is_empty() {
        return zabal(odmitni(&dotaz, ResponseCode::Refused, stav), max_odpoved);
    }
    if jen_vnitrni && !forward::je_vnitrni(klient) {
        tracing::debug!(klient = %klient, "přeposílání odmítnuto, adresa není z vnitřní sítě");
        return zabal(odmitni(&dotaz, ResponseCode::Refused, stav), max_odpoved);
    }

    match stav.preposilac.preposli(&forwardery, &otazka).await {
        Some(v) => {
            if v.z_cache {
                stav.z_cache.fetch_add(1, Ordering::Relaxed);
            } else {
                stav.preposlane.fetch_add(1, Ordering::Relaxed);
            }
            odp.set_recursion_available(true);
            odp.set_response_code(v.rcode);
            odp.add_answers(v.answers);
            odp.add_name_servers(v.authority);
            odp.add_additionals(v.additional);
            dopln_edns(&mut odp, &dotaz, max_odpoved);
            zabal(odp, max_odpoved)
        }
        None => {
            stav.chyby.fetch_add(1, Ordering::Relaxed);
            zabal(odmitni(&dotaz, ResponseCode::ServFail, stav), max_odpoved)
        }
    }
}

async fn nacti_forwardery(store: &Store) -> Vec<IpAddr> {
    let s = store.clone();
    tokio::task::spawn_blocking(move || s.forwardery())
        .await
        .ok()
        .and_then(|v| v.ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .collect()
}

fn zaklad_odpovedi(dotaz: &Message) -> Message {
    let mut odp = Message::new();
    odp.set_id(dotaz.id())
        .set_message_type(MessageType::Response)
        .set_op_code(dotaz.op_code())
        .set_recursion_desired(dotaz.recursion_desired())
        .set_checking_disabled(dotaz.checking_disabled());
    for q in dotaz.queries() {
        odp.add_query(q.clone());
    }
    odp
}

fn odmitni(dotaz: &Message, kod: ResponseCode, stav: &DnsStav) -> Message {
    if kod == ResponseCode::Refused {
        stav.odmitnute.fetch_add(1, Ordering::Relaxed);
    }
    let mut odp = zaklad_odpovedi(dotaz);
    odp.set_response_code(kod);
    odp
}

/// Když se tazatel ozval s EDNS, odpovíme taky s EDNS.
fn dopln_edns(odpoved: &mut Message, dotaz: &Message, max: usize) {
    if dotaz.extensions().is_none() {
        return;
    }
    let mut edns = Edns::new();
    edns.set_max_payload(max.min(UDP_MAX_EDNS as usize) as u16);
    edns.set_version(0);
    odpoved.set_edns(edns);
}

/// Zakóduje odpověď. Když se nevejde, ořízne ji a nastaví příznak
/// „zkráceno" — tazatel se pak zeptá znovu přes TCP.
fn zabal(odpoved: Message, max: usize) -> Option<Vec<u8>> {
    let data = odpoved.to_vec().ok()?;
    if data.len() <= max {
        return Some(data);
    }
    let mut zkracena = Message::new();
    zkracena
        .set_id(odpoved.id())
        .set_message_type(MessageType::Response)
        .set_op_code(odpoved.op_code())
        .set_recursion_desired(odpoved.recursion_desired())
        .set_recursion_available(odpoved.recursion_available())
        .set_authoritative(odpoved.authoritative())
        .set_response_code(odpoved.response_code())
        .set_truncated(true);
    for q in odpoved.queries() {
        zkracena.add_query(q.clone());
    }
    zkracena.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, Record};

    fn dotaz_na(jmeno: &str, typ: RecordType) -> Message {
        let mut m = Message::new();
        m.set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(hickory_proto::op::Query::query(Name::from_utf8(jmeno).unwrap(), typ));
        m
    }

    #[test]
    fn zaklad_odpovedi_zachova_otazku_i_cislo() {
        let d = dotaz_na("pokus.example.", RecordType::A);
        let o = zaklad_odpovedi(&d);
        assert_eq!(o.id(), 0x1234);
        assert_eq!(o.message_type(), MessageType::Response);
        assert_eq!(o.queries().len(), 1);
        assert_eq!(o.queries()[0].name().to_string(), "pokus.example.");
    }

    #[test]
    fn velka_odpoved_se_zkrati() {
        let d = dotaz_na("pokus.example.", RecordType::TXT);
        let mut o = zaklad_odpovedi(&d);
        for i in 0..100 {
            o.add_answer(Record::from_rdata(
                Name::from_utf8("pokus.example.").unwrap(),
                60,
                hickory_proto::rr::RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![format!(
                    "vypln-{i}-{}",
                    "x".repeat(200)
                )])),
            ));
        }
        let data = zabal(o, UDP_BEZ_EDNS).unwrap();
        assert!(data.len() <= UDP_BEZ_EDNS, "odpověď se musí vejít do 512 bajtů");
        let zpet = Message::from_vec(&data).unwrap();
        assert!(zpet.truncated(), "musí být nastavený příznak zkrácení");
        assert_eq!(zpet.id(), 0x1234);
    }

    #[test]
    fn mala_odpoved_se_nezkracuje() {
        let d = dotaz_na("pokus.example.", RecordType::A);
        let o = zaklad_odpovedi(&d);
        let data = zabal(o, UDP_BEZ_EDNS).unwrap();
        let zpet = Message::from_vec(&data).unwrap();
        assert!(!zpet.truncated());
    }

    #[test]
    fn odmitnuti_se_pocita() {
        let stav = DnsStav::default();
        let d = dotaz_na("pokus.example.", RecordType::A);
        let o = odmitni(&d, ResponseCode::Refused, &stav);
        assert_eq!(o.response_code(), ResponseCode::Refused);
        assert_eq!(stav.odmitnute.load(Ordering::Relaxed), 1);
        // NotImp se mezi odmítnutí nepočítá.
        odmitni(&d, ResponseCode::NotImp, &stav);
        assert_eq!(stav.odmitnute.load(Ordering::Relaxed), 1);
    }
}
