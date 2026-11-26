//! Logika domény: kontrola předpokladů, povýšení serveru na řadič
//! domény a jeho zrušení.
//!
//! Tohle je obdoba `dcpromo` — jediné místo, kde doména vzniká.

use crate::config::Cesty;
use crate::pki;
use crate::store::{schema::nastaveni, Store};
use ad_core::dns;
use ad_core::ids::{rid, DomainSid};
use ad_core::model::Domain;
use ad_core::names;
use ad_core::proto::{CheckItem, CheckStatus, PrecheckResponse, PromoteRequest, PromoteResponse};
use ad_core::{password, secret, AdError, ErrorCode, Result};
use rusqlite::params;
use std::net::{IpAddr, SocketAddr};

fn ok(code: &str, title: &str, detail: impl Into<String>) -> CheckItem {
    CheckItem {
        code: code.into(),
        title: title.into(),
        status: CheckStatus::Pass,
        detail: detail.into(),
        remedy: None,
    }
}

fn varovani(code: &str, title: &str, detail: impl Into<String>, rada: &str) -> CheckItem {
    CheckItem {
        code: code.into(),
        title: title.into(),
        status: CheckStatus::Warn,
        detail: detail.into(),
        remedy: Some(rada.into()),
    }
}

fn chyba(code: &str, title: &str, detail: impl Into<String>, rada: &str) -> CheckItem {
    CheckItem {
        code: code.into(),
        title: title.into(),
        status: CheckStatus::Fail,
        detail: detail.into(),
        remedy: Some(rada.into()),
    }
}

/// Co víme o vlastním DNS serveru, když kontrolujeme předpoklady.
#[derive(Debug, Clone, Copy)]
pub struct StavDns {
    /// Náš DNS server už poslouchá. Bez toho by kontrola portu hlásila
    /// konflikt sama se sebou: role DNS se instaluje dřív než se vytvoří
    /// doména, takže v době kontroly už náš server na portu je.
    pub bezi: bool,
    /// Port z konfigurace (`[dns] bind`). Obvykle 53, v testech vyšší —
    /// na porty pod 1024 potřebuje proces zvláštní oprávnění.
    pub port: u16,
}

/// Zkontroluje předpoklady povýšení. Nic nemění.
pub fn precheck(
    store: &Store,
    cesty: &Cesty,
    req: &PromoteRequest,
    dns: StavDns,
) -> Result<PrecheckResponse> {
    let mut items = Vec::new();

    // --- doména ještě neexistuje ---
    if store.domena()?.is_some() {
        items.push(chyba(
            "no_domain",
            "Doména ještě neexistuje",
            "Na tomto serveru už doména je. Druhá nejde vytvořit.",
            "Nejdřív doménu zruš (Zrušit řadič domény).",
        ));
    } else {
        items.push(ok("no_domain", "Doména ještě neexistuje", "Server zatím není řadičem."));
    }

    // --- role ---
    let role = store.role()?;
    if role.directory {
        items.push(ok("role_directory", "Role doménových služeb", "Nainstalovaná."));
    } else {
        items.push(chyba(
            "role_directory",
            "Role doménových služeb",
            "Role doménových služeb není nainstalovaná.",
            "Spusť průvodce Přidat role a funkce a zapni Doménové služby.",
        ));
    }
    if role.dns {
        items.push(ok("role_dns", "Role DNS", "Nainstalovaná."));
    } else {
        items.push(varovani(
            "role_dns",
            "Role DNS",
            "Role DNS není nainstalovaná — zóny se nevytvoří.",
            "Zapni roli DNS, jinak si klienti doménu nenajdou podle jména.",
        ));
    }

    // --- jméno domény ---
    match names::validuj_jmeno_domeny(&req.domain_dns_name) {
        Ok(k) => {
            if k.varovani.is_empty() {
                items.push(ok(
                    "domain_name",
                    "Jméno domény",
                    format!("{} (krátce {})", k.fqdn, k.kratke),
                ));
            } else {
                items.push(varovani(
                    "domain_name",
                    "Jméno domény",
                    k.varovani.join(" "),
                    "Pro vnitřní doménu je nejbezpečnější koncovka .internal",
                ));
            }
        }
        Err(e) => items.push(chyba(
            "domain_name",
            "Jméno domény",
            e.message.clone(),
            "Použij něco jako skola.internal",
        )),
    }

    // --- jméno řadiče ---
    match names::validuj_jmeno_pocitace(&req.dc_hostname) {
        Ok(h) => items.push(ok("dc_hostname", "Jméno řadiče domény", h)),
        Err(e) => items.push(chyba(
            "dc_hostname",
            "Jméno řadiče domény",
            e.message.clone(),
            "Například DC01.",
        )),
    }

    // --- heslo správce ---
    let zasada = ad_core::policy::PasswordPolicy::default();
    match password::zkontroluj(
        req.administrator_password.odhal(),
        &zasada,
        Some("administrator"),
        &[],
    ) {
        Ok(()) => {
            items.push(ok("admin_password", "Heslo správce", "Splňuje výchozí zásadu hesel."))
        }
        Err(e) => items.push(chyba(
            "admin_password",
            "Heslo správce",
            e.message.clone(),
            "Minimálně 8 znaků, velké i malé písmeno a číslice.",
        )),
    }

    // --- IP adresa ---
    match req.dc_ip.parse::<IpAddr>() {
        Err(_) => items.push(chyba(
            "static_ip",
            "IP adresa řadiče",
            format!("{} není platná IP adresa.", req.dc_ip),
            "Zadej adresu tohoto stroje, např. 192.168.56.10.",
        )),
        Ok(ip) => {
            if ip.is_loopback() {
                items.push(varovani(
                    "static_ip",
                    "IP adresa řadiče",
                    "Zadaná adresa je loopback — klienti z jiných strojů se nepřipojí.",
                    "Pro test ve virtuálkách použij adresu síťové karty.",
                ));
            } else if patri_stroji(ip) {
                items.push(ok(
                    "static_ip",
                    "IP adresa řadiče",
                    format!("{ip} patří tomuto stroji."),
                ));
            } else {
                items.push(chyba(
                    "static_ip",
                    "IP adresa řadiče",
                    format!("{ip} na tomto stroji není."),
                    "Zkontroluj síťové nastavení (ip a / ipconfig).",
                ));
            }
        }
    }

    // --- porty ---
    if role.dns && req.dns.enable_server {
        let titul = format!("Port {} pro DNS", dns.port);
        if dns.bezi {
            items.push(ok("dns_port_free", &titul, "Náš DNS server už na něm poslouchá."));
        } else if port_volny(dns.port) {
            items.push(ok("dns_port_free", &titul, "Je volný."));
        } else if dns.port < 1024 {
            // Dvě různé příčiny splývají do jedné: buď port drží cizí
            // služba, nebo na privilegovaný port nemáme právo. Poradíme
            // obojí, ať se to nehádá.
            items.push(chyba(
                "dns_port_free",
                &titul,
                format!(
                    "Na port {} se nedá navázat — buď ho drží jiná služba, \
                     nebo na porty pod 1024 nemá tento proces právo.",
                    dns.port
                ),
                "Vypni cizí DNS (sudo systemctl disable --now systemd-resolved). \
                 Pokud server neběží jako služba ani jako root, přidej mu \
                 oprávnění: sudo setcap cap_net_bind_service=+ep ./ad-server",
            ));
        } else {
            items.push(chyba(
                "dns_port_free",
                &titul,
                format!("Na portu {} už něco poslouchá a není to náš server.", dns.port),
                "Zastav službu, která port drží, nebo si v konfiguraci zvol jiný port.",
            ));
        }
    }
    if port_volny(ad_core::proto::PORT_TLS) {
        items.push(ok(
            "api_port_free",
            "Port doménového API",
            format!("Port {} je volný.", ad_core::proto::PORT_TLS),
        ));
    } else {
        items.push(varovani(
            "api_port_free",
            "Port doménového API",
            format!("Na portu {} už něco poslouchá.", ad_core::proto::PORT_TLS),
            "Zastav to, nebo si v konfiguraci zvol jiný port.",
        ));
    }

    // --- zápis do adresářů ---
    match zkus_zapis(cesty) {
        Ok(()) => items.push(ok(
            "writable_paths",
            "Zápis do datových adresářů",
            format!("{} je zapisovatelný.", cesty.data_dir.display()),
        )),
        Err(e) => items.push(chyba(
            "writable_paths",
            "Zápis do datových adresářů",
            e.message.clone(),
            "Spusť server jako uživatel, který tam smí zapisovat.",
        )),
    }

    // --- hodiny ---
    let nyni = ad_core::nyni();
    if nyni.year() < 2024 || nyni.year() > 2100 {
        items.push(chyba(
            "clock",
            "Systémový čas",
            format!("Čas {nyni} vypadá špatně. Certifikáty by byly neplatné."),
            "Nastav správné datum (timedatectl nebo NTP).",
        ));
    } else {
        items.push(ok("clock", "Systémový čas", format!("{nyni}")));
    }

    // --- původní DNS pro forwarder ---
    let puvodni = zjisti_systemovy_dns();
    if req.dns.forwarders.is_empty() {
        if puvodni.is_empty() {
            items.push(varovani(
                "existing_dns",
                "Přeposílání dotazů",
                "Nenašel jsem, co má systém za DNS, a žádný forwarder jsi nezadal.",
                "Zadej forwarder ručně, např. 1.1.1.1 — jinak nepůjde vyhledávat ve světě.",
            ));
        } else {
            items.push(ok(
                "existing_dns",
                "Přeposílání dotazů",
                format!("Použije se stávající DNS: {}", puvodni.join(", ")),
            ));
        }
    } else {
        let mut spatne = Vec::new();
        for f in &req.dns.forwarders {
            if f.parse::<IpAddr>().is_err() {
                spatne.push(f.clone());
            }
        }
        if spatne.is_empty() {
            items.push(ok(
                "existing_dns",
                "Přeposílání dotazů",
                format!("Zadané forwardery: {}", req.dns.forwarders.join(", ")),
            ));
        } else {
            items.push(chyba(
                "existing_dns",
                "Přeposílání dotazů",
                format!("Tyto adresy nejsou platné IP: {}", spatne.join(", ")),
                "Zadej IP adresy, ne jména.",
            ));
        }
    }

    // --- reverzní zóna ---
    if req.dns.create_reverse && !matches!(req.dns.reverse_prefix, 8 | 16 | 24) {
        items.push(chyba(
            "reverse_prefix",
            "Maska reverzní zóny",
            format!("Maska /{} není podporovaná.", req.dns.reverse_prefix),
            "Použij /8, /16 nebo /24.",
        ));
    }

    let can_continue = !items.iter().any(|i| i.status == CheckStatus::Fail);
    Ok(PrecheckResponse { items, can_continue })
}

/// Povýší server na řadič domény.
pub fn promote(
    store: &Store,
    cesty: &Cesty,
    req: &PromoteRequest,
    dns: StavDns,
    actor: &str,
    ip: &str,
) -> Result<PromoteResponse> {
    if !req.confirm {
        return Err(AdError::bad_request("chybí potvrzení (confirm), doména se nevytvoří omylem"));
    }
    let kontrola = precheck(store, cesty, req, dns)?;
    if !kontrola.can_continue {
        let nesplnene: Vec<&CheckItem> =
            kontrola.items.iter().filter(|i| i.status == CheckStatus::Fail).collect();
        let seznam: Vec<String> =
            nesplnene.iter().map(|i| format!("{}: {}", i.title, i.detail)).collect();
        return Err(AdError::new(
            ErrorCode::PrerequisiteFailed,
            format!("kontrola předpokladů neprošla — {}", seznam.join("; ")),
        )
        .with_details(serde_json::json!({ "items": nesplnene })));
    }

    let jmeno = names::validuj_jmeno_domeny(&req.domain_dns_name)?;
    let kratke = match &req.short_name {
        Some(s) => names::validuj_kratke_jmeno(s)?,
        None => jmeno.kratke.clone(),
    };
    let hostname = names::validuj_jmeno_pocitace(&req.dc_hostname)?;
    let ip_radice: IpAddr = req
        .dc_ip
        .parse()
        .map_err(|_| AdError::bad_request(format!("{} není platná IP adresa", req.dc_ip)))?;
    let dc_fqdn = format!("{}.{}", hostname.to_ascii_lowercase(), jmeno.fqdn);
    let sid = DomainSid::generate();
    let nyni = ad_core::nyni();
    let nyni_text = crate::store::cas_do_db(nyni);

    // --- certifikační autorita a certifikát serveru ---
    // Děláme to před zápisem do databáze: kdyby to selhalo, zůstane
    // databáze čistá.
    cesty.priprav()?;
    let ca = pki::vytvor_ca(&jmeno.fqdn)?;
    let server_cert = pki::vydej_server_cert(
        &jmeno.fqdn,
        &ca.key_pem,
        &[dc_fqdn.clone(), hostname.to_ascii_lowercase(), "localhost".to_string()],
        &[ip_radice, "127.0.0.1".parse().unwrap()],
    )?;
    pki::uloz(&cesty.pki(), &ca, &server_cert)?;
    let otisk = secret::otisk_z_pem(&ca.cert_pem)?;

    let hash_spravce = password::zahasuj(req.administrator_password.odhal())?;
    // Host dostane náhodné heslo, které nikdo nezná — účet je navíc vypnutý.
    let hash_hosta = password::zahasuj(&secret::novy_token())?;

    // POZOR: všechno, co se ptá databáze přes `store`, musí být **před**
    // `store.lock()`. Spojení je za obyčejným mutexem, takže vnořené
    // zamknutí by program zaseklo. Proto si roli zjistíme dopředu.
    let dns_zapnuto = store.role()?.dns;

    let mut spojeni = store.lock();
    let tx = spojeni.transaction().map_err(crate::store::db_chyba)?;

    tx.execute(
        "INSERT INTO domain(id, dns_name, short_name, sid_a, sid_b, sid_c,
             dc_hostname, dc_fqdn, dc_ip, next_rid, created_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            jmeno.fqdn,
            kratke,
            sid.a as i64,
            sid.b as i64,
            sid.c as i64,
            hostname,
            dc_fqdn,
            ip_radice.to_string(),
            rid::FIRST_USER_RID as i64,
            nyni_text
        ],
    )
    .map_err(crate::store::db_chyba)?;

    // --- výchozí organizační jednotky ---
    let ou_id = |tx: &rusqlite::Transaction<'_>, jmeno: &str, popis: &str| -> Result<i64> {
        tx.execute(
            "INSERT INTO ou(guid, name, parent_id, path, description, protected, created_at)
             VALUES (?1, ?2, NULL, ?3, ?4, 1, ?5)",
            params![
                ad_core::ids::novy_guid().to_string(),
                jmeno,
                format!("/{jmeno}"),
                popis,
                nyni_text
            ],
        )
        .map_err(crate::store::db_chyba)?;
        Ok(tx.last_insert_rowid())
    };
    let ou_users = ou_id(&tx, "Users", "Výchozí umístění uživatelských účtů")?;
    let _ou_computers = ou_id(&tx, "Computers", "Výchozí umístění počítačů")?;
    let _ou_dc = ou_id(&tx, "Domain Controllers", "Řadiče domény")?;

    // --- vestavěné skupiny ---
    let vloz_skupinu = |tx: &rusqlite::Transaction<'_>,
                        r: u32,
                        sam: &str,
                        jmeno: &str,
                        popis: &str|
     -> Result<i64> {
        tx.execute(
            "INSERT INTO groups(guid, rid, sam, name, description, kind, ou_id, builtin, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'security', NULL, 1, ?6)",
            params![ad_core::ids::novy_guid().to_string(), r as i64, sam, jmeno, popis, nyni_text],
        )
        .map_err(crate::store::db_chyba)?;
        Ok(tx.last_insert_rowid())
    };
    let g_admins = vloz_skupinu(
        &tx,
        rid::DOMAIN_ADMINS,
        "domain-admins",
        "Domain Admins",
        "Správci domény — plná správa",
    )?;
    let g_users = vloz_skupinu(
        &tx,
        rid::DOMAIN_USERS,
        "domain-users",
        "Domain Users",
        "Všichni uživatelé domény",
    )?;
    let _g_computers = vloz_skupinu(
        &tx,
        rid::DOMAIN_COMPUTERS,
        "domain-computers",
        "Domain Computers",
        "Všechny počítače připojené do domény",
    )?;
    let _g_dns =
        vloz_skupinu(&tx, rid::DNS_ADMINS, "dns-admins", "DNS Admins", "Správa DNS zón a záznamů")?;

    // --- vestavěné účty ---
    tx.execute(
        "INSERT INTO users(guid, rid, sam, password_hash, display_name, given_name, surname,
             email, description, ou_id, enabled, must_change_password,
             password_never_expires, password_set_at, builtin, created_at)
         VALUES (?1, ?2, 'administrator', ?3, 'Administrator', '', '', '',
             'Vestavěný účet správce domény', ?4, 1, 0, 1, ?5, 1, ?5)",
        params![
            ad_core::ids::novy_guid().to_string(),
            rid::ADMINISTRATOR as i64,
            hash_spravce,
            ou_users,
            nyni_text
        ],
    )
    .map_err(crate::store::db_chyba)?;
    let u_admin = tx.last_insert_rowid();

    tx.execute(
        "INSERT INTO users(guid, rid, sam, password_hash, display_name, given_name, surname,
             email, description, ou_id, enabled, must_change_password,
             password_never_expires, password_set_at, builtin, created_at)
         VALUES (?1, ?2, 'guest', ?3, 'Guest', '', '', '',
             'Vestavěný účet hosta — vypnutý', ?4, 0, 0, 1, ?5, 1, ?5)",
        params![
            ad_core::ids::novy_guid().to_string(),
            rid::GUEST as i64,
            hash_hosta,
            ou_users,
            nyni_text
        ],
    )
    .map_err(crate::store::db_chyba)?;

    for g in [g_admins, g_users] {
        tx.execute(
            "INSERT INTO group_members(group_id, member_kind, member_id, added_at)
             VALUES (?1, 'user', ?2, ?3)",
            params![g, u_admin, nyni_text],
        )
        .map_err(crate::store::db_chyba)?;
    }

    tx.execute(
        "INSERT INTO password_history(user_id, password_hash, set_at) VALUES (?1, ?2, ?3)",
        params![u_admin, hash_spravce, nyni_text],
    )
    .map_err(crate::store::db_chyba)?;

    // --- DNS zóny ---
    let mut zony: Vec<String> = Vec::new();
    if dns_zapnuto {
        let rname = format!("hostmaster.{}", jmeno.fqdn);
        tx.execute(
            "INSERT INTO dns_zones(name, kind, serial, primary_ns, rname, managed, created_at)
             VALUES (?1, 'forward', 1, ?2, ?3, 1, ?4)",
            params![jmeno.fqdn, dc_fqdn, rname, nyni_text],
        )
        .map_err(crate::store::db_chyba)?;
        let z_forward = tx.last_insert_rowid();
        zony.push(jmeno.fqdn.clone());

        let vloz_zaznam = |tx: &rusqlite::Transaction<'_>,
                           zona: i64,
                           jmeno_zaznamu: &str,
                           data: &dns::RecordData|
         -> Result<()> {
            let json = serde_json::to_string(data)
                .map_err(|e| AdError::internal(format!("záznam DNS: {e}")))?;
            tx.execute(
                "INSERT INTO dns_records(zone_id, name, rtype, ttl, rdata_json, managed, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                params![
                    zona,
                    jmeno_zaznamu,
                    data.typ().as_str(),
                    dns::VYCHOZI_TTL,
                    json,
                    nyni_text
                ],
            )
            .map_err(crate::store::db_chyba)?;
            Ok(())
        };

        vloz_zaznam(&tx, z_forward, "@", &dns::RecordData::Ns { target: dc_fqdn.clone() })?;
        if let IpAddr::V4(v4) = ip_radice {
            vloz_zaznam(
                &tx,
                z_forward,
                &hostname.to_ascii_lowercase(),
                &dns::RecordData::A { address: v4 },
            )?;
        }
        vloz_zaznam(
            &tx,
            z_forward,
            dns::SRV_SLUZBA,
            &dns::RecordData::Srv {
                priority: 0,
                weight: 100,
                port: ad_core::proto::PORT_TLS,
                target: dc_fqdn.clone(),
            },
        )?;

        // Reverzní zóna
        if req.dns.create_reverse {
            if let IpAddr::V4(v4) = ip_radice {
                let jmeno_zony = dns::reverzni_zona_ipv4(v4, req.dns.reverse_prefix)?;
                tx.execute(
                    "INSERT INTO dns_zones(name, kind, serial, primary_ns, rname, managed, created_at)
                     VALUES (?1, 'reverse', 1, ?2, ?3, 1, ?4)",
                    params![jmeno_zony, dc_fqdn, format!("hostmaster.{}", jmeno.fqdn), nyni_text],
                )
                .map_err(crate::store::db_chyba)?;
                let z_rev = tx.last_insert_rowid();
                let relativni = dns::ptr_relativne(v4, &jmeno_zony)?;
                vloz_zaznam(&tx, z_rev, "@", &dns::RecordData::Ns { target: dc_fqdn.clone() })?;
                vloz_zaznam(
                    &tx,
                    z_rev,
                    &relativni,
                    &dns::RecordData::Ptr { target: dc_fqdn.clone() },
                )?;
                zony.push(jmeno_zony);
            } else {
                tracing::warn!("reverzní zónu umíme jen pro IPv4, přeskakuji");
            }
        }
    }

    tx.commit().map_err(crate::store::db_chyba)?;
    drop(spojeni);

    // --- nastavení ---
    store.nastav(nastaveni::CA_FINGERPRINT, &otisk)?;
    let forwardery: Vec<String> = if req.dns.forwarders.is_empty() {
        zjisti_systemovy_dns()
    } else {
        req.dns.forwarders.clone()
    };
    store.nastav(
        nastaveni::DNS_FORWARDERS,
        &serde_json::to_string(&forwardery).unwrap_or_else(|_| "[]".into()),
    )?;
    store.nastav(
        nastaveni::DNS_ORIGINAL,
        &serde_json::to_string(&zjisti_systemovy_dns()).unwrap_or_else(|_| "[]".into()),
    )?;
    // Jednorázový token už neplatí a všechny session končí — od teď se
    // přihlašuje doménový správce.
    store.zrus_nastaveni(nastaveni::SETUP_TOKEN_HASH)?;
    store.smaz_vsechny_session()?;
    let _ = std::fs::remove_file(cesty.setup_token());

    store.zapis_audit(
        "domain.promote",
        actor,
        &jmeno.fqdn,
        ip,
        true,
        &format!("řadič {dc_fqdn}, adresa {ip_radice}"),
    )?;

    let domena = store.domena_nebo_chyba()?;
    Ok(PromoteResponse {
        domain: domena,
        ca_fingerprint_sha256: otisk,
        zones: zony,
        next_steps: vec![
            "Přihlas se znovu jako administrator s heslem, které jsi právě zadal.".into(),
            "Otisk CA opiš klientům: ad-client join --fingerprint <otisk>".to_string(),
            "Vytvoř organizační jednotky a uživatele v nástroji Uživatelé a počítače.".into(),
            "Nastav klientům tento server jako DNS (klient to udělá sám při připojení).".into(),
        ],
        client_endpoint: format!("https://{dc_fqdn}:{}", ad_core::proto::PORT_TLS),
    })
}

/// Zruší doménu. Smaže objekty i DNS zóny, případně celou databázi.
pub fn demote(
    store: &Store,
    cesty: &Cesty,
    potvrzene_jmeno: &str,
    smazat_databazi: bool,
    actor: &str,
    ip: &str,
) -> Result<()> {
    let d: Domain = store.domena_nebo_chyba()?;
    if potvrzene_jmeno.trim().to_ascii_lowercase() != d.dns_name {
        return Err(AdError::bad_request(
            "jméno domény pro potvrzení nesouhlasí — nic jsem nesmazal",
        ));
    }

    let mut spojeni = store.lock();
    let tx = spojeni.transaction().map_err(crate::store::db_chyba)?;
    for tabulka in [
        "user_tickets",
        "machine_tokens",
        "admin_sessions",
        "group_members",
        "password_history",
        "gpo_links",
        "gpos",
        "dns_records",
        "dns_zones",
        "computers",
        "users",
        "groups",
        "ou",
        "domain",
    ] {
        tx.execute(&format!("DELETE FROM {tabulka}"), []).map_err(crate::store::db_chyba)?;
    }
    if smazat_databazi {
        for tabulka in ["events", "login_attempts", "assets", "settings"] {
            tx.execute(&format!("DELETE FROM {tabulka}"), []).map_err(crate::store::db_chyba)?;
        }
    }
    tx.commit().map_err(crate::store::db_chyba)?;
    drop(spojeni);

    // PKI se smaže taky — CA domény, která už neexistuje, nemá co dělat
    // na disku.
    let p = pki::SouboryPki::v(&cesty.pki());
    for f in [&p.ca_cert, &p.ca_key, &p.server_cert, &p.server_key] {
        let _ = std::fs::remove_file(f);
    }
    store.zrus_nastaveni(nastaveni::CA_FINGERPRINT)?;
    store.zrus_nastaveni(nastaveni::ROLE_DIRECTORY)?;
    store.zrus_nastaveni(nastaveni::ROLE_DNS)?;

    if !smazat_databazi {
        store.zapis_audit("domain.demote", actor, &d.dns_name, ip, true, "doména zrušena")?;
    }
    Ok(())
}

// -----------------------------------------------------------------------
// Zjišťování stavu systému
// -----------------------------------------------------------------------

/// Patří IP adresa tomuto stroji? Zkusíme se na ni navázat — když to
/// jde, adresa je naše. Žádná další knihovna k tomu netřeba.
pub fn patri_stroji(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Je port volný? Zkusíme se na něj navázat a hned ho pustíme.
pub fn port_volny(port: u16) -> bool {
    let adresa = SocketAddr::from(([0, 0, 0, 0], port));
    let tcp = std::net::TcpListener::bind(adresa).is_ok();
    let udp = std::net::UdpSocket::bind(adresa).is_ok();
    tcp && udp
}

fn zkus_zapis(cesty: &Cesty) -> Result<()> {
    cesty.priprav()?;
    let test = cesty.data_dir.join(".zapis-test");
    std::fs::write(&test, b"test").map_err(|e| {
        AdError::internal(format!("do {} nelze zapsat: {e}", cesty.data_dir.display()))
    })?;
    let _ = std::fs::remove_file(&test);
    Ok(())
}

/// Co má systém nastavené jako DNS. Používá se jako výchozí forwarder.
///
/// Na Linuxu čteme `/etc/resolv.conf`. Na Windows to zatím neumíme
/// zjistit bez dalších knihoven — vrátíme prázdný seznam a správce
/// forwarder zadá ručně. **Je to známá mezera, ne omyl.**
pub fn zjisti_systemovy_dns() -> Vec<String> {
    #[cfg(unix)]
    {
        let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
            return Vec::new();
        };
        let mut v = Vec::new();
        for radek in text.lines() {
            let r = radek.trim();
            if let Some(zbytek) = r.strip_prefix("nameserver") {
                if let Ok(ip) = zbytek.trim().parse::<IpAddr>() {
                    // Vlastní adresa jako forwarder by byla smyčka.
                    if !ip.is_loopback() && !v.contains(&ip.to_string()) {
                        v.push(ip.to_string());
                    }
                }
            }
        }
        v
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ad_core::proto::{PromoteDnsOptions, PromoteRequest};

    /// Testy nesmí záviset na tom, jestli zrovna běžíme jako root:
    /// na port pod 1024 by se jako obyčejný uživatel navázat nedalo.
    const DNS_TEST: StavDns = StavDns { bezi: false, port: 15353 };

    fn pozadavek() -> PromoteRequest {
        PromoteRequest {
            domain_dns_name: "skola.internal".into(),
            short_name: None,
            dc_hostname: "DC01".into(),
            dc_ip: "127.0.0.1".into(),
            administrator_password: secret::Tajne::new("Spravce-Heslo1"),
            dns: PromoteDnsOptions {
                create_reverse: true,
                reverse_prefix: 24,
                forwarders: vec![],
                enable_server: false,
            },
            confirm: true,
        }
    }

    fn prostredi() -> (Store, Cesty, tempdir::Smazat) {
        let dir = std::env::temp_dir().join(format!(
            "ad-domain-test-{}-{}",
            std::process::id(),
            &ad_core::secret::novy_token().replace(['-', '_'], "")[..8]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cesty = Cesty::nove(Some(dir.clone()), Some(dir.join("config.toml")));
        let store = Store::v_pameti().unwrap();
        (store, cesty, tempdir::Smazat(dir))
    }

    mod tempdir {
        pub struct Smazat(pub std::path::PathBuf);
        impl Drop for Smazat {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn precheck_bez_roli_neprojde() {
        let (store, cesty, _u) = prostredi();
        let v = precheck(&store, &cesty, &pozadavek(), DNS_TEST).unwrap();
        assert!(!v.can_continue, "bez role doménových služeb to nesmí projít");
        assert!(v
            .items
            .iter()
            .any(|i| i.code == "role_directory" && i.status == CheckStatus::Fail));
    }

    #[test]
    fn precheck_s_rolemi_projde() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        store.nastav_bool(nastaveni::ROLE_DNS, true).unwrap();
        let v = precheck(&store, &cesty, &pozadavek(), DNS_TEST).unwrap();
        assert!(
            v.can_continue,
            "{:#?}",
            v.items.iter().filter(|i| i.status == CheckStatus::Fail).collect::<Vec<_>>()
        );
    }

    #[test]
    fn precheck_odmitne_local_a_slabe_heslo() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        let mut req = pozadavek();
        req.domain_dns_name = "skola.local".into();
        req.administrator_password = secret::Tajne::new("heslo");
        let v = precheck(&store, &cesty, &req, DNS_TEST).unwrap();
        assert!(!v.can_continue);
        assert!(v.items.iter().any(|i| i.code == "domain_name" && i.status == CheckStatus::Fail));
        assert!(v
            .items
            .iter()
            .any(|i| i.code == "admin_password" && i.status == CheckStatus::Fail));
    }

    #[test]
    fn povyseni_vytvori_domenu_s_vestavenymi_objekty() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        store.nastav_bool(nastaveni::ROLE_DNS, true).unwrap();
        let odpoved =
            promote(&store, &cesty, &pozadavek(), DNS_TEST, "setup-token", "127.0.0.1").unwrap();

        assert_eq!(odpoved.domain.dns_name, "skola.internal");
        assert_eq!(odpoved.domain.short_name, "SKOLA");
        assert_eq!(odpoved.domain.dc_fqdn, "dc01.skola.internal");
        assert_eq!(odpoved.ca_fingerprint_sha256.len(), 95);
        assert_eq!(odpoved.zones.len(), 2, "dopředná i reverzní zóna");
        assert!(odpoved.zones.contains(&"skola.internal".to_string()));
        assert!(odpoved.zones.iter().any(|z| z.ends_with("in-addr.arpa")));

        // Vestavěné objekty
        let admin = store.uzivatel_podle_sam("administrator").unwrap().unwrap();
        assert!(admin.builtin && admin.enabled);
        assert_eq!(admin.sid.rid, rid::ADMINISTRATOR);
        let host = store.uzivatel_podle_sam("guest").unwrap().unwrap();
        assert!(!host.enabled, "host musí být vypnutý");
        assert!(store.je_ve_skupine_rid(admin.id, rid::DOMAIN_ADMINS).unwrap());
        assert_eq!(store.seznam_ou().unwrap().len(), 3);

        // Soubory PKI
        assert!(pki::SouboryPki::v(&cesty.pki()).existuji());
        assert_eq!(pki::otisk_ca(&cesty.pki()).unwrap(), odpoved.ca_fingerprint_sha256);

        // Druhé povýšení už nesmí projít.
        let e = promote(&store, &cesty, &pozadavek(), DNS_TEST, "x", "127.0.0.1").unwrap_err();
        assert_eq!(e.code, ErrorCode::PrerequisiteFailed);
    }

    #[test]
    fn povyseni_bez_potvrzeni_neprojde() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        let mut req = pozadavek();
        req.confirm = false;
        assert!(promote(&store, &cesty, &req, DNS_TEST, "x", "127.0.0.1").is_err());
    }

    #[test]
    fn prihlaseni_spravce_po_povyseni() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        promote(&store, &cesty, &pozadavek(), DNS_TEST, "setup-token", "127.0.0.1").unwrap();

        let u = store.over_spravce("administrator", "Spravce-Heslo1", "127.0.0.1").unwrap();
        assert_eq!(u.sam_account_name, "administrator");
        assert_eq!(u.upn, "administrator@skola.internal");

        // Krátký tvar jména i UPN
        store.over_spravce("SKOLA\\administrator", "Spravce-Heslo1", "127.0.0.1").unwrap();
        store.over_spravce("administrator@skola.internal", "Spravce-Heslo1", "127.0.0.1").unwrap();
        // Špatné heslo
        assert_eq!(
            store.over_spravce("administrator", "spatne", "127.0.0.1").unwrap_err().code,
            ErrorCode::InvalidCredentials
        );
    }

    #[test]
    fn zruseni_domeny_uklidi_vsechno() {
        let (store, cesty, _u) = prostredi();
        store.nastav_bool(nastaveni::ROLE_DIRECTORY, true).unwrap();
        store.nastav_bool(nastaveni::ROLE_DNS, true).unwrap();
        promote(&store, &cesty, &pozadavek(), DNS_TEST, "setup", "127.0.0.1").unwrap();

        // Špatné jméno pro potvrzení nic nesmaže.
        assert!(demote(&store, &cesty, "jina.internal", false, "x", "127.0.0.1").is_err());
        assert!(store.domena().unwrap().is_some());

        demote(&store, &cesty, "skola.internal", false, "administrator", "127.0.0.1").unwrap();
        assert!(store.domena().unwrap().is_none());
        assert_eq!(store.pocty().unwrap().users, 0);
        assert_eq!(store.pocty().unwrap().zones, 0);
        assert!(!pki::SouboryPki::v(&cesty.pki()).existuji());
        // Audit zůstává — chceme vědět, že se doména rušila.
        assert!(store.audit(&Default::default()).unwrap().total > 0);
    }
}
