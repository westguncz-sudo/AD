//! `ad-client` — připojení počítače do naší vlastní domény.
//!
//! Co klient dělá:
//! * připojí počítač do domény (s kontrolou otisku certifikátu),
//! * zazálohuje nastavení DNS a přepne ho na doménový server,
//! * přihlásí doménového uživatele **v tomhle programu**,
//! * stáhne a použije zásady,
//! * při odpojení vrátí všechno do původního stavu.
//!
//! Co klient **nedělá**: nezasahuje do přihlašování do systému.
//! Žádný Credential Provider na Windows, žádný modul PAM na Linuxu.
//! To je samostatná a riziková kapitola a zadání ji vylučuje.

mod dns;
mod spojeni;
mod stav;
mod zasady;

use ad_core::{AdError, Result};
use spojeni::Klient;
use stav::{Cesty, StavPripojeni, UlozeneZasady};
use std::path::PathBuf;

fn main() {
    let kod = match bezet() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("\nad-client: {}", e.message);
            if e.code == ad_core::ErrorCode::FingerprintMismatch {
                eprintln!(
                    "\nOtisk si ověř ve správě serveru (Místní server → Certifikační\n\
                     autorita domény). Dokud nesouhlasí, nic se neodeslalo —\n\
                     heslo správce se posílá až po ověření otisku."
                );
            }
            1
        }
    };
    std::process::exit(kod);
}

fn bezet() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let prikaz = args.first().map(String::as_str).unwrap_or("--help");

    match prikaz {
        "-V" | "--version" => {
            println!("ad-client {} (protokol {})", ad_core::VERZE, ad_core::proto::PROTO_VERZE);
            Ok(())
        }
        "-h" | "--help" | "help" => {
            napoveda();
            Ok(())
        }
        "join" | "status" | "logon" | "policy" | "leave" | "passwd" => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| AdError::internal(format!("tokio: {e}")))?;
            runtime.block_on(vykonej(prikaz, &args[1..]))
        }
        jiny => {
            eprintln!("Neznámý příkaz: {jiny}\n");
            napoveda();
            Err(AdError::bad_request("neznámý příkaz"))
        }
    }
}

async fn vykonej(prikaz: &str, args: &[String]) -> Result<()> {
    let p = Prepinace::zparsuj(args)?;
    let cesty = Cesty::nove(p.data_dir.clone());
    match prikaz {
        "join" => join(&cesty, &p).await,
        "status" => status(&cesty).await,
        "logon" => logon(&cesty, &p).await,
        "policy" => policy(&cesty, &p).await,
        "passwd" => passwd(&cesty, &p).await,
        "leave" => leave(&cesty, &p).await,
        _ => unreachable!(),
    }
}

// =======================================================================
// Přepínače
// =======================================================================

#[derive(Debug, Default)]
struct Prepinace {
    server: Option<String>,
    fingerprint: Option<String>,
    admin: Option<String>,
    user: Option<String>,
    name: Option<String>,
    ou: Option<String>,
    data_dir: Option<PathBuf>,
    heslo_ze_stdin: bool,
    bez_dns: bool,
    pouzij_zasady: bool,
    vynutit: bool,
}

impl Prepinace {
    fn zparsuj(args: &[String]) -> Result<Self> {
        let mut p = Self::default();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let mut hodnota = |jmeno: &str| -> Result<String> {
                i += 1;
                args.get(i)
                    .cloned()
                    .ok_or_else(|| AdError::bad_request(format!("{jmeno} potřebuje hodnotu")))
            };
            match a {
                "--server" => p.server = Some(hodnota("--server")?),
                "--fingerprint" => p.fingerprint = Some(hodnota("--fingerprint")?),
                "--admin" => p.admin = Some(hodnota("--admin")?),
                "--user" => p.user = Some(hodnota("--user")?),
                "--name" => p.name = Some(hodnota("--name")?),
                "--ou" => p.ou = Some(hodnota("--ou")?),
                "--data-dir" => p.data_dir = Some(PathBuf::from(hodnota("--data-dir")?)),
                "--password-stdin" => p.heslo_ze_stdin = true,
                "--no-dns" => p.bez_dns = true,
                "--apply" => p.pouzij_zasady = true,
                "--force" => p.vynutit = true,
                "--password" => {
                    return Err(AdError::bad_request(
                        "heslo se na příkazové řádce nezadává — je vidět v seznamu procesů \
                         (ps, Správce úloh) a zůstane v historii shellu. Použij --password-stdin \
                         nebo proměnnou prostředí.",
                    ))
                }
                jiny => return Err(AdError::bad_request(format!("neznámý přepínač: {jiny}"))),
            }
            i += 1;
        }
        Ok(p)
    }
}

fn napoveda() {
    println!(
        r#"ad-client {verze} — připojení počítače do vlastní domény

POUŽITÍ:
    ad-client PŘÍKAZ [PŘEPÍNAČE]

PŘÍKAZY:
    join      připojí počítač do domény
    status    vypíše stav připojení, DNS a poslední zásady
    logon     přihlásí doménového uživatele v tomto programu
    passwd    změní heslo doménového uživatele
    policy    stáhne zásady (s --apply je i použije)
    leave     odpojí počítač a vrátí původní nastavení DNS

PŘEPÍNAČE:
    --server HOST[:PORT]   adresa řadiče domény (výchozí port {port})
    --fingerprint OTISK    otisk certifikační autority domény
    --admin JMÉNO          účet správce domény (pro join)
    --user JMÉNO           doménový uživatel (pro logon a passwd)
    --name JMÉNO           jméno počítače (výchozí: jméno tohoto stroje)
    --ou CESTA             organizační jednotka, např. /Computers
    --data-dir CESTA       kam ukládat stav (výchozí podle systému)
    --password-stdin       heslo načíst ze standardního vstupu
    --no-dns               neměnit nastavení DNS
    --apply                u příkazu policy zásady i použít
    --force                u příkazu leave uklidit i bez spojení se serverem
    -V, --version          verze
    -h, --help             tato nápověda

HESLA:
    Heslo se nikdy nezadává jako přepínač — bylo by vidět v seznamu
    procesů. Buď ho program vyžádá, nebo:
        echo 'heslo' | ad-client join ... --password-stdin
        AD_ADMIN_PASSWORD=heslo ad-client join ...
        AD_USER_PASSWORD=heslo ad-client logon ...

PŘÍKLAD:
    # otisk najdeš ve správě serveru: Místní server → Certifikační autorita
    sudo ad-client join --server 192.168.56.10 \
        --fingerprint A1:B2:...:FF --admin administrator

    ad-client logon --user jan.novak
    sudo ad-client leave

CO TENHLE PROGRAM NEDĚLÁ:
    Nezasahuje do přihlašování do systému. Doménovým účtem se přihlásíš
    v tomhle programu, ne na přihlašovací obrazovce Windows nebo Linuxu.
"#,
        verze = ad_core::VERZE,
        port = ad_core::proto::PORT_TLS,
    );
}

// =======================================================================
// Hesla
// =======================================================================

/// Načte heslo: ze standardního vstupu, z proměnné prostředí, nebo se
/// zeptá. Nikdy ne z příkazové řádky.
fn nacti_heslo(p: &Prepinace, promenna: &str, vyzva: &str) -> Result<String> {
    if p.heslo_ze_stdin {
        let mut radek = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut radek)
            .map_err(|e| AdError::internal(format!("čtení hesla: {e}")))?;
        let h = radek.trim_end_matches(['\n', '\r']).to_string();
        if h.is_empty() {
            return Err(AdError::bad_request("na standardním vstupu nebylo žádné heslo"));
        }
        return Ok(h);
    }
    if let Ok(h) = std::env::var(promenna) {
        if !h.is_empty() {
            return Ok(h);
        }
    }
    zeptej_se_na_heslo(vyzva)
}

/// Zeptá se na heslo a schová psaní, kde to jde.
fn zeptej_se_na_heslo(vyzva: &str) -> Result<String> {
    use std::io::Write;
    print!("{vyzva}: ");
    std::io::stdout().flush().ok();

    let schovano = vypni_echo();
    let mut radek = String::new();
    let vysledek = std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut radek);
    if schovano {
        zapni_echo();
        println!();
    }
    vysledek.map_err(|e| AdError::internal(format!("čtení hesla: {e}")))?;

    let h = radek.trim_end_matches(['\n', '\r']).to_string();
    if h.is_empty() {
        return Err(AdError::bad_request("heslo je prázdné"));
    }
    Ok(h)
}

/// Vypne zobrazování psaného textu. Vrací `true`, když se to povedlo.
#[cfg(unix)]
fn vypni_echo() -> bool {
    std::process::Command::new("stty")
        .args(["-echo"])
        .stdin(std::process::Stdio::inherit())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn zapni_echo() {
    let _ = std::process::Command::new("stty")
        .args(["echo"])
        .stdin(std::process::Stdio::inherit())
        .status();
}

/// Na Windows psaní neschováváme — bylo by k tomu potřeba volat
/// konzolové API. Radši o tom řekneme, než abychom mlčeli.
#[cfg(not(unix))]
fn vypni_echo() -> bool {
    eprintln!("(psané heslo bude vidět — použij --password-stdin, pokud ti to vadí)");
    false
}

#[cfg(not(unix))]
fn zapni_echo() {}

// =======================================================================
// Pomocné
// =======================================================================

/// Rozdělí `host` nebo `host:port`.
fn rozdel_server(vstup: &str) -> Result<(String, u16)> {
    let vstup = vstup.trim();
    if vstup.is_empty() {
        return Err(AdError::bad_request("adresa serveru je prázdná"));
    }
    // IPv6 v hranatých závorkách
    if let Some(zbytek) = vstup.strip_prefix('[') {
        let (adresa, zbytek) = zbytek
            .split_once(']')
            .ok_or_else(|| AdError::bad_request("chybí uzavírací závorka v IPv6 adrese"))?;
        let port = match zbytek.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| AdError::bad_request("port není číslo"))?,
            None => ad_core::proto::PORT_TLS,
        };
        return Ok((adresa.to_string(), port));
    }
    match vstup.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => Ok((
            host.to_string(),
            port.parse().map_err(|_| AdError::bad_request("port není číslo"))?,
        )),
        _ => Ok((vstup.to_string(), ad_core::proto::PORT_TLS)),
    }
}

/// Jméno tohoto počítače.
fn jmeno_stroje() -> String {
    #[cfg(windows)]
    let syrove = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(windows))]
    let syrove = std::fs::read_to_string("/etc/hostname").unwrap_or_default();

    let kratke = syrove.trim().split('.').next().unwrap_or("").to_string();
    match ad_core::names::validuj_jmeno_pocitace(&kratke) {
        Ok(j) => j,
        Err(_) => "PC-01".to_string(),
    }
}

/// Vymění tajemství počítačového účtu za krátkodobý token.
async fn ziskej_token(klient: &Klient, s: &StavPripojeni) -> Result<String> {
    let odpoved = klient
        .poslat(
            "POST",
            "/api/v1/machine/token",
            Some(&serde_json::json!({
                "machine_id": s.machine_id,
                "machine_secret": s.machine_secret,
            })),
            None,
        )
        .await?;
    let t: ad_core::proto::MachineTokenResponse = odpoved.json()?;
    Ok(t.token.odhal().to_string())
}

/// Klient podle uloženého stavu.
fn klient_ze_stavu(cesty: &Cesty, s: &StavPripojeni) -> Result<Klient> {
    let ca = std::fs::read_to_string(cesty.ca()).ok();
    Klient::novy(&s.server_host, s.server_port, &s.ca_fingerprint, ca.as_deref())
}

// =======================================================================
// join
// =======================================================================

async fn join(cesty: &Cesty, p: &Prepinace) -> Result<()> {
    if let Some(stary) = StavPripojeni::nacti(cesty)? {
        return Err(AdError::conflict(format!(
            "počítač už je v doméně {} jako {}. Nejdřív spusť: ad-client leave",
            stary.domain_dns_name, stary.computer_name
        )));
    }

    let server = p
        .server
        .as_deref()
        .ok_or_else(|| AdError::bad_request("chybí --server (adresa řadiče domény)"))?;
    let otisk = p.fingerprint.as_deref().ok_or_else(|| {
        AdError::bad_request(
            "chybí --fingerprint. Otisk certifikační autority najdeš ve správě \
             serveru v části Místní server. Bez něj se připojit nedá — jinak by \
             se nedalo poznat, jestli mluvíš se svým serverem.",
        )
    })?;
    let admin = p.admin.as_deref().unwrap_or("administrator");
    let (host, port) = rozdel_server(server)?;
    let jmeno = match &p.name {
        Some(j) => ad_core::names::validuj_jmeno_pocitace(j)?,
        None => jmeno_stroje(),
    };

    println!("Připojuji počítač {jmeno} do domény přes {host}:{port}");
    println!("Připnutý otisk: {}", ad_core::secret::normalizuj_otisk(otisk)?);

    // 1. Spojení — tady se ověří otisk. Heslo se ještě neposílá.
    let klient = Klient::novy(&host, port, otisk, None)?;
    let hello: ad_core::proto::HelloResponse =
        klient.poslat("GET", "/api/v1/hello", None, None).await?.json()?;
    println!("  ✓ otisk souhlasí, server je {} {}", hello.product, hello.version);

    ad_core::proto::zkontroluj_verzi(hello.proto_max.min(ad_core::proto::PROTO_VERZE))?;
    let Some(domena) = hello.domain.clone() else {
        return Err(AdError::new(
            ad_core::ErrorCode::DomainNotCreated,
            "na serveru zatím žádná doména není — nejdřív ho povyš na řadič domény",
        ));
    };
    println!("  ✓ doména {} ({})", domena.dns_name, domena.short_name);

    // 2. Teprve teď heslo správce.
    let heslo = nacti_heslo(p, "AD_ADMIN_PASSWORD", &format!("Heslo účtu {admin}"))?;

    let telo = serde_json::json!({
        "computer_name": jmeno,
        "admin_username": admin,
        "admin_password": heslo,
        "ou_path": p.ou,
        "os_name": popis_systemu(),
        "os_version": verze_systemu(),
        "client_version": ad_core::VERZE,
    });
    let odpoved = klient.poslat("POST", "/api/v1/join", Some(&telo), None).await?;
    let pripojeni: ad_core::proto::JoinResponse = odpoved.json()?;
    println!("  ✓ počítačový účet vytvořen ({})", pripojeni.computer.dns_name);

    // 3. Uložíme certifikát autority a stav.
    //
    // Ukládáme otisk, který zadal správce — ne ten, co tvrdí server.
    // A ověříme, že certifikát v odpovědi tomu otisku odpovídá a že je
    // to tentýž certifikát, kterým se server právě prokázal při TLS.
    // Jinak by server mohl podstrčit pro příště jinou autoritu.
    let otisk_zadany = ad_core::secret::normalizuj_otisk(otisk)?;
    let otisk_z_odpovedi = ad_core::secret::otisk_z_pem(&pripojeni.ca_cert_pem)?;
    if !ad_core::secret::otisky_se_rovnaji(&otisk_zadany, &otisk_z_odpovedi)? {
        return Err(AdError::new(
            ad_core::ErrorCode::FingerprintMismatch,
            "certifikát autority v odpovědi neodpovídá otisku, který jsi zadal.              Nic jsem neuložil.",
        ));
    }
    if let Some(pouzity) = klient.zachycena_ca_pem() {
        let otisk_pouzity = ad_core::secret::otisk_z_pem(&pouzity)?;
        if !ad_core::secret::otisky_se_rovnaji(&otisk_zadany, &otisk_pouzity)? {
            return Err(AdError::new(
                ad_core::ErrorCode::FingerprintMismatch,
                "server se při spojení prokázal jinou autoritou, než jakou poslal                  v odpovědi. Nic jsem neuložil.",
            ));
        }
    }

    cesty.priprav()?;
    std::fs::write(cesty.ca(), &pripojeni.ca_cert_pem)
        .map_err(|e| AdError::internal(format!("nelze uložit certifikát autority: {e}")))?;

    let novy_stav = StavPripojeni {
        server_host: host.clone(),
        server_port: port,
        ca_fingerprint: otisk_zadany,
        machine_id: pripojeni.machine_id.to_string(),
        machine_secret: pripojeni.machine_secret.odhal().to_string(),
        computer_name: pripojeni.computer.name.clone(),
        domain_dns_name: pripojeni.domain.dns_name.clone(),
        domain_short_name: pripojeni.domain.short_name.clone(),
        dc_fqdn: pripojeni.domain.dc_fqdn.clone(),
        dns_servers: pripojeni.dns_servers.clone(),
        policy_poll_seconds: pripojeni.policy_poll_seconds,
        joined_at: stav::nyni_text(),
    };
    novy_stav.uloz(cesty)?;
    println!("  ✓ stav uložen do {}", cesty.stav().display());

    // 4. DNS: nejdřív záloha, pak teprve změna.
    if p.bez_dns {
        println!("  • DNS neměním (--no-dns)");
    } else if pripojeni.dns_servers.is_empty() {
        println!("  • server neposlal žádnou adresu DNS, nic neměním");
    } else {
        match dns::zalohuj() {
            Ok(zaloha) => {
                println!("  ✓ původní DNS zazálohováno: {}", zaloha.popis());
                zaloha.uloz(cesty)?;
                match dns::nastav(&pripojeni.dns_servers, &pripojeni.domain.dns_name) {
                    Ok(()) => println!("  ✓ DNS nastaveno na {}", pripojeni.dns_servers.join(", ")),
                    Err(e) => {
                        eprintln!("  ! DNS se nepodařilo nastavit: {}", e.message);
                        eprintln!("    Nastav ho ručně na {}", pripojeni.dns_servers.join(", "));
                    }
                }
            }
            Err(e) => {
                eprintln!("  ! zálohu DNS se nepodařilo udělat: {}", e.message);
                eprintln!("    DNS proto neměním — nechci nechat počítač bez cesty zpátky.");
            }
        }
    }

    // 5. První stažení zásad.
    match stahni_zasady(cesty, &klient, &novy_stav).await {
        Ok((z, _)) => println!("  ✓ zásady staženy (verze {})", z.serial),
        Err(e) => eprintln!("  ! zásady se nepodařilo stáhnout: {}", e.message),
    }

    println!(
        "\nHotovo. Počítač {} je v doméně {}.\n\
         Přihlášení uživatele:  ad-client logon --user jmeno\n\
         Odpojení:              ad-client leave",
        novy_stav.computer_name, novy_stav.domain_dns_name
    );
    Ok(())
}

fn popis_systemu() -> String {
    #[cfg(target_os = "linux")]
    {
        // Jméno distribuce z /etc/os-release, ať je v přehledu vidět
        // Debian a Void zvlášť.
        if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
            for radek in text.lines() {
                if let Some(h) = radek.strip_prefix("NAME=") {
                    return h.trim_matches('"').to_string();
                }
            }
        }
        "Linux".to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
    }
}

fn verze_systemu() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
            for radek in text.lines() {
                if let Some(h) = radek.strip_prefix("VERSION_ID=") {
                    return h.trim_matches('"').to_string();
                }
            }
        }
        String::new()
    }
    #[cfg(windows)]
    {
        std::env::var("OS").unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        String::new()
    }
}

// =======================================================================
// status
// =======================================================================

async fn status(cesty: &Cesty) -> Result<()> {
    let Some(s) = StavPripojeni::nacti(cesty)? else {
        println!("Počítač není v žádné doméně.");
        println!("Připojit ho můžeš příkazem:");
        println!("  ad-client join --server <adresa> --fingerprint <otisk> --admin administrator");
        return Ok(());
    };

    println!("Doména:          {} ({})", s.domain_dns_name, s.domain_short_name);
    println!("Řadič domény:    {} ({}:{})", s.dc_fqdn, s.server_host, s.server_port);
    println!("Jméno počítače:  {}", s.computer_name);
    println!("Připojeno:       {}", s.joined_at);
    println!("Otisk autority:  {}", s.ca_fingerprint);
    println!("Stav uložen v:   {}", cesty.data_dir.display());

    println!("\nDNS");
    let aktualni = dns::aktualni();
    println!(
        "  teď:           {}",
        if aktualni.is_empty() { "nenastaveno".to_string() } else { aktualni.join(", ") }
    );
    match dns::Zaloha::nacti(cesty)? {
        Some(z) => println!("  před připojením: {} (záloha z {})", z.popis(), z.zalohovano),
        None => println!("  před připojením: nezálohováno (DNS se neměnilo)"),
    }

    println!("\nSpojení se serverem");
    let klient = klient_ze_stavu(cesty, &s)?;
    match klient.poslat("GET", "/api/v1/hello", None, None).await {
        Ok(o) => match o.json::<ad_core::proto::HelloResponse>() {
            Ok(h) => println!("  ✓ {} {} odpovídá, otisk souhlasí", h.product, h.version),
            Err(e) => println!("  ! server odpověděl divně: {}", e.message),
        },
        Err(e) => println!("  ! {}", e.message),
    }

    println!("\nZásady");
    match UlozeneZasady::nacti(cesty)? {
        Some(z) => {
            println!("  verze:         {}", z.serial);
            println!("  staženo:       {}", z.fetched_at);
            println!("  použito:       {}", z.applied_at.unwrap_or_else(|| "nikdy".into()));
            vypis_zasady(&z.policy);
        }
        None => println!("  zatím nestaženy (ad-client policy)"),
    }
    Ok(())
}

fn vypis_zasady(z: &ad_core::policy::EffectivePolicy) {
    println!(
        "  heslo:         nejméně {} znaků, historie {}",
        z.password.min_length, z.password.history_length
    );
    println!(
        "  zamykání:      {}",
        if z.lockout.threshold == 0 {
            "vypnuté".to_string()
        } else {
            format!("{} chyb → {} min", z.lockout.threshold, z.lockout.duration_minutes)
        }
    );
    println!("  uvítací zpráva: {}", if z.welcome.enabled { "zapnutá" } else { "vypnutá" });
    println!("  tapeta:        {}", if z.wallpaper.enabled { "zapnutá" } else { "vypnutá" });
    if !z.applied.is_empty() {
        println!(
            "  použité zásady: {}",
            z.applied
                .iter()
                .map(|a| format!("{}{}", a.name, if a.enforced { " (vynucená)" } else { "" }))
                .collect::<Vec<_>>()
                .join(" → ")
        );
    }
}

// =======================================================================
// policy
// =======================================================================

async fn stahni_zasady(
    cesty: &Cesty,
    klient: &Klient,
    s: &StavPripojeni,
) -> Result<(UlozeneZasady, String)> {
    let token = ziskej_token(klient, s).await?;
    let odpoved = klient.poslat("GET", "/api/v1/machine/policy", None, Some(&token)).await?;
    let p: ad_core::proto::PolicyResponse = odpoved.json()?;
    zasady::zkontroluj(&p.policy)?;

    let ulozene = UlozeneZasady {
        policy: p.policy,
        serial: p.serial,
        fetched_at: stav::nyni_text(),
        applied_at: UlozeneZasady::nacti(cesty)?.and_then(|s| s.applied_at),
    };
    ulozene.uloz(cesty)?;
    Ok((ulozene, token))
}

async fn policy(cesty: &Cesty, p: &Prepinace) -> Result<()> {
    let s = StavPripojeni::vyzaduj(cesty)?;
    let klient = klient_ze_stavu(cesty, &s)?;
    let (mut ulozene, token) = stahni_zasady(cesty, &klient, &s).await?;

    println!("Zásady pro počítač {} (verze {})", s.computer_name, ulozene.serial);
    vypis_zasady(&ulozene.policy);

    if p.pouzij_zasady {
        println!("\nPoužívám:");
        let v = zasady::pouzij(cesty, &klient, &token, &ulozene.policy).await?;
        for r in &v.radky {
            println!("  ✓ {r}");
        }
        for r in &v.varovani {
            println!("  ! {r}");
        }
        ulozene.applied_at = Some(stav::nyni_text());
        ulozene.uloz(cesty)?;
    } else {
        println!("\n(zásady se jen stáhly; použít je můžeš přepínačem --apply)");
    }
    Ok(())
}

// =======================================================================
// logon
// =======================================================================

async fn logon(cesty: &Cesty, p: &Prepinace) -> Result<()> {
    let s = StavPripojeni::vyzaduj(cesty)?;
    let klient = klient_ze_stavu(cesty, &s)?;
    let token = ziskej_token(&klient, &s).await?;

    let uzivatel = match &p.user {
        Some(u) => u.clone(),
        None => {
            use std::io::Write;
            print!("Uživatel ({}\\): ", s.domain_short_name);
            std::io::stdout().flush().ok();
            let mut radek = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut radek)
                .map_err(|e| AdError::internal(format!("čtení jména: {e}")))?;
            radek.trim().to_string()
        }
    };
    if uzivatel.is_empty() {
        return Err(AdError::bad_request("jméno uživatele je prázdné"));
    }
    let heslo = nacti_heslo(p, "AD_USER_PASSWORD", &format!("Heslo uživatele {uzivatel}"))?;

    let telo = serde_json::json!({ "username": uzivatel, "password": heslo });
    let odpoved = klient.poslat("POST", "/api/v1/auth/logon", Some(&telo), Some(&token)).await?;
    let prihlaseni: ad_core::proto::LogonResponse = odpoved.json()?;

    println!("\nPřihlášen: {}", prihlaseni.user.display_name);
    println!("  účet:      {}", prihlaseni.user.upn);
    println!("  umístění:  {}", prihlaseni.user.ou_path);
    println!("  skupiny:   {}", prihlaseni.user.groups.join(", "));
    if let Some(dny) = prihlaseni.password_expires_in_days {
        println!("  heslo vyprší za {dny} dní");
    }

    zasady::zkontroluj(&prihlaseni.policy)?;
    if let Some(zprava) = zasady::uvitani(&prihlaseni.policy) {
        print!("{zprava}");
    }

    println!("\nZásady pro tohoto uživatele (verze {}):", prihlaseni.policy_serial);
    let v = zasady::pouzij(cesty, &klient, &token, &prihlaseni.policy).await?;
    for r in &v.radky {
        println!("  ✓ {r}");
    }
    for r in &v.varovani {
        println!("  ! {r}");
    }

    // Uložíme, co platí — ať to `status` umí ukázat i bez serveru.
    UlozeneZasady {
        policy: prihlaseni.policy.clone(),
        serial: prihlaseni.policy_serial,
        fetched_at: stav::nyni_text(),
        applied_at: Some(stav::nyni_text()),
    }
    .uloz(cesty)?;

    if prihlaseni.must_change_password {
        println!(
            "\n! Heslo je potřeba změnit. Udělej to příkazem:\n  \
             ad-client passwd --user {}",
            prihlaseni.user.sam_account_name
        );
    }

    // Ticket serveru vrátíme — už ho nepotřebujeme.
    let _ = klient
        .poslat(
            "POST",
            "/api/v1/auth/logoff",
            Some(&serde_json::json!({ "ticket": prihlaseni.ticket.odhal() })),
            Some(&token),
        )
        .await;
    Ok(())
}

// =======================================================================
// passwd
// =======================================================================

async fn passwd(cesty: &Cesty, p: &Prepinace) -> Result<()> {
    let s = StavPripojeni::vyzaduj(cesty)?;
    let klient = klient_ze_stavu(cesty, &s)?;
    let token = ziskej_token(&klient, &s).await?;

    let uzivatel = p
        .user
        .clone()
        .ok_or_else(|| AdError::bad_request("chybí --user (jméno doménového uživatele)"))?;

    let (stare, nove) = if p.heslo_ze_stdin {
        // Dva řádky: staré a nové heslo.
        let mut vstup = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut vstup)
            .map_err(|e| AdError::internal(format!("čtení hesel: {e}")))?;
        let mut radky = vstup.lines();
        let stare = radky.next().unwrap_or_default().to_string();
        let nove = radky.next().unwrap_or_default().to_string();
        if stare.is_empty() || nove.is_empty() {
            return Err(AdError::bad_request("na vstupu musí být dva řádky: staré a nové heslo"));
        }
        (stare, nove)
    } else {
        let stare = zeptej_se_na_heslo("Stávající heslo")?;
        let nove = zeptej_se_na_heslo("Nové heslo")?;
        let znovu = zeptej_se_na_heslo("Nové heslo znovu")?;
        if nove != znovu {
            return Err(AdError::bad_request("nová hesla se neshodují"));
        }
        (stare, nove)
    };

    let telo = serde_json::json!({
        "username": uzivatel,
        "old_password": stare,
        "new_password": nove,
    });
    let odpoved =
        klient.poslat("POST", "/api/v1/auth/change-password", Some(&telo), Some(&token)).await?;
    if !(200..300).contains(&odpoved.status) {
        let chyba = odpoved.chyba();
        // Když heslo neprošlo zásadou, vypíšeme která pravidla chybí.
        if let Some(detaily) = &chyba.details {
            if let Some(seznam) = detaily.get("complaints").and_then(|c| c.as_array()) {
                eprintln!("Nové heslo nesplňuje zásady domény:");
                for s in seznam {
                    eprintln!("  • {}", popis_pravidla(s));
                }
            }
        }
        return Err(chyba);
    }
    println!("Heslo změněno.");
    Ok(())
}

fn popis_pravidla(s: &serde_json::Value) -> String {
    let pravidlo = s.get("rule").and_then(|r| r.as_str()).unwrap_or("?");
    match pravidlo {
        "too_short" => {
            format!("nejméně {} znaků", s.get("min").and_then(|m| m.as_u64()).unwrap_or(0))
        }
        "too_long" => "heslo je příliš dlouhé".into(),
        "missing_uppercase" => "chybí velké písmeno".into(),
        "missing_lowercase" => "chybí malé písmeno".into(),
        "missing_digit" => "chybí číslice".into(),
        "missing_symbol" => "chybí symbol".into(),
        "contains_username" => "heslo obsahuje přihlašovací jméno".into(),
        "in_history" => format!(
            "shoduje se s posledními {} hesly",
            s.get("count").and_then(|m| m.as_u64()).unwrap_or(0)
        ),
        "control_character" => "heslo obsahuje řídicí znak".into(),
        "too_common" => "heslo je příliš běžné".into(),
        jine => jine.to_string(),
    }
}

// =======================================================================
// leave
// =======================================================================

async fn leave(cesty: &Cesty, p: &Prepinace) -> Result<()> {
    let s = StavPripojeni::vyzaduj(cesty)?;
    println!("Odpojuji počítač {} z domény {}", s.computer_name, s.domain_dns_name);

    // 1. Ohlásíme se serveru. Když to nejde, s --force pokračujeme.
    let mut server_vi = false;
    match klient_ze_stavu(cesty, &s) {
        Ok(klient) => match ziskej_token(&klient, &s).await {
            Ok(token) => {
                let telo = serde_json::json!({ "remove_dns": true });
                match klient.poslat("POST", "/api/v1/unjoin", Some(&telo), Some(&token)).await {
                    Ok(o) if (200..300).contains(&o.status) => {
                        server_vi = true;
                        println!("  ✓ počítačový účet na serveru smazán");
                    }
                    Ok(o) => eprintln!("  ! server odmítl odpojení: {}", o.chyba().message),
                    Err(e) => eprintln!("  ! server neodpověděl: {}", e.message),
                }
            }
            Err(e) => eprintln!("  ! nepodařilo se ověřit u serveru: {}", e.message),
        },
        Err(e) => eprintln!("  ! spojení se serverem nejde navázat: {}", e.message),
    }

    if !server_vi && !p.vynutit {
        return Err(AdError::conflict(
            "se serverem se nepodařilo spojit, takže počítačový účet na něm zůstane. \
             Místní stav jsem nechal, ať se dá odpojení zkusit znovu. \
             Když chceš uklidit jen tenhle počítač, přidej --force \
             (účet pak smaž ve správě serveru ručně).",
        ));
    }

    // 2. Vrátíme DNS.
    if p.bez_dns {
        println!("  • DNS neměním (--no-dns)");
    } else {
        match dns::Zaloha::nacti(cesty)? {
            Some(zaloha) => match dns::obnov(&zaloha) {
                Ok(()) => println!("  ✓ DNS vráceno do původního stavu: {}", zaloha.popis()),
                Err(e) => {
                    eprintln!("  ! DNS se nepodařilo vrátit: {}", e.message);
                    eprintln!("    Záloha zůstává v {}", cesty.dns_zaloha().display());
                    eprintln!("    Vrať ji ručně, pak soubor smaž.");
                }
            },
            None => println!("  • žádná záloha DNS, nic nevracím"),
        }
    }

    // 3. Uklidíme po sobě.
    let mut zbylo = Vec::new();
    for soubor in [cesty.stav(), cesty.ca(), cesty.zasady(), cesty.dns_zaloha()] {
        if soubor.exists() {
            if let Err(e) = std::fs::remove_file(&soubor) {
                zbylo.push(format!("{}: {e}", soubor.display()));
            }
        }
    }
    for pripona in ["png", "jpg"] {
        let t = cesty.tapeta().with_extension(pripona);
        if t.exists() {
            let _ = std::fs::remove_file(&t);
        }
    }
    if zbylo.is_empty() {
        println!("  ✓ místní soubory smazány");
    } else {
        for r in zbylo {
            eprintln!("  ! nepodařilo se smazat {r}");
        }
    }

    println!("\nHotovo. Počítač už v doméně není.");
    if !server_vi {
        println!("Pozor: server o odpojení neví. Smaž počítač ve správě ručně.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rozdeleni_adresy_serveru() {
        assert_eq!(
            rozdel_server("dc01.skola.internal").unwrap(),
            ("dc01.skola.internal".into(), 8443)
        );
        assert_eq!(rozdel_server("192.168.56.10:9443").unwrap(), ("192.168.56.10".into(), 9443));
        assert_eq!(rozdel_server(" dc01 ").unwrap(), ("dc01".into(), 8443));
        assert_eq!(rozdel_server("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert_eq!(rozdel_server("[fd00::1]").unwrap(), ("fd00::1".into(), 8443));
        assert!(rozdel_server("").is_err());
        assert!(rozdel_server("host:port").is_ok(), "nečíselný port bereme jako součást jména");
    }

    #[test]
    fn heslo_na_prikazove_radce_se_odmitne() {
        let e = Prepinace::zparsuj(&["--password".into(), "tajne".into()]).unwrap_err();
        assert!(e.message.contains("procesů"), "{}", e.message);
    }

    #[test]
    fn prepinace_se_zparsuji() {
        let p = Prepinace::zparsuj(&[
            "--server".into(),
            "dc01:8443".into(),
            "--fingerprint".into(),
            "AB".into(),
            "--admin".into(),
            "administrator".into(),
            "--no-dns".into(),
            "--apply".into(),
        ])
        .unwrap();
        assert_eq!(p.server.as_deref(), Some("dc01:8443"));
        assert_eq!(p.admin.as_deref(), Some("administrator"));
        assert!(p.bez_dns);
        assert!(p.pouzij_zasady);
        assert!(!p.vynutit);
    }

    #[test]
    fn chybejici_hodnota_prepinace() {
        assert!(Prepinace::zparsuj(&["--server".into()]).is_err());
        assert!(Prepinace::zparsuj(&["--nesmysl".into()]).is_err());
    }

    #[test]
    fn jmeno_stroje_je_platne() {
        let j = jmeno_stroje();
        assert!(ad_core::names::validuj_jmeno_pocitace(&j).is_ok(), "neplatné jméno: {j}");
    }

    #[test]
    fn popis_pravidel_hesla() {
        let v = serde_json::json!({ "rule": "too_short", "min": 12 });
        assert_eq!(popis_pravidla(&v), "nejméně 12 znaků");
        let v = serde_json::json!({ "rule": "missing_digit" });
        assert_eq!(popis_pravidla(&v), "chybí číslice");
    }
}
