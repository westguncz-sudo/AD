//! Protokol mezi klientem, webovým rozhraním a serverem.
//!
//! Všechno je JSON přes HTTPS. Žádné vlastní binární formáty — snadno se
//! to ladí (curl, DevTools) a je to bezpečnější, než si psát vlastní
//! parser.
//!
//! # Dvě oddělená rozhraní
//! * **doménové API** (`/api/v1/...`) na TLS portu — mluví s ním `ad-client`.
//!   Umí jen to, co klient potřebuje: připojit se, přihlásit uživatele,
//!   stáhnout zásady.
//! * **správní API** (`/admin/api/v1/...`) jen na `127.0.0.1` — mluví
//!   s ním vestavěné webové rozhraní. Tady je správa domény.
//!
//! Oddělení je záměrné: i kdyby v administraci byla chyba, z sítě na ni
//! nikdo nedosáhne. Na vzdálený přístup se používá SSH tunel.

use crate::error::AdError;
use crate::ids::Guid;
use crate::model::*;
use crate::policy::{EffectivePolicy, PolicySet};
use crate::secret::Tajne;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Konstanty protokolu
// ---------------------------------------------------------------------------

/// Verze protokolu, kterou mluvíme. Server i klient si ji vyměňují
/// a při nesouladu se odmítnou spojit.
pub const PROTO_VERZE: u32 = 1;
/// Nejstarší verze, kterou server ještě zvládne.
pub const PROTO_VERZE_MIN: u32 = 1;

/// Jméno produktu v hlavičce `Server` a v odpovědi `/hello`.
pub const PRODUKT: &str = "ad-server";

/// Hlavička s verzí protokolu.
pub const HLAVICKA_PROTO: &str = "x-ad-proto";
/// Hlavička s CSRF tokenem (správní API).
pub const HLAVICKA_CSRF: &str = "x-ad-csrf";
/// Hlavička s verzí klienta (jen pro přehled v UI).
pub const HLAVICKA_KLIENT: &str = "x-ad-client";

/// Jméno cookie se session správce.
pub const COOKIE_SESSION: &str = "ad_admin_session";

/// Předpona doménového API.
pub const API: &str = "/api/v1";
/// Předpona správního API.
pub const ADMIN_API: &str = "/admin/api/v1";

/// Výchozí port doménového API (TLS).
pub const PORT_TLS: u16 = 8443;
/// Výchozí port webové správy (jen loopback).
pub const PORT_SPRAVA: u16 = 8080;
/// Výchozí port DNS.
pub const PORT_DNS: u16 = 53;

/// Jak dlouho platí token počítačového účtu (minuty).
pub const PLATNOST_TOKENU_MIN: i64 = 15;
/// Jak dlouho platí session správce bez aktivity (minuty).
pub const PLATNOST_SESSION_MIN: i64 = 60;
/// Jak dlouho platí „ticket“ přihlášeného uživatele v klientovi (minuty).
pub const PLATNOST_TICKETU_MIN: i64 = 480;
/// Jak často si klient stahuje zásady (sekundy).
pub const INTERVAL_ZASAD_S: u64 = 900;

// ---------------------------------------------------------------------------
// Společné
// ---------------------------------------------------------------------------

/// Stránkovaný seznam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Celkový počet záznamů bez stránkování.
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}

/// Jak hluboko se má hledat ve stromu OU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Jen přímo v dané OU.
    #[default]
    Level,
    /// Včetně všech podřízených OU.
    Subtree,
}

/// Parametry dotazu na seznam (query string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    /// Hledaný text (podřetězec ve jméně nebo popisu).
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub ou_id: Option<i64>,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

impl ListQuery {
    /// Největší povolená stránka. Víc server pošle, jen když se chce
    /// někdo pokusit o DoS — proto to zastropujeme.
    pub const MAX_LIMIT: u64 = 500;

    pub fn offset(&self) -> u64 {
        self.offset.unwrap_or(0)
    }

    pub fn limit(&self) -> u64 {
        self.limit.unwrap_or(50).clamp(1, Self::MAX_LIMIT)
    }
}

/// Prázdná odpověď „povedlo se“.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ok2 {
    pub ok: bool,
}

impl Default for Ok2 {
    fn default() -> Self {
        Self { ok: true }
    }
}

// ---------------------------------------------------------------------------
// Doménové API: /api/v1
// ---------------------------------------------------------------------------

/// Veřejné údaje o doméně — co smí vědět i nepřihlášený klient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainPublic {
    pub dns_name: String,
    pub short_name: String,
    pub dc_fqdn: String,
}

/// `GET /api/v1/hello` — bez přihlášení.
///
/// Klient si tím ověří, že mluví s naším serverem a jaká doména to je.
/// Záměrně neprozrazuje počty objektů ani jména uživatelů.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResponse {
    pub product: String,
    /// Verze `ad-server`, např. `0.1.0`.
    pub version: String,
    pub proto_min: u32,
    pub proto_max: u32,
    pub stage: ServerStage,
    /// `None`, dokud server není řadičem domény.
    pub domain: Option<DomainPublic>,
    /// Otisk certifikační autority, kterou si klient připne.
    pub ca_fingerprint_sha256: String,
    #[serde(with = "crate::model::cas::povinny")]
    pub server_time: OffsetDateTime,
}

/// `POST /api/v1/join` — připojení počítače do domény.
///
/// Autentizace: jméno a heslo správce domény. Posílá se **jednou**,
/// server si ho neukládá a vrátí tajemství počítačového účtu.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    /// Jméno počítače, které se zapíše do domény a do DNS.
    pub computer_name: String,
    /// Správce domény (`administrator` nebo `SKOLA\administrator`).
    pub admin_username: String,
    pub admin_password: Tajne,
    /// Do které OU počítač zařadit. `None` = výchozí OU `Computers`.
    #[serde(default)]
    pub ou_path: Option<String>,
    /// Co o sobě klient tvrdí. Server to jen uloží k zobrazení.
    pub os_name: String,
    pub os_version: String,
    pub client_version: String,
    /// IPv4 adresa klienta pro záznamy A a PTR. Server ji porovná
    /// s adresou, ze které spojení skutečně přišlo.
    #[serde(default)]
    pub ip_address: Option<String>,
}

/// Co klient dostane po úspěšném připojení.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub machine_id: Guid,
    /// Tajemství počítačového účtu. Uloží se do souboru jen pro správce
    /// (0600 / ACL jen SYSTEM+Administrators) a už se nikdy neposílá.
    pub machine_secret: Tajne,
    pub computer: Computer,
    pub domain: DomainPublic,
    /// Které DNS adresy si má klient nastavit.
    pub dns_servers: Vec<String>,
    /// Certifikát naší autority v PEM — klient si ho uloží a dál ověřuje
    /// jen proti němu.
    pub ca_cert_pem: String,
    pub ca_fingerprint_sha256: String,
    /// Jak často se má ptát na zásady.
    pub policy_poll_seconds: u64,
}

/// `POST /api/v1/machine/token` — výměna tajemství za krátkodobý token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineTokenRequest {
    pub machine_id: Guid,
    pub machine_secret: Tajne,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineTokenResponse {
    /// Posílá se dál v hlavičce `Authorization: Bearer <token>`.
    pub token: Tajne,
    #[serde(with = "crate::model::cas::povinny")]
    pub expires_at: OffsetDateTime,
    pub policy_poll_seconds: u64,
}

/// `POST /api/v1/unjoin` — odpojení z domény. Autentizace tokenem
/// počítače; volitelně navíc heslem správce (když chce správce odpojit
/// počítač, jehož tajemství se ztratilo).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnjoinRequest {
    /// Smazat i DNS záznamy počítače.
    #[serde(default = "pravda")]
    pub remove_dns: bool,
    #[serde(default)]
    pub admin_username: Option<String>,
    #[serde(default)]
    pub admin_password: Option<Tajne>,
}

fn pravda() -> bool {
    true
}

/// `GET /api/v1/machine/policy` — zásady pro počítač.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub policy: EffectivePolicy,
    /// Zvyšuje se při každé změně zásad. Klient může posílat
    /// `If-None-Match` a šetřit tím přenos.
    pub serial: u64,
    #[serde(with = "crate::model::cas::povinny")]
    pub generated_at: OffsetDateTime,
    pub policy_poll_seconds: u64,
}

/// `POST /api/v1/auth/logon` — přihlášení doménového uživatele
/// **v programu** (ne do systému).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogonRequest {
    /// `jan.novak`, `jan.novak@skola.internal` nebo `SKOLA\jan.novak`.
    pub username: String,
    pub password: Tajne,
}

/// Údaje o přihlášeném uživateli, které klient zobrazí.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPublic {
    pub sam_account_name: String,
    pub upn: String,
    pub display_name: String,
    pub sid: crate::ids::Sid,
    /// Jména skupin, ve kterých uživatel je (včetně vnořených).
    pub groups: Vec<String>,
    /// Cesta k OU, kde účet je — kvůli zobrazení.
    pub ou_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonResponse {
    pub user: UserPublic,
    /// Ticket pro další dotazy za tohoto uživatele.
    pub ticket: Tajne,
    #[serde(with = "crate::model::cas::povinny")]
    pub ticket_expires_at: OffsetDateTime,
    /// Zásady platné pro tohoto uživatele (ne pro počítač).
    pub policy: EffectivePolicy,
    pub policy_serial: u64,
    /// Musí si hned změnit heslo (vynucené správcem nebo vypršelé).
    pub must_change_password: bool,
    /// Za kolik dní heslo vyprší. `None` = nikdy.
    pub password_expires_in_days: Option<u16>,
}

/// `POST /api/v1/auth/change-password`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    pub username: String,
    pub old_password: Tajne,
    pub new_password: Tajne,
}

/// `POST /api/v1/heartbeat` — klient se ohlásí, že žije.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub os_name: String,
    pub os_version: String,
    pub client_version: String,
    /// Sériové číslo zásad, které klient právě má.
    #[serde(default)]
    pub policy_serial: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// `true` = klient si má znovu stáhnout zásady.
    pub policy_changed: bool,
    pub policy_serial: u64,
    #[serde(with = "crate::model::cas::povinny")]
    pub server_time: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// Správní API: /admin/api/v1
// ---------------------------------------------------------------------------

/// Čím se správce přihlašuje do webového rozhraní.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminLoginRequest {
    /// Doménový účet ve skupině `Domain Admins`.
    Password { username: String, password: Tajne },
    /// Jednorázový token vypsaný do konzole při prvním spuštění.
    /// Platí jen dokud doména neexistuje.
    SetupToken { token: Tajne },
}

/// Kdo je přihlášený.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminPrincipal {
    /// Správce podle jednorázového tokenu (jen před vytvořením domény).
    Setup,
    /// Doménový správce.
    User { sam_account_name: String, display_name: String, sid: crate::ids::Sid },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSessionResponse {
    pub principal: AdminPrincipal,
    /// Token, který musí být v hlavičce `x-ad-csrf` u každé měnící akce.
    pub csrf_token: String,
    #[serde(with = "crate::model::cas::povinny")]
    pub expires_at: OffsetDateTime,
}

/// Kolik čeho v doméně je — pro dlaždice na přehledu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Counts {
    pub users: u64,
    pub groups: u64,
    pub ous: u64,
    pub computers: u64,
    pub gpos: u64,
    pub zones: u64,
    /// Počítače, které se ohlásily v posledních 24 hodinách.
    pub computers_online: u64,
    /// Zamčené účty.
    pub locked_users: u64,
}

/// Na čem server poslouchá — pro přehled a pro nápovědu k SSH tunelu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    /// `admin`, `domain-api`, `dns-udp`, `dns-tcp`
    pub name: String,
    pub address: String,
    pub tls: bool,
    pub running: bool,
}

/// `GET /admin/api/v1/status` — všechno pro Dashboard na jeden dotaz.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub product: String,
    pub version: String,
    pub stage: ServerStage,
    pub roles: InstalledRoles,
    pub domain: Option<Domain>,
    pub counts: Counts,
    pub alerts: Vec<Alert>,
    pub listeners: Vec<Listener>,
    pub ca_fingerprint_sha256: Option<String>,
    pub uptime_seconds: u64,
    pub hostname: String,
    pub os: String,
    #[serde(with = "crate::model::cas::povinny")]
    pub server_time: OffsetDateTime,
}

/// `POST /admin/api/v1/roles` — průvodce „Přidat role a funkce“.
///
/// `consent` musí být `true`. Nic se neinstaluje bez výslovného souhlasu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRolesRequest {
    pub directory: bool,
    pub dns: bool,
    pub consent: bool,
}

/// Jak vyšla jedna kontrola předpokladů.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckItem {
    /// Stabilní kód kontroly, např. `dns_port_free`.
    pub code: String,
    pub title: String,
    pub status: CheckStatus,
    pub detail: String,
    /// Co s tím dělat, když to neprošlo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

/// Nastavení DNS při povýšení.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteDnsOptions {
    /// Vytvořit i reverzní zónu.
    pub create_reverse: bool,
    /// Maska pro reverzní zónu (8, 16 nebo 24).
    pub reverse_prefix: u8,
    /// Kam přeposílat dotazy, na které neumíme odpovědět.
    /// Prázdný seznam = server si vezme ty, co měl systém předtím.
    pub forwarders: Vec<String>,
    /// Poslouchat na portu 53.
    pub enable_server: bool,
}

impl Default for PromoteDnsOptions {
    fn default() -> Self {
        Self {
            create_reverse: true,
            reverse_prefix: 24,
            forwarders: Vec::new(),
            enable_server: true,
        }
    }
}

/// `POST /admin/api/v1/promote/precheck` a `POST /admin/api/v1/promote`
/// berou stejné údaje — kontrola běží nad tím, co se opravdu chystáš udělat.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromoteRequest {
    /// `skola.internal`
    pub domain_dns_name: String,
    /// `None` = odvodí se z prvního labelu.
    #[serde(default)]
    pub short_name: Option<String>,
    /// Jméno řadiče bez domény, např. `DC01`.
    pub dc_hostname: String,
    /// IPv4, na které bude řadič dostupný.
    pub dc_ip: String,
    /// Heslo vestavěného účtu `administrator`.
    pub administrator_password: Tajne,
    pub dns: PromoteDnsOptions,
    /// Musí být `true` — potvrzení, že se opravdu má doména vytvořit.
    pub confirm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecheckResponse {
    pub items: Vec<CheckItem>,
    /// `false`, pokud některá kontrola skončila `Fail`.
    pub can_continue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteResponse {
    pub domain: Domain,
    pub ca_fingerprint_sha256: String,
    /// Zóny, které se vytvořily.
    pub zones: Vec<String>,
    /// Jak dál — zobrazí se na poslední stránce průvodce.
    pub next_steps: Vec<String>,
    /// Kam se mají klienti připojovat.
    pub client_endpoint: String,
}

/// `POST /admin/api/v1/demote` — zrušení domény (uklidí i DNS zóny).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoteRequest {
    /// Opsat jméno domény — pojistka proti překliku.
    pub confirm_domain_name: String,
    /// Smazat i databázi, ne jen doménu.
    #[serde(default)]
    pub wipe_database: bool,
}

// --- uživatelé ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    pub sam_account_name: String,
    #[serde(default)]
    pub given_name: String,
    #[serde(default)]
    pub surname: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub ou_id: Option<i64>,
    pub password: Tajne,
    #[serde(default = "pravda")]
    pub must_change_password: bool,
    #[serde(default = "pravda")]
    pub enabled: bool,
    #[serde(default)]
    pub password_never_expires: bool,
    /// Do kterých skupin rovnou zařadit (jména nebo id).
    #[serde(default)]
    pub groups: Vec<i64>,
}

/// Úprava uživatele. `None` = neměnit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub surname: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub must_change_password: Option<bool>,
    #[serde(default)]
    pub password_never_expires: Option<bool>,
    /// Chybějící pole = neměnit, `null` = přesunout přímo pod doménu.
    #[serde(default, deserialize_with = "dvojity_option")]
    pub ou_id: Option<Option<i64>>,
}

/// Rozliší „pole chybí“ (`None`) od „pole je null“ (`Some(None)`).
/// Samotné `#[serde(default)]` to neumí — obojí by dalo `None`.
fn dvojity_option<'de, D, T>(d: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Nastavení hesla správcem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPasswordRequest {
    pub new_password: Tajne,
    #[serde(default = "pravda")]
    pub must_change_password: bool,
    /// Obejít kontrolu historie (např. při obnově zapomenutého hesla).
    /// Zásadu složitosti to neobchází.
    #[serde(default)]
    pub skip_history_check: bool,
}

/// Odemčení zamčeného účtu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UnlockRequest {}

// --- skupiny ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub sam_account_name: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: GroupKind,
    #[serde(default)]
    pub ou_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembersRequest {
    /// Koho přidat nebo odebrat.
    pub members: Vec<MemberRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRef {
    pub kind: MemberKind,
    pub id: i64,
}

// --- OU ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOuRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<i64>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub protected: bool,
}

/// Přesun objektu do jiné OU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveRequest {
    /// `None` = přímo pod doménu.
    pub target_ou_id: Option<i64>,
}

/// Přejmenování objektu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    pub new_name: String,
}

/// Uzel stromu pro levý panel „Uživatelé a počítače“.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeNode {
    /// `None` u korene (domény).
    pub ou_id: Option<i64>,
    pub name: String,
    pub path: String,
    pub protected: bool,
    /// Kolik objektů je přímo v tomto uzlu.
    pub object_count: u64,
    pub children: Vec<TreeNode>,
}

// --- počítače ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateComputerRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub ou_id: Option<i64>,
}

/// Výsledek předběžného vytvoření počítače správcem — tajemství se
/// zobrazí jen jednou.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateComputerResponse {
    pub computer: Computer,
    pub machine_id: Guid,
    pub machine_secret: Tajne,
}

// --- zásady ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGpoRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub settings: PolicySet,
    #[serde(default = "pravda")]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateGpoRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub settings: Option<PolicySet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkGpoRequest {
    pub target: GpoTarget,
    #[serde(default)]
    pub enforced: bool,
    #[serde(default = "pravda")]
    pub enabled: bool,
}

/// `GET /admin/api/v1/gpos/effective?ou_id=..` — výsledná sada zásad,
/// abys v UI viděl, co na danou OU opravdu platí.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectivePolicyResponse {
    pub policy: EffectivePolicy,
    pub serial: u64,
}

/// Odpověď po nahrání tapety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadAssetResponse {
    pub asset_id: Guid,
    pub sha256: String,
    pub size: u64,
    pub format: crate::policy::ImageFormat,
    pub width: u32,
    pub height: u32,
}

// --- DNS ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateZoneRequest {
    /// Dopředná: `skola.internal`. Reverzní: zadej síť v `network`.
    #[serde(default)]
    pub name: Option<String>,
    pub kind: crate::dns::ZoneKind,
    /// Pro reverzní zónu, např. `192.168.56.0/24`.
    #[serde(default)]
    pub network: Option<String>,
}

/// Pozor: tahle struktura **nemá** `deny_unknown_fields`, protože to serde
/// neumí zkombinovat s `flatten`. Typ a data záznamu se proto validují
/// zvlášť přes `RecordData::validuj()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRecordRequest {
    /// Relativní jméno nebo `@`.
    pub name: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(flatten)]
    pub data: crate::dns::RecordData,
}

/// Nastavení přeposílání dotazů.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardersRequest {
    pub forwarders: Vec<String>,
}

/// Stav DNS serveru pro Správce DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsStatusResponse {
    pub running: bool,
    pub listen: Vec<String>,
    pub forwarders: Vec<String>,
    /// Adresy, které měl systém nastavené před námi — kam se vrátíme.
    pub original_forwarders: Vec<String>,
    pub queries_total: u64,
    pub queries_forwarded: u64,
    pub queries_refused: u64,
    pub cache_entries: u64,
}

// --- audit ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EventsQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub only_failures: Option<bool>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

// ---------------------------------------------------------------------------
// Pomocné
// ---------------------------------------------------------------------------

/// Zkontroluje, že verze protokolu klienta je pro nás přijatelná.
pub fn zkontroluj_verzi(klient: u32) -> Result<(), AdError> {
    if (PROTO_VERZE_MIN..=PROTO_VERZE).contains(&klient) {
        Ok(())
    } else {
        Err(AdError::new(
            crate::error::ErrorCode::ProtoVersionUnsupported,
            format!(
                "klient mluví protokol {klient}, server umí {PROTO_VERZE_MIN} až {PROTO_VERZE}"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verze_protokolu() {
        zkontroluj_verzi(1).unwrap();
        assert!(zkontroluj_verzi(0).is_err());
        assert!(zkontroluj_verzi(2).is_err());
    }

    #[test]
    fn limit_stranky_se_zastropuje() {
        let q = ListQuery { limit: Some(100_000), ..Default::default() };
        assert_eq!(q.limit(), ListQuery::MAX_LIMIT);
        assert_eq!(ListQuery::default().limit(), 50);
        assert_eq!(ListQuery { limit: Some(0), ..Default::default() }.limit(), 1);
    }

    #[test]
    fn neznama_polozka_v_pozadavku_se_odmitne() {
        // Překlep ve jménu pole se musí poznat, ne tiše ignorovat.
        let j = r#"{"computer_name":"PC-01","admin_username":"administrator",
            "admin_password":"x","os_name":"Linux","os_version":"12",
            "client_version":"0.1.0","nebezpecne_pole":1}"#;
        assert!(serde_json::from_str::<JoinRequest>(j).is_err());
    }

    #[test]
    fn join_pozadavek_se_parsuje() {
        let j = r#"{"computer_name":"PC-01","admin_username":"SKOLA\\administrator",
            "admin_password":"Tajne1!","os_name":"Debian","os_version":"13",
            "client_version":"0.1.0"}"#;
        let r: JoinRequest = serde_json::from_str(j).unwrap();
        assert_eq!(r.computer_name, "PC-01");
        assert_eq!(r.admin_password.odhal(), "Tajne1!");
        assert!(r.ou_path.is_none());
        // A hlavně: v Debug výpisu heslo není.
        assert!(!format!("{r:?}").contains("Tajne1!"));
    }

    #[test]
    fn prihlaseni_spravce_je_tagovane() {
        let j = r#"{"method":"setup_token","token":"abc"}"#;
        let r: AdminLoginRequest = serde_json::from_str(j).unwrap();
        match r {
            AdminLoginRequest::SetupToken { token } => assert_eq!(token.odhal(), "abc"),
            _ => panic!("špatná varianta"),
        }
        let j2 = r#"{"method":"password","username":"administrator","password":"x"}"#;
        assert!(matches!(
            serde_json::from_str::<AdminLoginRequest>(j2).unwrap(),
            AdminLoginRequest::Password { .. }
        ));
    }

    #[test]
    fn zaznam_dns_se_sklada_plocho() {
        let j = r#"{"name":"dc01","type":"A","address":"192.168.56.10"}"#;
        let r: CreateRecordRequest = serde_json::from_str(j).unwrap();
        assert_eq!(r.name, "dc01");
        assert!(matches!(r.data, crate::dns::RecordData::A { .. }));
    }

    #[test]
    fn uprava_uzivatele_umi_vynulovat_ou() {
        // Option<Option<i64>>: chybějící pole = neměnit, null = přesunout
        // pod doménu.
        let nic: UpdateUserRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(nic.ou_id, None);
        let na_koren: UpdateUserRequest = serde_json::from_str(r#"{"ou_id":null}"#).unwrap();
        assert_eq!(na_koren.ou_id, Some(None));
        let do_ou: UpdateUserRequest = serde_json::from_str(r#"{"ou_id":5}"#).unwrap();
        assert_eq!(do_ou.ou_id, Some(Some(5)));
    }

    #[test]
    fn souhlas_s_instalaci_je_povinny_ve_schematu() {
        let j = r#"{"directory":true,"dns":true}"#;
        assert!(
            serde_json::from_str::<InstallRolesRequest>(j).is_err(),
            "souhlas se nesmí dát vynechat"
        );
        let j2 = r#"{"directory":true,"dns":true,"consent":true}"#;
        assert!(serde_json::from_str::<InstallRolesRequest>(j2).unwrap().consent);
    }
}
