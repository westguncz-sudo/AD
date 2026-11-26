//! Schéma databáze. Migrace jsou číslované a spouští se podle
//! `PRAGMA user_version` — stejná databáze se tak dá otevřít i novější
//! verzí serveru.
//!
//! Časy jsou TEXT v RFC 3339 (UTC). SQLite nemá typ pro datum a čas;
//! text je čitelný v `sqlite3` a dá se řadit jako string.

/// Verze schématu, kterou tento server umí.
pub const VERZE_SCHEMATU: i64 = 1;

/// Migrace 1 — celé schéma. Tabulky pro DNS a zásady zakládáme už teď,
/// i když se plně využijí až ve fázích 4 a 5: měnit schéma později je
/// dražší než ho mít od začátku celé.
pub const MIGRACE_1: &str = r#"
CREATE TABLE domain (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    dns_name                TEXT    NOT NULL,
    short_name              TEXT    NOT NULL,
    sid_a                   INTEGER NOT NULL,
    sid_b                   INTEGER NOT NULL,
    sid_c                   INTEGER NOT NULL,
    dc_hostname             TEXT    NOT NULL,
    dc_fqdn                 TEXT    NOT NULL,
    dc_ip                   TEXT    NOT NULL,
    next_rid                INTEGER NOT NULL DEFAULT 10000,
    created_at              TEXT    NOT NULL
);

CREATE TABLE ou (
    id                      INTEGER PRIMARY KEY,
    guid                    TEXT    NOT NULL UNIQUE,
    name                    TEXT    NOT NULL,
    parent_id               INTEGER          REFERENCES ou(id),
    path                    TEXT    NOT NULL UNIQUE,
    description             TEXT    NOT NULL DEFAULT '',
    protected               INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL,
    UNIQUE (parent_id, name)
);

CREATE TABLE users (
    id                      INTEGER PRIMARY KEY,
    guid                    TEXT    NOT NULL UNIQUE,
    rid                     INTEGER NOT NULL UNIQUE,
    sam                     TEXT    NOT NULL UNIQUE,
    password_hash           TEXT    NOT NULL,
    display_name            TEXT    NOT NULL DEFAULT '',
    given_name              TEXT    NOT NULL DEFAULT '',
    surname                 TEXT    NOT NULL DEFAULT '',
    email                   TEXT    NOT NULL DEFAULT '',
    description             TEXT    NOT NULL DEFAULT '',
    ou_id                   INTEGER          REFERENCES ou(id),
    enabled                 INTEGER NOT NULL DEFAULT 1,
    must_change_password    INTEGER NOT NULL DEFAULT 0,
    password_never_expires  INTEGER NOT NULL DEFAULT 0,
    password_set_at         TEXT,
    last_logon_at           TEXT,
    locked_until            TEXT,
    failed_logons           INTEGER NOT NULL DEFAULT 0,
    first_failed_at         TEXT,
    builtin                 INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL
);
CREATE INDEX idx_users_ou ON users(ou_id);

CREATE TABLE password_history (
    id                      INTEGER PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash           TEXT    NOT NULL,
    set_at                  TEXT    NOT NULL
);
CREATE INDEX idx_pwhist_user ON password_history(user_id, set_at DESC);

CREATE TABLE groups (
    id                      INTEGER PRIMARY KEY,
    guid                    TEXT    NOT NULL UNIQUE,
    rid                     INTEGER NOT NULL UNIQUE,
    sam                     TEXT    NOT NULL UNIQUE,
    name                    TEXT    NOT NULL,
    description             TEXT    NOT NULL DEFAULT '',
    kind                    TEXT    NOT NULL DEFAULT 'security'
                                    CHECK (kind IN ('security','distribution')),
    ou_id                   INTEGER          REFERENCES ou(id),
    builtin                 INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL
);

CREATE TABLE group_members (
    group_id                INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    member_kind             TEXT    NOT NULL CHECK (member_kind IN ('user','group','computer')),
    member_id               INTEGER NOT NULL,
    added_at                TEXT    NOT NULL,
    PRIMARY KEY (group_id, member_kind, member_id)
);
CREATE INDEX idx_members_member ON group_members(member_kind, member_id);

CREATE TABLE computers (
    id                      INTEGER PRIMARY KEY,
    guid                    TEXT    NOT NULL UNIQUE,
    rid                     INTEGER NOT NULL UNIQUE,
    name                    TEXT    NOT NULL UNIQUE,
    dns_name                TEXT    NOT NULL,
    secret_hash             TEXT    NOT NULL,
    description             TEXT    NOT NULL DEFAULT '',
    ou_id                   INTEGER          REFERENCES ou(id),
    enabled                 INTEGER NOT NULL DEFAULT 1,
    os_name                 TEXT    NOT NULL DEFAULT '',
    os_version              TEXT    NOT NULL DEFAULT '',
    last_ip                 TEXT    NOT NULL DEFAULT '',
    joined_at               TEXT    NOT NULL,
    last_seen_at            TEXT
);

CREATE TABLE gpos (
    id                      INTEGER PRIMARY KEY,
    guid                    TEXT    NOT NULL UNIQUE,
    name                    TEXT    NOT NULL UNIQUE,
    description             TEXT    NOT NULL DEFAULT '',
    enabled                 INTEGER NOT NULL DEFAULT 1,
    settings_json           TEXT    NOT NULL DEFAULT '{}',
    created_at              TEXT    NOT NULL,
    modified_at             TEXT    NOT NULL
);

CREATE TABLE gpo_links (
    id                      INTEGER PRIMARY KEY,
    gpo_id                  INTEGER NOT NULL REFERENCES gpos(id) ON DELETE CASCADE,
    scope                   TEXT    NOT NULL CHECK (scope IN ('domain','ou')),
    ou_id                   INTEGER          REFERENCES ou(id) ON DELETE CASCADE,
    ord                     INTEGER NOT NULL DEFAULT 1,
    enforced                INTEGER NOT NULL DEFAULT 0,
    enabled                 INTEGER NOT NULL DEFAULT 1,
    CHECK ((scope = 'domain' AND ou_id IS NULL) OR (scope = 'ou' AND ou_id IS NOT NULL))
);
CREATE UNIQUE INDEX idx_links_unikat ON gpo_links(gpo_id, scope, IFNULL(ou_id, -1));

CREATE TABLE assets (
    id                      TEXT    PRIMARY KEY,
    sha256                  TEXT    NOT NULL,
    size                    INTEGER NOT NULL,
    format                  TEXT    NOT NULL,
    width                   INTEGER NOT NULL DEFAULT 0,
    height                  INTEGER NOT NULL DEFAULT 0,
    original_name           TEXT    NOT NULL DEFAULT '',
    created_at              TEXT    NOT NULL
);

CREATE TABLE dns_zones (
    id                      INTEGER PRIMARY KEY,
    name                    TEXT    NOT NULL UNIQUE,
    kind                    TEXT    NOT NULL CHECK (kind IN ('forward','reverse')),
    serial                  INTEGER NOT NULL DEFAULT 1,
    primary_ns              TEXT    NOT NULL,
    rname                   TEXT    NOT NULL,
    refresh                 INTEGER NOT NULL DEFAULT 3600,
    retry                   INTEGER NOT NULL DEFAULT 600,
    expire                  INTEGER NOT NULL DEFAULT 604800,
    minimum                 INTEGER NOT NULL DEFAULT 3600,
    managed                 INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL
);

CREATE TABLE dns_records (
    id                      INTEGER PRIMARY KEY,
    zone_id                 INTEGER NOT NULL REFERENCES dns_zones(id) ON DELETE CASCADE,
    name                    TEXT    NOT NULL,
    rtype                   TEXT    NOT NULL,
    ttl                     INTEGER NOT NULL DEFAULT 3600,
    rdata_json              TEXT    NOT NULL,
    managed                 INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT    NOT NULL,
    UNIQUE (zone_id, name, rtype, rdata_json)
);
CREATE INDEX idx_records_hledani ON dns_records(zone_id, name, rtype);

-- Session správce ve webovém rozhraní. Token je uložený jen jako SHA-256.
CREATE TABLE admin_sessions (
    token_hash              TEXT    PRIMARY KEY,
    principal_json          TEXT    NOT NULL,
    csrf_token              TEXT    NOT NULL,
    created_at              TEXT    NOT NULL,
    expires_at              TEXT    NOT NULL,
    created_ip              TEXT    NOT NULL DEFAULT ''
);

-- Krátkodobé tokeny počítačových účtů.
CREATE TABLE machine_tokens (
    token_hash              TEXT    PRIMARY KEY,
    computer_id             INTEGER NOT NULL REFERENCES computers(id) ON DELETE CASCADE,
    created_at              TEXT    NOT NULL,
    expires_at              TEXT    NOT NULL
);

-- Tickety přihlášených uživatelů (přihlášení v programu, ne do systému).
CREATE TABLE user_tickets (
    token_hash              TEXT    PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    computer_id             INTEGER          REFERENCES computers(id) ON DELETE CASCADE,
    created_at              TEXT    NOT NULL,
    expires_at              TEXT    NOT NULL
);

-- Neúspěšné pokusy o přihlášení podle IP — omezení rychlosti.
CREATE TABLE login_attempts (
    id                      INTEGER PRIMARY KEY,
    ip                      TEXT    NOT NULL,
    at                      TEXT    NOT NULL
);
CREATE INDEX idx_attempts ON login_attempts(ip, at);

-- Auditní log. Nikdy neobsahuje hesla ani tokeny.
CREATE TABLE events (
    id                      INTEGER PRIMARY KEY,
    at                      TEXT    NOT NULL,
    action                  TEXT    NOT NULL,
    actor                   TEXT    NOT NULL,
    target                  TEXT    NOT NULL DEFAULT '',
    source_ip               TEXT    NOT NULL DEFAULT '',
    success                 INTEGER NOT NULL DEFAULT 1,
    detail                  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_events_cas ON events(at DESC);

CREATE TABLE settings (
    key                     TEXT    PRIMARY KEY,
    value                   TEXT    NOT NULL
);
"#;

/// Klíče v tabulce `settings`.
pub mod nastaveni {
    /// SHA-256 jednorázového tokenu pro první přihlášení.
    pub const SETUP_TOKEN_HASH: &str = "setup_token_hash";
    /// Role doménových služeb nainstalovaná (`1` / `0`).
    pub const ROLE_DIRECTORY: &str = "role_directory";
    /// Role DNS nainstalovaná.
    pub const ROLE_DNS: &str = "role_dns";
    /// Otisk CA (pro zobrazení ve správě a v `/hello`).
    pub const CA_FINGERPRINT: &str = "ca_fingerprint";
    /// Sériové číslo zásad — zvyšuje se při každé změně GPO.
    pub const POLICY_SERIAL: &str = "policy_serial";
    /// Adresy, kam DNS přeposílá dotazy (JSON seznam).
    pub const DNS_FORWARDERS: &str = "dns_forwarders";
    /// Co měl systém za DNS, než jsme ho přepsali (JSON seznam).
    pub const DNS_ORIGINAL: &str = "dns_original";
}
