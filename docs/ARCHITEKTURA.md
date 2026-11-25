# Architektura

> Vlastní zjednodušená obdoba Active Directory. Žádná Samba, žádné AD DS,
> žádné sssd — všechno dělají dva naše programy. Knihovny (crates) ano.

## 1. Co to má umět a co ne

**Má:**
- vlastní databáze domény (uživatelé, skupiny, OU, počítače) v SQLite
- přihlašování doménového uživatele ověřené proti serveru
- vlastní DNS server (dopředná + reverzní zóna, A/PTR/SRV, forwarder)
- zásady skupiny: pravidla hesel, zamykání účtu, uvítací zpráva, tapeta
- webová správa ve vzhledu Správce serveru (dashboard, průvodci, nástroje)
- běh jako služba: Windows Service, systemd, runit
- klient: připojení do domény, stažení zásad, odpojení s úplným návratem

**Nemá (schválně):**
- kompatibilitu se skutečným AD — žádný LDAP, Kerberos, SMB, GPO soubory
- přihlašování do samotného systému (Credential Provider, PAM) — to je
  samostatná, riziková kapitola a zadání ji vylučuje
- replikaci mezi více řadiči, lesy, trusty, DHCP, certifikační službu pro
  klienty

To, co neumíme, nepředstíráme. Vzhled a postup se podobá Windows Serveru
2025, vnitřek je náš.

## 2. Celkový obrázek

```
                    ┌──────────────────────────────────────────────┐
  prohlížeč         │  ad-server (jeden proces, více úloh)         │
  127.0.0.1:8080 ───┼─► správní HTTP ── axum ─┐                    │
  (nebo SSH tunel)  │   jen loopback          │                    │
                    │                         ▼                    │
  ad-client ────────┼─► doménové API ──► jádro domény              │
  TLS :8443         │   axum + rustls      (ad-core model)         │
                    │                         │                    │
  dotazy DNS ───────┼─► DNS server ───────────┤                    │
  :53 UDP/TCP       │   (hickory-proto)       ▼                    │
                    │                    SQLite (WAL)              │
                    │                         │                    │
                    │   forwarder ──► původní DNS sítě             │
                    └──────────────────────────────────────────────┘
```

Jeden binární soubor, uvnitř tři nezávislé úlohy (tokio tasks) nad jedním
datovým jádrem. Důvod: snadná instalace („jeden exe soubor“) a jeden
společný stav bez meziprocesové komunikace.

### Vrstvy

| Vrstva | Kde | Zodpovědnost |
|---|---|---|
| `ad-core` | sdílený crate | model, protokol, zásady, validace, hesla |
| `ad-server/store` | server | SQLite, transakce, migrace |
| `ad-server/domain` | server | pravidla domény (povýšení, zásady, uzamčení) |
| `ad-server/http` | server | axum routery, autentizace, CSRF, audit |
| `ad-server/dns` | server | zóny, odpovídání, forwarder |
| `ad-server/web` | server | zabalené HTML/CSS/JS (rust-embed) |
| `ad-server/service` | server | Windows Service / systemd / runit |
| `ad-client` | klient | join/leave, DNS záloha, logon, zásady |

## 3. Procesy, porty a oddělení rozhraní

| Název | Adresa | TLS | Kdo s tím mluví |
|---|---|---|---|
| `admin` | `127.0.0.1:8080` | volitelné (viz níže) | prohlížeč správce |
| `domain-api` | `0.0.0.0:8443` | **ano** | `ad-client` |
| `dns-udp`, `dns-tcp` | `0.0.0.0:53` | — | kdokoli v síti |

**Správní rozhraní a doménové API jsou oddělené routery na oddělených
poslouchátkách.** Z vnější sítě se na správu nedá dosáhnout vůbec — ne
proto, že by to router zakázal, ale protože tam neposlouchá. To je
nejsilnější druh izolace.

### TLS na správním rozhraní: obojí, s pojistkou

Zadání říká „komunikace přes TLS“. Klient–server TLS má vždy, bez
výjimky. U správního rozhraní se dá vybrat:

```toml
[admin]
bind = "127.0.0.1:8080"   # kde poslouchá správa
tls  = false              # true = HTTPS se stejným certifikátem jako doménové API
```

**Pojistka:** když `bind` není loopback (`127.0.0.1` nebo `::1`), je
`tls = true` povinné a server s `false` odmítne nastartovat. Důvod: na
loopbacku provoz nikdy neopustí počítač, ale na `0.0.0.0` by heslo
správce letělo sítí v čistém textu. Takhle si můžeš přepnout, co
potřebuješ, ale nedá se omylem vystavit nechráněná správa.

**Výchozí stav** je `127.0.0.1:8080` a `tls = false`, protože:

- provoz neopustí počítač, odposlechnout se dá jen z toho stroje
- vzdáleně se k tomu dostaneš SSH tunelem, kde šifruje SSH
  (`ssh -L 8080:127.0.0.1:8080 uzivatel@server`)
- prohlížeč nehlásí varování o nedůvěryhodném certifikátu, takže to
  v obhajobě neruší

S `tls = true` se použije stejný certifikát jako pro doménové API, tedy
podepsaný naší CA. Prohlížeč na varování upozorní, dokud do něj
nenaimportuješ `ca.pem` — to je očekávané, ne chyba.

## 4. Kde co leží

| | Windows | Debian / Void |
|---|---|---|
| konfigurace serveru | `C:\ProgramData\ad-server\config.toml` | `/etc/ad-server/config.toml` |
| databáze | `C:\ProgramData\ad-server\domain.db` | `/var/lib/ad-server/domain.db` |
| certifikáty, CA | `C:\ProgramData\ad-server\pki\` | `/var/lib/ad-server/pki/` |
| tapety a soubory | `...\assets\` | `/var/lib/ad-server/assets/` |
| log | `...\logs\ad-server.log` | `/var/log/ad-server/ad-server.log` |
| jednorázový token | `...\setup-token.txt` | `/var/lib/ad-server/setup-token.txt` |
| stav klienta | `C:\ProgramData\ad-client\state.json` | `/var/lib/ad-client/state.json` |
| záloha DNS klienta | `...\dns-backup.json` | `/var/lib/ad-client/dns-backup.json` |

Všechny soubory s tajemstvím: na Linuxu `0600` a vlastník služby, na
Windows ACL jen pro `SYSTEM` a `Administrators`. Nic se nepíše mimo tyhle
cesty — odinstalace je pak smazání dvou adresářů a jedné služby.

## 5. Databáze (náhled na fázi 2)

SQLite v režimu WAL, `foreign_keys = ON`, migrace číslované v kódu.

```sql
-- jedna doména, řádek s id = 1
CREATE TABLE domain(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  dns_name TEXT NOT NULL, short_name TEXT NOT NULL,
  sid_a INTEGER NOT NULL, sid_b INTEGER NOT NULL, sid_c INTEGER NOT NULL,
  dc_hostname TEXT NOT NULL, dc_ip TEXT NOT NULL,
  next_rid INTEGER NOT NULL DEFAULT 10000,
  created_at TEXT NOT NULL);

CREATE TABLE ou(
  id INTEGER PRIMARY KEY, guid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL, parent_id INTEGER REFERENCES ou(id),
  path TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
  protected INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);

CREATE TABLE users(
  id INTEGER PRIMARY KEY, guid TEXT NOT NULL UNIQUE,
  rid INTEGER NOT NULL UNIQUE,
  sam TEXT NOT NULL UNIQUE,             -- vždy malými písmeny
  password_hash TEXT NOT NULL,          -- PHC argon2id, nikdy odsud nevyleze
  ou_id INTEGER REFERENCES ou(id),
  enabled INTEGER NOT NULL DEFAULT 1,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  password_never_expires INTEGER NOT NULL DEFAULT 0,
  password_set_at TEXT, last_logon_at TEXT, locked_until TEXT,
  failed_logons INTEGER NOT NULL DEFAULT 0, first_failed_at TEXT,
  builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
  -- + display_name, given_name, surname, email, description
);

CREATE TABLE password_history(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL, set_at TEXT NOT NULL);

CREATE TABLE groups(...);          -- rid, sam, name, kind, ou_id, builtin
CREATE TABLE group_members(group_id, member_kind, member_id, UNIQUE(...));
CREATE TABLE computers(...);       -- rid, name, dns_name, secret_hash, ou_id,
                                   -- os_name, os_version, last_ip, last_seen_at
CREATE TABLE gpos(id, guid, name, settings_json, enabled, ...);
CREATE TABLE gpo_links(id, gpo_id, scope, ou_id, ord, enforced, enabled);
CREATE TABLE dns_zones(id, name, kind, serial, soa_*, managed);
CREATE TABLE dns_records(id, zone_id, name, type, ttl, rdata_json, managed);
CREATE TABLE admin_sessions(token_hash PRIMARY KEY, principal_json,
                            csrf_token, expires_at, created_ip);
CREATE TABLE machine_tokens(token_hash PRIMARY KEY, computer_id, expires_at);
CREATE TABLE user_tickets(token_hash PRIMARY KEY, user_id, computer_id,
                          expires_at);
CREATE TABLE assets(id TEXT PRIMARY KEY, sha256, size, format, width, height);
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE events(id, at, action, actor, target, source_ip, success, detail);
CREATE TABLE login_attempts(ip TEXT, at TEXT);   -- omezení rychlosti
```

Hesla a tajemství jsou **jen** v `users.password_hash`,
`password_history` a `computers.secret_hash`. Žádný dotaz, který vrací
objekt do API, se jich nedotýká — struktury v `ad-core::model` je ani
neumí reprezentovat.

## 6. TLS a vlastní certifikační autorita

Při povýšení na řadič domény server vygeneruje (`rcgen`):

1. **CA** — samopodepsaný certifikát `AD Domain CA (skola.internal)`,
   klíč ECDSA P-256, platnost 10 let, `is_ca = true`.
2. **certifikát serveru** — podepsaný tou CA, SAN:
   `dc01.skola.internal`, `dc01`, IP adresa řadiče. Platnost 1 rok,
   server si ho obnoví sám (CA se nemění).

Klient si při připojení **připne otisk CA**, ne otisk serveru. Díky tomu
obnova certifikátu serveru klientovi nic nerozbije, ale podvržený server
s jinou CA neprojde. Otisk ověřuje člověk: webová správa ho zobrazí,
správce ho zadá klientovi (`ad-client join --fingerprint ...`).

## 7. DNS

Vlastní server postavený na `hickory-proto` (parsování a skládání
paketů). Odpovídání, zóny i forwarder jsou náš kód.

```
dotaz ──► patří do našich zón?
            ├── ano ──► odpověď z SQLite (A, AAAA, PTR, SRV, TXT, NS, MX, SOA)
            │           nic nenalezeno → NXDOMAIN s naším SOA
            └── ne ───► je forwarder? ──► ano: přepošli, výsledek do cache
                                      └── ne: REFUSED
```

Při vytvoření domény `skola.internal` se založí:

| Zóna | Záznam | Hodnota |
|---|---|---|
| `skola.internal` | `@ SOA` | `dc01.skola.internal hostmaster...` |
| | `@ NS` | `dc01.skola.internal` |
| | `dc01 A` | IP řadiče |
| | `_ad._tcp SRV` | `0 100 8443 dc01.skola.internal` |
| `56.168.192.in-addr.arpa` | `10 PTR` | `dc01.skola.internal` |

Forwarder se předvyplní tím, co měl systém nastavené **před** námi
(`/etc/resolv.conf`, resp. Windows DNS klient). Klient při připojení
k domény udělá to samé na své straně: zálohuje a nastaví sebe na náš
server. Při odpojení se vrátí záloha.

SRV záznam `_ad._tcp` není kosmetika — klient, který zná jen jméno domény,
si jím najde adresu a port řadiče.

## 8. Cesta zásad od správce ke klientovi

```
správce ve webu ──► GPO (PolicySet, JSON v SQLite)
                      │  připojení na doménu nebo OU, pořadí, vynuceno
                      ▼
            vyhodnocení (ad-core::policy::vyhodnot)
              doména → OU od korene k listu, vynucené nahoru
                      ▼
            EffectivePolicy + serial
                      ▼
 klient GET /api/v1/machine/policy  (nebo policy pro uživatele při logon)
                      ▼
       klient znovu validuje (nevěří ani serveru) ──► použije
```

`serial` se zvýší při každé změně zásad. Klient ho posílá v heartbeatu
a stahuje znovu jen při změně.

**Zásada je uzavřený výčet dat.** V `PolicySet` není a nebude pole, které
by znamenalo „spusť tohle“. Všechny struktury mají `deny_unknown_fields`,
takže kdyby server poslal cokoli navíc, klient to odmítne už při
parsování. Tapeta se přenáší jako obrázek s kontrolním součtem, formát se
ověřuje podle magických bajtů a SVG je zakázané (je to XML se skriptem).

## 9. Běh jako služba

| Systém | Jak | Co se udělá |
|---|---|---|
| Windows | `windows-service` crate, `ad-server install-service` | zapíše službu `ADServer`, start automaticky, log do souboru |
| Debian | jednotka systemd `/etc/systemd/system/ad-server.service` | `Type=notify`, `User=ad-server`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` (port 53) |
| Void | runit `/etc/sv/ad-server/run` | `exec chpst -u ad-server ... 2>&1`, log přes `svlogd` |

Stejný binární soubor pozná, že ho spustil service manager (`--service`,
resp. prostředí Windows SCM) a podle toho loguje. Na Linuxu port 53
neřešíme spuštěním pod rootem, ale `CAP_NET_BIND_SERVICE`, resp. u Void
`setcap` v instalačním skriptu.

## 10. Sestavení

| Výstup | Cíl (target) | Poznámka |
|---|---|---|
| `ad-server.exe`, `ad-client.exe` | `x86_64-pc-windows-gnu` | mingw-w64 |
| `ad-server-linux`, `ad-client-linux` | `x86_64-unknown-linux-musl` | staticky, běží na Debianu i Void |

```bash
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu
sudo apt install musl-tools mingw-w64          # Debian/Ubuntu
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target x86_64-pc-windows-gnu
```

Ověřeno ve fázi 1: oba cíle se přeloží, musl výstup je `static-pie`
a nepotřebuje žádnou knihovnu.

Pozor na fázi 2: `rusqlite` s `bundled` kompiluje SQLite v C, takže pro
musl je potřeba `musl-gcc` a pro Windows mingw. Oboje už máme vyzkoušené.

## 11. Plán fází a co po každé testovat

| Fáze | Obsah | Test |
|---|---|---|
| **1** | architektura, protokol, `ad-core` | `cargo test`, `--version`, oba cíle |
| 2 | SQLite, povýšení, uživatelé, přihlášení, TLS | `curl` proti API |
| 3 | webová správa (dashboard, průvodci, nástroje) | prohlížeč na 127.0.0.1 |
| 4 | DNS server, zóny, forwarder | `dig @server`, `nslookup` |
| 5 | klient: join, logon, zásady, leave | dvě virtuálky |
| 6 | Windows Service, systemd, runit | restart virtuálky |
| 7 | `index.html`, SHA-256, GitHub Actions | stáhnout a spustit |

Po každé fázi se čeká na tvůj test. Nic se neinstaluje a nemění v systému
bez výslovného souhlasu a všechno jde odinstalovat.
