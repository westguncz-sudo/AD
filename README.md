# Vlastní zjednodušená obdoba Active Directory

Školní projekt v Rustu: **vlastní** doménový server a klient. Žádná Samba
AD, žádné Microsoft AD DS, žádné sssd — všechno dělají tyhle dva programy.
Knihovny (crates) používáme.

Vzhledem a postupem se to podobá Správci serveru z Windows Serveru 2025.
Kompatibilita se skutečným AD není cílem a nikde se nepředstírá.

## Stav

| Fáze | Co | Stav |
|---|---|---|
| 1 | architektura, protokol, sdílené jádro `ad-core` | hotovo |
| **2** | server: SQLite, doména, uživatelé, přihlášení, TLS | **hotovo, k otestování** |
| 3 | webová správa (dashboard, průvodci, nástroje) | čeká |
| 4 | vlastní DNS server | čeká |
| 5 | klient a zásady | čeká |
| 6 | služby: Windows Service, systemd, runit | čeká |
| 7 | `index.html`, SHA-256, GitHub Actions | čeká |

## Dokumentace

| Soubor | Co v něm je |
|---|---|
| [`docs/ARCHITEKTURA.md`](docs/ARCHITEKTURA.md) | komponenty, porty, databáze, DNS, cesta zásad, služby |
| [`docs/PROTOKOL.md`](docs/PROTOKOL.md) | AD-PROTO/1: koncové body, autentizace, chyby, příklady |
| [`docs/BEZPECNOST.md`](docs/BEZPECNOST.md) | model hrozeb, rozhodnutí a jejich důvody, známé slabiny |
| [`docs/TESTOVANI.md`](docs/TESTOVANI.md) | postup testu ve virtuálkách |

## Struktura

```
Cargo.toml                 workspace
rust-toolchain.toml        verze Rustu a cílové platformy
.cargo/config.toml         linkery pro křížové sestavení
crates/
  ad-core/                 sdílené jádro (bez síťování, plně testovatelné)
    src/error.rs           kódy chyb
    src/ids.rs             SID, RID, GUID
    src/names.rs           validace jmen (domény, účty, počítače, OU)
    src/model.rs           datový model domény
    src/policy.rs          zásady skupiny + vyhodnocení řetězce GPO
    src/password.rs        Argon2id, kontrola zásady hesel
    src/secret.rs          tokeny, otisky certifikátů, typ Tajne
    src/dns.rs             model zón a záznamů
    src/proto.rs           protokol AD-PROTO/1
  ad-server/               řadič domény
    src/config.rs          konfigurace a cesty k datům
    src/pki.rs             vlastní CA a certifikát serveru (rcgen)
    src/domain.rs          kontrola předpokladů, povýšení, zrušení domény
    src/store/             SQLite: schéma, objekty, přihlašování, zásady, DNS
    src/http/              axum: správní API, doménové API, CSRF, chyby
  ad-client/               klient (fáze 5)
docs/
  test-faze2.sh            automatický test fáze 2 na jednom stroji
```

Proč jedno sdílené jádro: kdyby měl server a klient každý svoji kopii
struktur, rozešly by se a vznikla by chyba, kterou kompilátor nenajde.
Takhle se při změně protokolu nepřeloží obojí, dokud to neopravíš.

## Sestavení

### Příprava (jednou)

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# cíle pro Windows a statický Linux
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu

# linkery — Debian/Ubuntu
sudo apt install musl-tools mingw-w64
# Void Linux
sudo xbps-install -S musl-devel mingw-w64
```

### Sestavení

```bash
cargo build                                              # pro vývoj
cargo build --release --target x86_64-unknown-linux-musl # Linux, staticky
cargo build --release --target x86_64-pc-windows-gnu     # Windows
```

Výstupy:

```
target/x86_64-unknown-linux-musl/release/ad-server    → ad-server-linux
target/x86_64-unknown-linux-musl/release/ad-client    → ad-client-linux
target/x86_64-pc-windows-gnu/release/ad-server.exe
target/x86_64-pc-windows-gnu/release/ad-client.exe
```

Linuxové verze jsou staticky slinkované (`static-pie`), takže běží na
Debianu i na Void Linuxu bez instalace knihoven.

## Test fáze 2

Celá fáze 2 se dá otestovat na jednom stroji, bez virtuálky:

```bash
cargo build -p ad-server
bash docs/test-faze2.sh
```

Skript projde celý postup a hlásí každý krok: start serveru, jednorázový
token, CSRF, přidání rolí, kontrolu předpokladů, povýšení na řadič domény,
vytvoření OU a uživatelů, TLS, připojení počítače, přihlášení uživatele,
zamčení účtu, zásady, restart serveru a zrušení domény. Kontroluje i to,
co se **nemá** stát — třeba že v logu ani v databázi není žádné heslo.

### Ručně, krok za krokem

```bash
# 1. server (datový adresář v projektu, ať se nic nesype do /var)
cargo run -p ad-server -- --data-dir ./data run

# vypíše jednorázový token, např.:
#   PRVNÍ SPUŠTĚNÍ — jednorázový token pro přihlášení do správy
#     Xy7...

# 2. přihlášení tím tokenem
TOKEN=$(cat data/setup-token.txt)
ODP=$(curl -s -c c.txt -X POST http://127.0.0.1:8080/admin/api/v1/session \
  -H 'content-type: application/json' \
  -d "{\"method\":\"setup_token\",\"token\":\"$TOKEN\"}")
CSRF=$(echo "$ODP" | jq -r .csrf_token)

# 3. přehled — uvidíš upozornění "Přidat role a funkce"
curl -s -b c.txt http://127.0.0.1:8080/admin/api/v1/status | jq

# 4. role
curl -s -b c.txt -X POST http://127.0.0.1:8080/admin/api/v1/roles \
  -H "x-ad-csrf: $CSRF" -H 'content-type: application/json' \
  -d '{"directory":true,"dns":true,"consent":true}' | jq

# 5. kontrola předpokladů (vypíše pass/warn/fail ke každé položce)
POV='{"domain_dns_name":"skola.internal","dc_hostname":"DC01",
  "dc_ip":"127.0.0.1","administrator_password":"Spravce-Heslo1",
  "dns":{"create_reverse":true,"reverse_prefix":24,
  "forwarders":["1.1.1.1"],"enable_server":false},"confirm":true}'
curl -s -b c.txt -X POST http://127.0.0.1:8080/admin/api/v1/promote/precheck \
  -H "x-ad-csrf: $CSRF" -H 'content-type: application/json' -d "$POV" | jq

# 6. vytvoření domény
curl -s -b c.txt -X POST http://127.0.0.1:8080/admin/api/v1/promote \
  -H "x-ad-csrf: $CSRF" -H 'content-type: application/json' -d "$POV" | jq

# 7. doménové API přes TLS, s ověřeným certifikátem naší CA
curl -s --cacert data/pki/ca.pem --resolve dc01.skola.internal:8443:127.0.0.1 \
  https://dc01.skola.internal:8443/api/v1/hello | jq
```

Co stojí za to zkusit naschvál špatně:

| Zkus | Očekávaná odpověď |
|---|---|
| POST bez hlavičky `x-ad-csrf` | `403 csrf_failed` |
| doména `skola.local` | kontrola skončí `fail` |
| heslo `heslo` u nového uživatele | `400 password_policy_violation` se seznamem porušených pravidel |
| zásada s polem `"run_command"` | `400 bad_request` — neznámé pole |
| 5× špatné heslo | `403 account_locked` |
| `jan.novak` připojuje počítač | `403 permission_denied` |
| správa z vnější IP adresy | spojení se vůbec nenaváže |

## Test fáze 1

Fáze 1 nemá nic, co by poslouchalo na síti — proto se testuje překladem
a jednotkovými testy. Žádná virtuálka ještě není potřeba.

```bash
# 1. všechny testy (73 testů)
cargo test

# 2. žádné varování
cargo clippy --all-targets -- -D warnings

# 3. formátování
cargo fmt --check

# 4. oba cíle se přeloží
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target x86_64-pc-windows-gnu

# 5. binárky se spustí a ohlásí verzi
./target/x86_64-unknown-linux-musl/release/ad-server --version
./target/x86_64-unknown-linux-musl/release/ad-client --help

# 6. musl výstup je opravdu statický
ldd target/x86_64-unknown-linux-musl/release/ad-server   # "statically linked"
file target/x86_64-pc-windows-gnu/release/ad-server.exe  # "PE32+ ... MS Windows"
```

Co stojí za to si projít v kódu, protože to jsou ta rozhodnutí:

```bash
# zásada s propašovaným příkazem se odmítne
cargo test -p ad-core neznama_polozka

# heslo se nevypíše do logu
cargo test -p ad-core tajne_se_nevypise

# .local se nedá použít jako doména
cargo test -p ad-core domena_local

# vynucená GPO přebije ostatní
cargo test -p ad-core vynucena_gpo
```

## Licence

MIT, viz [`LICENSE`](LICENSE).
