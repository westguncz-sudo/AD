# Vlastní zjednodušená obdoba Active Directory

Školní projekt v Rustu: **vlastní** doménový server a klient. Žádná Samba
AD, žádné Microsoft AD DS, žádné sssd — všechno dělají tyhle dva programy.
Knihovny (crates) používáme.

Vzhledem a postupem se to podobá Správci serveru z Windows Serveru 2025.
Kompatibilita se skutečným AD není cílem a nikde se nepředstírá.

## Stav

| Fáze | Co | Stav |
|---|---|---|
| **1** | architektura, protokol, sdílené jádro `ad-core` | **hotovo, k otestování** |
| 2 | server: SQLite, doména, uživatelé, přihlášení, TLS | čeká |
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
  ad-server/               řadič domény (fáze 2+)
  ad-client/               klient (fáze 5)
docs/
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
