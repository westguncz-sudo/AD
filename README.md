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
| 2 | server: SQLite, doména, uživatelé, přihlášení, TLS | hotovo |
| 3 | webová správa (dashboard, průvodci, nástroje) | hotovo |
| 4 | vlastní DNS server | hotovo |
| 5 | klient a zásady | hotovo |
| **6** | služby: Windows Service, systemd, runit | **hotovo, k otestování** |
| **7** | `index.html`, SHA-256, GitHub Actions | **hotovo, k otestování** |

## Dokumentace

| Soubor | Co v něm je |
|---|---|
| [`docs/INSTALACE.md`](docs/INSTALACE.md) | **návod krok za krokem**: server, klient, ověření, odinstalace, řešení potíží |
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
    src/sluzba.rs          instalace služby: systemd, runit, Windows Service
    src/dns/               vlastní DNS server (hickory-proto jen na pakety)
      odpoved.rs           sestavení odpovědi ze zón — bez sítě, plně testovatelné
      forward.rs           přeposílání dál + krátká paměť na odpovědi
      mod.rs               poslouchání na UDP i TCP, počitadla
    src/store/             SQLite: schéma, objekty, přihlašování, zásady, DNS
    src/http/              axum: správní API, doménové API, CSRF, chyby
    web/                   webové rozhraní zabalené do binárky
      index.html           kostra stránky
      css/app.css          vzhled podle Správce serveru
      js/jadro.js          API, DOM, dialogy, formátování
      js/app.js            přihlášení, rám, navigace, směrování
      js/pruvodce.js       rám průvodce (kroky vlevo, tlačítka dole)
      js/pohledy.js        přehled, místní server, oba průvodci, audit
      js/nastroje.js       uživatelé a počítače, DNS, zásady skupiny
  ad-client/               klient
    src/spojeni.rs         TLS s připnutým otiskem autority, volání API
    src/stav.rs            co si klient pamatuje mezi spuštěními
    src/dns.rs             záloha, přepnutí a návrat nastavení DNS
    src/zasady.rs          použití zásad: uvítací zpráva, tapeta
    src/main.rs            příkazy join, status, logon, passwd, policy, leave
docs/
  test-faze2.sh            automatický test serveru (85 kontrol)
  test-faze3.sh            automatický test rozhraní v prohlížeči (76 kontrol)
  test-faze4.sh            automatický test DNS serveru přes dig (41 kontrol)
  test-faze5.sh            automatický test klienta a zásad (65 kontrol)
  test-faze6.sh            test instalace služby (nanečisto i doopravdy)
scripts/
  sestav-vydani.sh         přeloží všechny čtyři binárky a vyrobí index.html
dist/
  index.template.html      šablona stránky ke stažení
.github/workflows/
  sestaveni.yml            kontroly, testy, sestavení a vydání
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

## Test fází 6 a 7

### Fáze 6 — služba

```bash
# nanečisto: jen ukáže, co by instalace udělala
bash docs/test-faze6.sh

# doopravdy: nainstaluje službu, ověří ji a zase ji odebere
sudo bash docs/test-faze6.sh --opravdu
```

Ručně:

```bash
sudo cp target/release/ad-server /usr/local/bin/
sudo ad-server install-service            # jen vypíše, co udělá
sudo ad-server install-service --yes      # teprve tohle to udělá
sudo ad-server service-status
sudo ad-server uninstall-service --yes    # a takhle zase pryč
```

Na Windows totéž v příkazovém řádku jako správce.

Co za tím je:

| Systém | Co vznikne |
|---|---|
| Debian a jiné se systemd | `/etc/systemd/system/ad-server.service` |
| Void Linux | `/etc/sv/ad-server/run` a `log/run`, odkaz ve `/var/service` |
| Windows | služba `ADServer` ve správci služeb |

Na Linuxu server **neběží pod rootem**. Port 53 je pod 1024, ale místo
práv roota dostane služba jen schopnost `CAP_NET_BIND_SERVICE`
(systemd přes `AmbientCapabilities`, runit přes `setcap` na binárce).
Jednotka systemd navíc zakazuje zápis mimo vlastní adresáře
(`ProtectSystem=strict`).

### Fáze 7 — sestavení a stránka ke stažení

```bash
bash scripts/sestav-vydani.sh
# výsledek: dist/index.html + čtyři binárky + SHA256SUMS
```

Skript sám zkontroluje, že linuxové binárky jsou staticky slinkované
(jinak by na Void nenaběhly) a že `.exe` nepotřebují přibalenou
knihovnu z mingw. Když ne, skončí chybou — tohle se nemá zjistit až
u uživatele.

Stránku si prohlédni v prohlížeči: `dist/index.html`. Odkazy míří na
soubory vedle ní; při vydání se přepíšou na adresy z GitHub Releases.

**GitHub Actions** (`.github/workflows/sestaveni.yml`) dělá při každém
pushi tohle:

| Úloha | Co dělá |
|---|---|
| `kontrola` | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, eslint |
| `testy-nanecisto` | spustí testy fází 2 až 6 a uloží snímky obrazovky |
| `sestaveni` | přeloží všechny čtyři binárky a vyrobí `index.html` |
| `vydani` | jen pro značku `v*` — vytvoří vydání se soubory a součty |

Vydat novou verzi:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Všechno se překládá na Linuxu — Windows binárky křížově přes mingw.
Ověřili jsme, že výsledná `.exe` nepotřebují žádnou přibalenou DLL,
takže se tím nic neztrácí a sestavení běží v jednom prostředí.

## Test fáze 5

```bash
bash docs/test-faze5.sh
```

Server i klient běží na jednom stroji. Klient zapisuje do vlastního
adresáře a nastavení DNS si přesměruje na dočasný soubor
(`AD_CLIENT_RESOLV_CONF`), takže o nastavení tvého stroje nezavadí.

### Ručně, ve dvou virtuálkách

Na serveru najdi otisk certifikační autority: **Místní server →
Certifikační autorita domény**. Je tam i hotový příkaz k opsání.

```bash
# na klientovi (Debian/Void) — zápis do /etc/resolv.conf chce práva
sudo ad-client join --server 192.168.56.10      --fingerprint A1:B2:...:FF --admin administrator

ad-client status                      # stav připojení, DNS, zásady
ad-client logon --user jan.novak      # přihlášení v programu + zásady
ad-client passwd --user jan.novak     # změna hesla
ad-client policy --apply              # stáhnout a použít zásady
sudo ad-client leave                  # odpojit a vrátit DNS
```

Na Windows totéž v příkazovém řádku spuštěném jako správce
(`ad-client.exe join …`).

Co zkusit naschvál špatně:

| Zkus | Co se stane |
|---|---|
| `join` se špatným otiskem | spojení se nenaváže a **heslo správce se vůbec neodešle** |
| `join` bez `--fingerprint` | klient odmítne a vysvětlí proč |
| `--password tajne` na příkazové řádce | klient to odmítne (heslo by bylo vidět v `ps`) |
| ručně přepsat `ca.pem` v datech klienta | klient pozná, že nesedí s uloženým otiskem |
| vyměnit soubor tapety na serveru | klient ho zahodí, protože nesedí kontrolní součet |
| `join` podruhé | klient řekne, že počítač už v doméně je |
| `leave` při vypnutém serveru | klient nic nesmaže; s `--force` uklidí aspoň sebe |

### Co klient záměrně nedělá

Nezasahuje do přihlašování do systému — žádný Credential Provider na
Windows, žádný modul PAM na Linuxu. Doménovým účtem se přihlásíš
**v tomhle programu**, ne na přihlašovací obrazovce. Zadání to tak chce
a je to i rozumné: špatně napsaný Credential Provider dokáže zamknout
přihlášení do celého systému.

Z toho plyne i omezení tapety: nastaví se přihlášenému uživateli
(na Linuxu v GNOME přes `gsettings`, na Windows přes
`SystemParametersInfo`). Volba „uživatel ji nemá měnit" je proto jen
informace, ne vynucení — a tak je to i popsané v rozhraní.

## Test fáze 4

```bash
cargo build -p ad-server
sudo apt install bind9-dnsutils     # kvůli dig; na Void: xbps-install bind-utils
bash docs/test-faze4.sh
```

Test si spustí server na portu 15353 (aby nepotřeboval oprávnění),
vytvoří doménu a pak se ptá pomocí `dig`.

### Ručně

DNS server se spustí sám, jakmile je nainstalovaná role DNS. Port 53
je pod 1024, takže potřebuje oprávnění:

```bash
# Debian: nejdřív uvolnit port 53 od systemd-resolved
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf && echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# oprávnění na port pod 1024 bez spouštění pod rootem
sudo setcap 'cap_net_bind_service=+ep' ./target/debug/ad-server

cargo run -p ad-server -- --data-dir ./data run
```

Co zkusit (`<ip>` je adresa serveru, z klientské virtuálky):

```bash
dig @<ip> dc01.skola.internal A          # A záznam řadiče
dig @<ip> -x 192.168.56.10               # reverzní překlad
dig @<ip> _ad._tcp.skola.internal SRV    # podle tohohle si klient najde řadič
dig @<ip> skola.internal SOA             # SOA zóny
dig @<ip> neni.skola.internal A          # NXDOMAIN s SOA v authority
dig @<ip> +tcp dc01.skola.internal A     # totéž přes TCP
dig @<ip> seznam.cz A                    # přepošle se na forwarder
```

A co **nemá** projít:

| Zkus | Co se stane | Proč |
|---|---|---|
| `dig @<ip> skola.internal AXFR` | odmítnuto | jinak si kdokoli stáhne seznam všech počítačů |
| `dig @<ip> skola.internal ANY` | `REFUSED` | malý dotaz, velká odpověď = nástroj k zesílení útoku |
| dotaz mimo zóny z veřejné adresy | `REFUSED` | otevřený přeposílač na internetu je zbraň |
| dotaz mimo zóny bez forwarderu | `REFUSED` | není koho se zeptat |
| `dig @<ip> ... +norecurse` na cizí jméno | `REFUSED` | nejsme autorita a tazatel rekurzi nechce |

## Test fáze 3

Webové rozhraní se testuje v prohlížeči. Test se proklikne celým
postupem jako člověk a cestou ukládá snímky obrazovky:

```bash
cargo build -p ad-server

# jednou: Playwright a prohlížeč pro něj
npm install -g playwright && npx playwright install chromium

bash docs/test-faze3.sh
```

Snímky obrazovky skončí v `data-test-ui/snimky/` — hodí se do
dokumentace k projektu.

### Ručně

```bash
cargo run -p ad-server -- --data-dir ./data run
# a v prohlížeči: http://127.0.0.1:8080
```

Na serveru bez grafiky přes SSH tunel z vlastního počítače:

```bash
ssh -L 8080:127.0.0.1:8080 uzivatel@192.168.56.10
# pak v prohlížeči na svém stroji: http://127.0.0.1:8080
```

Postup v rozhraní je stejný jako ve Windows Serveru:

1. **Přihlášení** jednorázovým tokenem z konzole (vypíše se při prvním spuštění).
2. **Přehled** — uvítací panel s číslovaným rychlým startem a vlaječka
   upozornění vpravo nahoře.
3. **Spravovat → Přidat role a funkce** — průvodce v šesti krocích,
   role se nenainstalují bez zatrženého souhlasu.
4. Upozornění **„Povýšit server na řadič domény"**.
5. **Konfigurační průvodce** — jméno domény, řadič, DNS, souhrn,
   kontrola předpokladů (12 položek `pass`/`warn`/`fail`), instalace.
6. **Nástroje** — Uživatelé a počítače (strom vlevo, seznam vpravo),
   Správce DNS, Správa zásad skupiny, Auditní log.

Co zkusit naschvál špatně:

| Zkus | Co se stane |
|---|---|
| doména `skola.local` | průvodce nepustí dál už v prohlížeči |
| jméno domény s diakritikou | totéž |
| heslo `heslo` u nového uživatele | server vypíše, která pravidla chybí |
| potvrzení instalace rolí bez zatržení souhlasu | tlačítko Instalovat je zakázané |
| zásada s neznámým polem (přes `curl`) | `400 bad_request` |
| `fetch` bez hlavičky `x-ad-csrf` z konzole prohlížeče | `403 csrf_failed` |
| `document.cookie` v konzoli prohlížeče | session cookie není vidět (HttpOnly) |

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
