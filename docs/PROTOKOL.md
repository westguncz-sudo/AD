# Protokol AD-PROTO/1

JSON přes HTTPS. Žádný vlastní binární formát — dá se to ladit `curl`em
a v DevTools, a nepíšeme si vlastní parser, kde by byla chyba.

Zdroj pravdy pro všechny struktury je `crates/ad-core/src/proto.rs`.
Tenhle dokument je jeho čitelná podoba.

## 1. Základy

| | |
|---|---|
| verze | `1` (konstanta `PROTO_VERZE`) |
| hlavička verze | `X-AD-Proto: 1` — povinná u doménového API |
| doménové API | `https://<server>:8443/api/v1/...` |
| správní API | `http://127.0.0.1:8080/admin/api/v1/...` |
| obsah | `Content-Type: application/json; charset=utf-8` |
| čas | RFC 3339 v UTC, `2026-11-25T18:00:00Z` |

Při neznámé verzi server odpoví `400` a kódem `proto_version_unsupported`.
Verze se zvyšuje jen při nekompatibilní změně; přidání volitelného pole
do odpovědi verzi nemění.

### Chyby

Vždycky stejný tvar:

```json
{ "error": {
    "code": "invalid_credentials",
    "message": "jméno nebo heslo nesouhlasí",
    "details": null } }
```

Klient se rozhoduje podle `code`, nikdy podle `message` — texty se dají
přeložit, kódy ne. Úplný seznam kódů je v `ad-core::error::ErrorCode`.

`details` nese strojové podrobnosti tam, kde to pomůže. Například
u porušené zásady hesel:

```json
{ "error": { "code": "password_policy_violation",
  "message": "heslo nesplňuje zásady domény",
  "details": { "complaints": [
      { "rule": "too_short", "min": 10 },
      { "rule": "missing_digit" } ] } } }
```

### Neznámá pole se odmítají

Všechny požadavky mají `deny_unknown_fields`. Překlep ve jméně pole
skončí chybou `400`, ne tichým ignorováním. Platí to na obou stranách:
klient takhle odmítne i odpověď serveru, která obsahuje něco navíc.

## 2. Kdo se jak autentizuje

Tři druhy přihlášení, každé jinde a jinak:

| Kdo | Kde | Čím | Jak dlouho |
|---|---|---|---|
| správce ve webu | správní API | session cookie + CSRF token | 60 min bez aktivity |
| počítač | doménové API | `Authorization: Bearer <token>` | 15 min, obnovuje se tajemstvím |
| doménový uživatel | doménové API | ticket vydaný při `logon` | 8 hodin |

### Počítačový účet

Při připojení do domény dostane počítač `machine_id` (GUID) a
`machine_secret` (256 bitů náhody, base64url). Tajemství se posílá **jen**
na `/machine/token`, kde se vyměňuje za krátkodobý token. Důvod: ověření
tajemství je Argon2id, což je schválně drahé, a nedělá se to u každého
dotazu. Token je uložený jako SHA-256 (má dost entropie, Argon2 by byl
zbytečný).

### Správce ve webu

```
POST /admin/api/v1/session         → Set-Cookie: ad_admin_session=...
                                      HttpOnly; SameSite=Strict; Path=/
                                   → tělo obsahuje csrf_token
```

Každý požadavek, který něco mění (POST, PUT, PATCH, DELETE), musí mít
hlavičku `X-AD-CSRF: <csrf_token>`. Server navíc kontroluje `Origin`
nebo `Referer` proti vlastní adrese. Čtení (GET) CSRF token nepotřebuje.

Po obnovení stránky prohlížeč token v paměti nemá, ale cookie platí dál.
Token se proto vrací i z `GET /me`. Není to díra: cizí stránka si
odpověď přečíst nemůže (neposíláme žádné hlavičky CORS) a cookie má
`SameSite=Strict`.

V seznamech znamená `ou_id=0` „přímo pod doménou". Nula není platné id
žádné organizační jednotky, takže se nedá splést — a `ou_id IS NULL`
se v dotazu jinak zapsat nedá. Vynechané `ou_id` znamená „kdekoli
v doméně" a používá se při hledání.

### První přihlášení, než doména existuje

Čerstvý server žádné účty nemá. Při prvním startu vypíše do konzole
a do souboru `setup-token.txt` jednorázový token:

```
POST /admin/api/v1/session
{ "method": "setup_token", "token": "..." }
```

Token platí jen do vytvoření domény a pak se zneplatní. Potom se
přihlašuje doménový správce:

```
POST /admin/api/v1/session
{ "method": "password", "username": "administrator", "password": "..." }
```

### Omezení rychlosti

Neúspěšná přihlášení se počítají na IP adresu: po 10 chybách za 5 minut
odpovídá server `429 rate_limited` bez ohledu na správnost hesla. Je to
nad zamykáním účtů, které se počítá zvlášť podle zásady.

Když uživatel neexistuje, server stejně ověří heslo proti náhodnému hashi
(`password::haš_na_zdržení`). Odpověď pak trvá stejně dlouho, takže se
nedá zjistit, která jména v doméně existují.

## 3. Doménové API — `/api/v1`

| Metoda | Cesta | Autentizace | Co dělá |
|---|---|---|---|
| GET | `/hello` | žádná | informace o serveru a doméně |
| POST | `/join` | heslo správce | připojí počítač, vrátí tajemství |
| POST | `/unjoin` | token počítače | odpojí počítač, uklidí DNS |
| POST | `/machine/token` | tajemství počítače | vydá krátkodobý token |
| GET | `/machine/policy` | token počítače | zásady pro počítač |
| GET | `/machine/asset/{id}` | token počítače | stáhne tapetu (fáze 5) |
| POST | `/auth/logon` | token počítače | přihlásí uživatele, vrátí zásady |
| POST | `/auth/change-password` | token počítače | změna hesla uživatelem |
| POST | `/auth/logoff` | ticket uživatele | zneplatní ticket |
| POST | `/heartbeat` | token počítače | ohlášení, kontrola změny zásad |

**Co v doménovém API není a nebude:** žádné `/exec`, `/script`, `/update`
ani nic, co by klientovi řeklo, aby něco spustil. Klient od serveru dostává
jen data, nikdy ne kód.

### `GET /hello`

```json
{ "product": "ad-server", "version": "0.1.0",
  "proto_min": 1, "proto_max": 1,
  "stage": "domain_controller",
  "domain": { "dns_name": "skola.internal", "short_name": "SKOLA",
              "dc_fqdn": "dc01.skola.internal" },
  "ca_fingerprint_sha256": "A1:B2:...:FF",
  "server_time": "2026-11-25T18:00:00Z" }
```

Záměrně neprozrazuje počty objektů ani jména — je to jediný koncový bod
bez přihlášení.

### Připojení do domény

```
ad-client                                           ad-server
    │
    │ 1. TLS handshake, ale certifikát ještě neznám
    ├──────────────────────────────────────────────────►
    │ 2. spočítám otisk CA, porovnám s --fingerprint
    │    nesouhlasí → KONEC, chyba fingerprint_mismatch
    │
    │ 3. GET /api/v1/hello
    ├──────────────────────────────────────────────────►
    │◄────────────────────────── doména, verze protokolu
    │
    │ 4. POST /api/v1/join  { computer_name, admin_*, os_* }
    ├──────────────────────────────────────────────────►
    │           server: ověří heslo správce (Argon2id),
    │           ověří, že je ve Domain Admins, založí
    │           počítačový účet, zapíše A + PTR záznam
    │◄──── machine_id, machine_secret, ca_cert_pem, dns_servers
    │
    │ 5. zálohuji původní DNS → dns-backup.json
    │ 6. nastavím DNS na server
    │ 7. uložím state.json (0600)
    │ 8. POST /api/v1/machine/token → bearer token
    │ 9. GET /api/v1/machine/policy → první zásady
```

Krok 2 je podstatný: otisk se kontroluje **před** odesláním hesla správce.

`POST /api/v1/join`:

```json
{ "computer_name": "PC-01",
  "admin_username": "SKOLA\\administrator",
  "admin_password": "...",
  "ou_path": "/Computers",
  "os_name": "Debian GNU/Linux", "os_version": "13",
  "client_version": "0.1.0",
  "ip_address": "192.168.56.20" }
```

Server porovná `ip_address` s adresou, ze které spojení skutečně přišlo.
Při nesouladu použije tu skutečnou a rozdíl zapíše do auditu — klient
si nesmí zapsat do DNS cizí adresu.

### Přihlášení uživatele v programu

```
POST /api/v1/auth/logon
Authorization: Bearer <token počítače>
{ "username": "jan.novak", "password": "..." }
```

Server po řadě:
1. omezení rychlosti podle IP,
2. najde účet (nebo haš na zdržení),
3. zkontroluje `locked_until` → `account_locked`,
4. ověří heslo Argon2id,
5. **chyba:** zvýší počítadlo, podle zásady případně zamkne, zapíše
   do auditu, vrátí `invalid_credentials`,
6. **úspěch:** vynuluje počítadlo, zapíše `last_logon_at`, zjistí
   skupiny (i vnořené), vyhodnotí zásady pro OU uživatele, vydá ticket.

```json
{ "user": { "sam_account_name": "jan.novak",
            "upn": "jan.novak@skola.internal",
            "display_name": "Jan Novák",
            "sid": "S-1-5-21-...-10004",
            "groups": ["Domain Users", "Zaci 1.A"],
            "ou_path": "/Uzivatele/Zaci" },
  "ticket": "...", "ticket_expires_at": "2026-11-26T02:00:00Z",
  "policy": { "password": {...}, "lockout": {...},
              "welcome": {...}, "wallpaper": {...}, "applied": [...] },
  "policy_serial": 42,
  "must_change_password": false,
  "password_expires_in_days": 83 }
```

Pozor na rozdíl: `must_change_password` vrací server i při jinak
úspěšném přihlášení. Klient pak musí nejdřív zavolat
`/auth/change-password`; ticket platí, ale klient nic jiného nedělá.

### Zásady

```
GET /api/v1/machine/policy
Authorization: Bearer <token počítače>
If-None-Match: "42"          ← nepovinné, serial, co klient má

200 { "policy": {...}, "serial": 43, "generated_at": "...",
      "policy_poll_seconds": 900 }
304                          ← beze změny
```

Tapeta se stahuje zvlášť a klient **musí** zkontrolovat součet:

```
GET /api/v1/machine/asset/{asset_id}
→ 200, Content-Type: image/png, X-AD-SHA256: <hex>
```

Když se součet neshoduje s tím v zásadě, klient soubor zahodí a nahlásí
chybu. Formát se navíc ověří podle magických bajtů (PNG/JPEG), ne podle
přípony ani `Content-Type`.

## 4. Správní API — `/admin/api/v1`

Dostupné jen z `127.0.0.1`. Měnící akce potřebují `X-AD-CSRF`.

### Stav a průvodci

| Metoda | Cesta | Co dělá |
|---|---|---|
| GET | `/hello` | **bez přihlášení**: verze, stav serveru, jméno domény |
| POST/DELETE | `/session` | přihlášení, odhlášení |
| GET | `/me` | kdo je přihlášený + CSRF token |
| GET | `/status` | vše pro dashboard na jeden dotaz |
| POST | `/roles` | „Přidat role a funkce“ — vyžaduje `consent: true` |
| POST | `/promote/precheck` | kontrola předpokladů |
| POST | `/promote` | vytvoření domény |
| POST | `/demote` | zrušení domény (opsat jméno domény) |
| GET | `/events` | auditní log |

`GET /status` vrací i `alerts` — tím se dělá ta žlutá vlaječka
„Povýšit server na řadič domény“:

```json
{ "stage": "roles_installed",
  "roles": { "directory": true, "dns": true },
  "domain": null,
  "counts": { "users": 0, ... },
  "alerts": [ { "code": "promote_pending", "level": "warning",
      "title": "Povýšit server na řadič domény",
      "detail": "Role doménových služeb je nainstalovaná, doména ještě není.",
      "action": "#/promote" } ],
  "listeners": [ { "name": "admin", "address": "127.0.0.1:8080",
                   "tls": false, "running": true }, ... ] }
```

Kontrola předpokladů (`/promote/precheck`) vrací seznam položek se
stavem `pass` / `warn` / `fail`. Plánované kontroly:

| kód | co kontroluje |
|---|---|
| `admin_password` | heslo správce splňuje zásadu |
| `domain_name` | jméno je platné, není `.local` |
| `dns_port_free` | na portu 53 nic jiného neposlouchá |
| `api_port_free` | port 8443 je volný |
| `static_ip` | zadaná IP opravdu patří tomuto stroji |
| `hostname_match` | jméno stroje odpovídá `dc_hostname` |
| `writable_paths` | zápis do datových adresářů funguje |
| `clock` | systémový čas je rozumný (kvůli platnosti certifikátů) |
| `existing_dns` | našel se původní DNS pro forwarder |
| `service_user` | uživatel/práva pro službu existují |

`fail` znamená, že `/promote` odmítne pokračovat. `warn` jen ukáže
upozornění.

### Objekty domény

| Cesta | Metody |
|---|---|
| `/ous`, `/ous/{id}` | GET, POST, PATCH, DELETE |
| `/ous/tree` | GET — strom pro levý panel |
| `/users`, `/users/{id}` | GET, POST, PATCH, DELETE |
| `/users/{id}/password` | PUT |
| `/users/{id}/unlock` | POST |
| `/users/{id}/move` | POST |
| `/groups`, `/groups/{id}` | GET, POST, PATCH, DELETE |
| `/groups/{id}/members` | GET, POST (přidat), DELETE (odebrat) |
| `/computers`, `/computers/{id}` | GET, POST, PATCH, DELETE |
| `/gpos`, `/gpos/{id}` | GET, POST, PATCH, DELETE |
| `/gpos/{id}/links` | GET, POST, DELETE |
| `/gpos/effective?ou_id=` | GET — výsledná sada zásad |
| `/assets` | POST — nahrání tapety (tělo je obsah souboru) |
| `/assets/{id}` | GET — náhled ve správě |
| `/dns/status` | GET — běží/neběží, adresy, forwardery, počitadla |
| `/dns/zones`, `/dns/zones/{id}` | GET, POST, DELETE |
| `/dns/zones/{id}/records` | GET, POST |
| `/dns/zones/{id}/records/{rid}` | PATCH, DELETE |
| `/dns/forwarders` | GET, PUT |

Seznamy jsou stránkované: `?q=&ou_id=&scope=level|subtree&offset=&limit=`,
`limit` nejvýš 500.

```json
{ "items": [ ... ], "total": 137, "offset": 0, "limit": 50 }
```

## 5. Co se neloguje

Do logu ani do auditu nikdy nejde: heslo, nové heslo, tajemství počítače,
token, obsah cookie, CSRF token. V `ad-core` jsou všechna tahle pole typu
`secret::Tajne`, které se v `Debug` vypíše jako `Tajne(***)` — takže se
to nestane ani omylem přes `tracing::debug!("{:?}", req)`.

Audit zapisuje: čas, strojovou akci (`user.create`, `auth.logon.failed`),
kdo (`SKOLA\administrator`, `machine:PC-01`, `setup-token`), čeho se to
týkalo, IP a výsledek.

## 6. Co už funguje

Stav po fázi 2 — co je hotové a co ještě ne:

| Část | Stav |
|---|---|
| `/hello`, `/join`, `/unjoin`, `/machine/token` | hotovo |
| `/auth/logon`, `/auth/change-password`, `/auth/logoff` | hotovo |
| `/machine/policy` (včetně `If-None-Match`), `/heartbeat` | hotovo |
| `/machine/asset/{id}` (tapeta) | hotovo |
| správní API: session, status, roles, promote, demote, audit | hotovo |
| správní API: OU, uživatelé, skupiny, počítače, zásady, DNS data | hotovo |
| nahrání tapety (`POST /assets`) | hotovo |
| webové rozhraní nad tím | hotovo |
| vlastní DNS server na portu 53 | hotovo |
| klient: join, status, logon, passwd, policy, leave | hotovo |

## 7. Příklady na vyzkoušení

```bash
# základní informace o serveru, bez přihlášení
curl --cacert ca.pem https://dc01.skola.internal:8443/api/v1/hello | jq

# otisk CA, který má klient připnout
openssl x509 -in ca.pem -noout -fingerprint -sha256

# přihlášení správce do webové správy
curl -c cookies.txt -X POST http://127.0.0.1:8080/admin/api/v1/session \
  -H 'content-type: application/json' \
  -d '{"method":"password","username":"administrator","password":"..."}'

# měnící akce musí mít CSRF hlavičku
curl -b cookies.txt -X POST http://127.0.0.1:8080/admin/api/v1/users \
  -H "x-ad-csrf: $CSRF" -H 'content-type: application/json' \
  -d '{"sam_account_name":"jan.novak","password":"...","given_name":"Jan"}'

# vzdálená správa přes SSH tunel
ssh -L 8080:127.0.0.1:8080 spravce@dc01
```
