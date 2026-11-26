# Bezpečnost: co chráníme, před kým a čím

Školní projekt, ale bezpečnost se nedělá „potom“. Tady je napsané, co
bereme jako hrozbu a jak na ni odpovídáme — ať se v obhajobě dá ukázat
rozhodnutí, ne jen kód.

## 1. Co má cenu

| Hodnota | Proč |
|---|---|
| hesla uživatelů | lidé je používají i jinde |
| tajemství počítačových účtů | kdo ho má, vydává se za počítač |
| session a CSRF token správce | kdo ho má, je správce domény |
| privátní klíč CA | kdo ho má, podvrhne celý server |
| obsah databáze | jména, skupiny, struktura školy |
| DNS odpovědi | kdo je ovládá, přesměruje klienty |

## 2. Kdo nám může ublížit

| Útočník | Co může | Co proti tomu máme |
|---|---|---|
| **uživatel ve školní síti** | zkoušet hesla, číst API | zamykání účtů, omezení rychlosti podle IP, oddělené správní rozhraní |
| **odposlech v síti** | čte provoz | TLS 1.2+ na doménovém API; správa jen na loopbacku nebo SSH tunelem |
| **podvržený server (MITM)** | vydávat se za řadič | připnutý otisk CA, ověřený člověkem při připojení |
| **podvržený klient** | hlásit se cizím jménem, zapsat cizí IP do DNS | tajemství počítače, server bere skutečnou IP spojení |
| **škodlivá webová stránka** | poslat požadavek do naší správy z prohlížeče správce | CSRF token v hlavičce, kontrola `Origin`, `SameSite=Strict`, poslouchá jen loopback |
| **kdo se dostane k souborům** | přečíst databázi | hesla jen jako Argon2id; práva 0600 / ACL; klíč CA zvlášť |
| **zvědavý správce (my sami)** | omylem zalogovat heslo | typ `Tajne` s cenzurovaným `Debug` |

Mimo rozsah: útočník s rootem na serveru, útok na hardware, DoS ze
sítě většího rozsahu, chyby v samotném Rustu či v jádru OS.

## 3. Hranice důvěry

```
┌─ veřejná síť ──────────────────────────────────────────┐
│  nedůvěryhodné. Jen TLS port 8443 a DNS port 53.      │
│                                                        │
│  ┌─ ad-client na stanici ───────────────────────────┐  │
│  │ polodůvěryhodný: zná tajemství svého počítače,   │  │
│  │ ale všechno, co tvrdí (jméno OS, IP), je jen     │  │
│  │ tvrzení. Server to bere jako vstup, ne jako      │  │
│  │ pravdu, a escapuje to při zobrazení.             │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
┌─ localhost serveru ────────────────────────────────────┐
│  důvěryhodnější, ale ne slepě: správní API chce        │
│  přihlášení i CSRF, i když poslouchá jen tady.         │
└────────────────────────────────────────────────────────┘
```

Server nikdy nevěří klientovi, že je ve správné OU, že má právo, nebo že
zadaná IP je jeho. Klient nikdy nevěří serveru, že poslaná zásada je
platná — znovu ji zvaliduje.

## 4. Konkrétní rozhodnutí a proč

### Hesla: Argon2id, m = 19 MiB, t = 2, p = 1

Doporučení OWASP. Argon2id odolává jak útoku s málo pamětí (GPU), tak
útoku s měřením času. Sůl je 16 náhodných bajtů na každé heslo, takže
dvě stejná hesla mají jiný haš a rainbow tabulky nefungují. Ukládá se
PHC řetězec včetně parametrů, takže je půjde v budoucnu zvýšit a staré
hashe se dopočítají při přihlášení (`potrebuje_prepocet`).

Hesla se neposílají nikam zpět — ani správci, ani do UI. Správce může
heslo jen nastavit nové.

### Tokeny: 256 bitů náhody, uložené jako SHA-256

Tokeny generujeme my, mají dost entropie, takže se nedají hádat.
Argon2 by u nich byl zbytečně drahý na každý požadavek. Hašujeme je
proto, že kdyby někdo přečetl databázi, nesmí se stát platným správcem.

Porovnávání vždy v konstantním čase (`subtle::ConstantTimeEq`), nikdy
`==` — porovnání po bajtech prozrazuje délku shodné předpony.

### Připnutý otisk CA, ne otisk serveru

Vlastní CA podepíše certifikát serveru. Klient si pamatuje otisk **CA**.

- Kdyby si pamatoval otisk serveru, rozbila by se obnova certifikátu.
- Kdyby nic nepřipínal, podvržený server s vlastním certifikátem by
  prošel — vlastní CA není v systémovém úložišti, takže by se musela
  ověřovat jinak, a „tak to nekontrolujme“ je špatná odpověď.

Otisk přenáší člověk (zobrazí se ve webové správě, zadá se klientovi).
To je ruční krok, ale je to to samé, co se dělá u SSH při prvním
připojení — a je jediný, který nejde obejít odposlechem.

### Zásady jsou data, ne příkazy

Nejnebezpečnější věc, kterou by takový systém mohl umět, je „server
řekne klientovi, co spustit“. Skutečné GPO to umí (startup scripts),
my ne a nebudeme.

Technicky to drží tři věci:
1. `PolicySet` je uzavřený výčet typů — není kam příkaz napsat.
2. `deny_unknown_fields` na všech strukturách — co server pošle navíc,
   klient odmítne při parsování. Test `neznama_polozka_v_json_se_odmitne`
   to kontroluje přímo na `{"...","run_command":"rm -rf /"}`.
3. Klient po přijetí znovu validuje rozsahy a délky.

### Tapeta: obsah se ověřuje, SVG je zakázané

Obrázek se stahuje zvlášť a klient kontroluje SHA-256 proti hodnotě
v zásadě. Formát se pozná podle magických bajtů, ne podle přípony nebo
`Content-Type` — ty si určuje ten, kdo soubor posílá.

SVG je zakázané, i když je to „jen obrázek“: je to XML, které umí
obsahovat skript, a nechat ho zobrazit je stejné jako spustit cizí kód.

### Uvítací zpráva: čistý text bez řídicích znaků

Text od správce se zobrazuje v klientovi (i v terminálu). Řídicí znaky
kromě `\n` a tabulátoru odmítáme — ANSI escape sekvence umí přepsat
výpis a podvrhnout uživateli cizí text. V HTML se text escapuje.

### Vyjmenování uživatelů

Při neexistujícím účtu se stejně počítá Argon2id nad náhodným hašem,
takže odpověď trvá stejně dlouho. Odpověď je vždy `invalid_credentials`,
nikdy „uživatel neexistuje“.

### Správní rozhraní jen na loopbacku

Nejlepší ochrana rozhraní je, že tam zvenčí nic neposlouchá. Pro
vzdálenou správu se používá SSH tunel — šifrování a autentizaci řeší
SSH, které je na to napsané lépe než my.

TLS se tam dá zapnout (`[admin] tls = true`) a při vazbě na jinou než
loopback adresu je **povinné** — server s `tls = false` na `0.0.0.0`
odmítne nastartovat, aby heslo správce nemohlo omylem letět sítí
v čistém textu.

I tak má správní API přihlášení a CSRF: na serveru může být víc
uživatelů a chyba v prohlížeči se stává.

### CSRF: token v hlavičce + kontrola Origin

Session cookie má `HttpOnly` (nedostane se k ní skript), `SameSite=Strict`
(nepošle se z cizí stránky) a `Path=/`. Měnící požadavky navíc potřebují
`X-AD-CSRF`, který zná jen naše stránka — cizí stránka ho nepřečte
(brání tomu Same-Origin Policy) a hlavičku si při jednoduchém požadavku
nepřidá. Server kontroluje i `Origin`.

### Webové rozhraní: nic se nenačítá zvenčí

Rozhraní je celé v binárce a hlavička `Content-Security-Policy` je
`default-src 'self'` bez `unsafe-inline` a `unsafe-eval`. Prohlížeč tedy
nenačte skript ani styl odjinud a nespustí nic vloženého do stránky.
K tomu `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`
(stránka nejde vložit do rámce, takže ani clickjacking) a
`Referrer-Policy: no-referrer`.

Do stránky se text vkládá výhradně přes `textContent`. Nejnebezpečnější
údaj je jméno operačního systému, které o sobě hlásí klient — je to
cizí text a kdyby se vložil jako HTML, stačilo by připojit počítač se
jménem systému `<img onerror=…>` a skript by běžel v prohlížeči správce.
Zákaz `innerHTML` hlídá pravidlo v `eslint.config.mjs`.

### SQL

Všechny dotazy jsou parametrizované (`rusqlite` `?1`, `?2`). Jména se
nikdy nelepí do SQL textu. `foreign_keys = ON`, takže smazání OU
nenechá v databázi osiřelé objekty.

### Vstupy

Validace je v `ad-core::names` a `ad-core::policy`, ne v HTTP vrstvě —
aby se nedala obejít jinou cestou (CLI, import, interní volání). Délky
jsou zastropované všude: jména, popisy, heslo (256 bajtů), tapeta
(8 MiB), stránka seznamu (500 záznamů).

Jméno domény `.local` je zakázané úplně, protože koliduje s mDNS
(Avahi/Bonjour) a rozbila by objevování služeb v síti.

### Nic skrytého

- Server ani klient nic neinstaluje bez výslovného souhlasu
  (`consent: true` v požadavku, potvrzení v průvodci).
- Klient před změnou DNS zálohuje původní stav do souboru a při
  `leave` ho vrátí. Záloha je čitelný JSON, dá se vrátit i ručně.
- Všechny soubory jsou ve dvou adresářích, odinstalace je jejich smazání
  a odebrání služby. Žádné zápisy do registru mimo klíč služby, žádné
  ovladače, žádná automatická aktualizace.
- Žádná telemetrie, žádné odesílání dat ven.

## 5. Co víme, že je slabé

Čestně:

- **Jedno zařízení, žádná replikace.** Když server spadne, doména
  nefunguje. Skutečné AD má víc řadičů.
- **Otisk se přenáší člověkem.** Když ho správce opíše špatně nebo
  přeskočí (`--insecure` neexistuje, ale lidé si poradí), ochrana padá.
- **Není dvoufaktor.** Heslo správce je jediná překážka k ovládnutí
  domény.
- **Tapeta a uvítací zpráva se v klientovi jen zobrazí / nastaví;**
  nic nevynucujeme v systému, protože nemáme PAM ani Credential Provider.
  Uživatel si tapetu může změnit zpátky. `lock_user_change` je proto
  jen informace, ne vynucení — a je to tak napsané i v UI.
- **DoS neřešíme.** Omezení rychlosti brání hádání hesel, ne zahlcení.
- **Logy nejsou podepsané.** Kdo má root na serveru, může je přepsat.
- **Vlastní kryptografie žádná** — a to je dobře. TLS dělá `rustls`,
  hašování `argon2`, náhodu OS. Nikde si nepíšeme vlastní šifru.

## 6. Kontrolní seznam před obhajobou

- [ ] `cargo test` prochází
- [ ] `cargo clippy` bez varování
- [ ] v logu po celém testu není žádné heslo (`grep -i heslo`, `grep` na
      skutečné testovací heslo)
- [ ] `/api/v1/hello` neprozrazuje nic citlivého
- [ ] měnící požadavek bez `X-AD-CSRF` skončí `403`
- [ ] požadavek na správní API z jiné adresy než loopback se nepřipojí
- [ ] `ad-client leave` vrátí `/etc/resolv.conf` do původního stavu
- [ ] zásada s neznámým polem se odmítne
- [ ] tapeta s rozbitým součtem se zahodí
- [ ] odinstalace nenechá na stroji nic kromě logů
