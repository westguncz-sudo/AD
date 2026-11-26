# Instalace krok za krokem

Návod od staženého souboru k funkční doméně. Píšu ho tak, jak bych to
dělal sám — včetně míst, kde se to obvykle zasekne.

Na konci je [řešení potíží](#8-řešení-potíží) a [odinstalace](#7-odinstalace).

---

## 0. Co budeš potřebovat

| | |
|---|---|
| **Server** | Debian 13 (bez grafiky stačí) nebo Windows Server. Pevná IP adresa. |
| **Klient** | Windows 11, Debian nebo Void Linux. |
| **Síť** | Virtuálky se musí navzájem vidět. Ve VirtualBoxu *Host-only adapter*. |
| **Soubory** | `ad-server-linux` + `ad-client-linux`, nebo `ad-server.exe` + `ad-client.exe` |

V celém návodu používám tyhle hodnoty — nahraď si je svými:

| Co | Hodnota |
|---|---|
| adresa serveru | `192.168.56.10` |
| jméno serveru | `DC01` |
| doména | `skola.internal` |
| adresa klienta | `192.168.56.20` |

> **Doménu nepojmenovávej s koncovkou `.local`.** Koliduje s mDNS
> (Avahi, Bonjour) a rozbila by objevování služeb v síti. Server ji
> odmítne. Používej `.internal`.

**Než začneš:** udělej si ve virtuálce snímek (snapshot) čistého stavu.
Když něco pokazíš, vrátíš se k němu a zkusíš to znovu. Bez snímku se
test nedá zopakovat.

---

## 1. Ověř stažené soubory

Kontrolní součet pozná, že se soubor cestou nezměnil.

```bash
# Linux
sha256sum -c SHA256SUMS

# Windows (PowerShell)
Get-FileHash .\ad-server.exe -Algorithm SHA256
```

Když součet nesedí, soubor nespouštěj a stáhni ho znovu.

---

## 2. Server na Debianu

### 2.1 Pevná IP adresa a jméno

Doména stojí na tom, že server má pořád stejnou adresu. S DHCP by
klienti po restartu přestali server najít.

```bash
sudo hostnamectl set-hostname dc01

# zjisti si jméno síťové karty pro host-only síť (bývá enp0s8)
ip -4 a
```

Debian po čisté instalaci používá `/etc/network/interfaces`:

```bash
sudo tee -a /etc/network/interfaces >/dev/null <<'EOF'

auto enp0s8
iface enp0s8 inet static
    address 192.168.56.10
    netmask 255.255.255.0
EOF

sudo ifup enp0s8
ip -4 addr show enp0s8    # musí ukázat 192.168.56.10
```

Když máš NetworkManager (třeba na desktopové instalaci), udělej to
raději přes `nmtui` — míchat dva správce sítě najednou dělá potíže.

### 2.2 Uvolni port 53

Na Debianu port 53 obvykle drží `systemd-resolved`. Náš DNS server se
na něj jinak nedostane.

```bash
# co na portu 53 sedí
sudo ss -tulpn | grep ':53'

# ZAPIŠ SI, jaký DNS server teď stroj používá — bude se hodit
resolvectl status | grep 'DNS Server'
```

Teď `systemd-resolved` vypni a místo něj napiš do `resolv.conf`
**tu adresu, kterou jsi si právě zapsal** (často je to brána
virtuální sítě, třeba `10.0.2.3` nebo `192.168.1.1`):

```bash
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo "nameserver 10.0.2.3" | sudo tee /etc/resolv.conf   # svou adresu!
```

> **Proč ne rovnou `127.0.0.1`?** Náš DNS server ještě neběží — stroj
> by přestal vidět do internetu. Navíc průvodce povýšením si z
> `resolv.conf` sám přečte, kam má přeposílat dotazy, a loopback
> adresu z toho vynechá. Na `127.0.0.1` přepneme až v kroku 2.8,
> když bude co odpovídat.

### 2.3 Nainstaluj program

```bash
chmod +x ad-server-linux
sudo cp ad-server-linux /usr/local/bin/ad-server
```

> **Důležité:** instalaci služby spouštěj až z `/usr/local/bin/`.
> Služba si zapamatuje cestu, ze které jsi ji instaloval — kdybys
> spustil `./ad-server-linux install-service` ve složce Stažené,
> ukazovala by služba tam.

### 2.4 Nainstaluj službu

Nejdřív se podívej, co to udělá. Bez `--yes` se nic nestane:

```bash
sudo ad-server install-service
```

Vypíše, které soubory vzniknou, jaký uživatel se vytvoří a jaké
oprávnění dostane. Když s tím souhlasíš:

```bash
sudo ad-server install-service --yes
sudo ad-server service-status
```

Co se stalo:

* vznikl systémový uživatel `ad-server` (server neběží pod rootem),
* vznikla jednotka `/etc/systemd/system/ad-server.service`,
* data budou v `/var/lib/ad-server/`, konfigurace v `/etc/ad-server/config.toml`,
* služba se zapnula a běží.

### 2.5 Přihlas se do správy

Správa poslouchá **jen na `127.0.0.1:8080`**. To je schválně — z sítě
se na ni nedá dosáhnout. Na server bez grafiky se dostaneš tunelem ze
svého počítače:

```bash
ssh -L 8080:127.0.0.1:8080 uzivatel@192.168.56.10
```

Nech okno otevřené a na **svém** počítači otevři `http://127.0.0.1:8080`.

Přihlašovací obrazovka chce jednorázový token. Vypsal se při prvním
spuštění a je i v souboru:

```bash
sudo cat /var/lib/ad-server/setup-token.txt
```

Token platí jen dokud nevytvoříš doménu.

### 2.6 Přidej role a vytvoř doménu

V rozhraní jdi na **Spravovat → Přidat role a funkce**:

1. proklikej se k **Role serveru**,
2. zatrhni **Doménové služby** i **DNS server**,
3. v **Potvrzení** zatrhni souhlas a dej **Instalovat**.

Pak se nahoře objeví vlaječka s upozorněním **„Povýšit server na řadič
domény"**. Klikni na ni a projdi průvodce:

| Krok | Co vyplnit |
|---|---|
| Konfigurace nasazení | jméno domény `skola.internal` |
| Možnosti řadiče domény | jméno `DC01`, IP `192.168.56.10`, heslo správce |
| Možnosti DNS | reverzní zóna zapnutá, přeposílání např. `1.1.1.1` |
| Zkontrolovat možnosti | přečti si souhrn |
| Kontrola předpokladů | všechno musí být zeleně, pak **Nainstalovat** |

Heslo správce si zapamatuj. Je uložené jako Argon2id a zpátky se
přečíst nedá — kdybys ho zapomněl, jediná cesta je zrušit doménu.

Po dokončení se odhlas a přihlas znovu jako `administrator` s tím
heslem. Jednorázový token už neplatí.

### 2.7 Opiš si otisk certifikátu

V rozhraní: **Místní server → Certifikační autorita domény**. Je tam
i hotový příkaz pro klienta. Otisk je jediná věc, podle které klient
pozná, že mluví se správným serverem.

### 2.8 Přepni server na vlastní DNS

Teď už vlastní DNS server běží, takže se na něj server může spolehnout
sám:

```bash
sudo tee /etc/resolv.conf >/dev/null <<'EOF'
search skola.internal
nameserver 127.0.0.1
EOF

# ověř, že odpovídá na vlastní doménu i na svět
dig +short dc01.skola.internal
dig +short seznam.cz
```

Když druhý příkaz nic nevrátí, nemáš nastavené přeposílání — doplň ho
ve správě v **Správce DNS → Přeposílání dotazů**.

### 2.9 Pusť server do sítě

Debian po čisté instalaci žádný firewall zapnutý nemá a tenhle krok
můžeš přeskočit. Pokud sis `ufw` zapnul:

```bash
sudo ufw allow from 192.168.56.0/24 to any port 8443 proto tcp
sudo ufw allow from 192.168.56.0/24 to any port 53
```

Port 8080 (správa) **neotvírej** — poslouchá jen na loopbacku
a vystavovat ho nemá smysl.

### 2.10 Vytvoř uživatele

V rozhraní **Nástroje → Uživatelé a počítače**:

1. **Nová OU** — třeba `Zaci`,
2. vyber ji vlevo a dej **Nový uživatel**,
3. **Nástroje → Správa zásad skupiny** → **Nová zásada** (pravidla
   hesel, uvítací zpráva, tapeta) a **Připojit k** doméně nebo OU.

---

## 3. Server na Windows Serveru

Kroky jsou stejné, liší se jen příkazy. Příkazový řádek spusť
**jako správce**.

```powershell
# pevná adresa
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.10 -PrefixLength 24
Rename-Computer -NewName DC01 -Restart

# instalace
mkdir C:\ad
copy ad-server.exe C:\ad\
cd C:\ad
.\ad-server.exe install-service          # jen ukáže, co udělá
.\ad-server.exe install-service --yes

# porty pro klienty
New-NetFirewallRule -DisplayName "AD doménové API" -Direction Inbound `
  -Protocol TCP -LocalPort 8443 -Action Allow
New-NetFirewallRule -DisplayName "AD DNS" -Direction Inbound `
  -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD DNS TCP" -Direction Inbound `
  -Protocol TCP -LocalPort 53 -Action Allow
```

Jednorázový token je v `C:\ProgramData\ad-server\setup-token.txt`.
Správu otevři přímo na serveru v prohlížeči na `http://127.0.0.1:8080`.

> **Pozor:** pokud na Windows Serveru běží role DNS od Microsoftu,
> drží port 53 a náš server se nespustí. Vypni ji, nebo použij jiný
> port v `C:\ProgramData\ad-server\config.toml`.

---

## 4. Klient na Debianu nebo Void Linuxu

```bash
chmod +x ad-client-linux
sudo cp ad-client-linux /usr/local/bin/ad-client
```

Ověř, že server je vidět:

```bash
ping -c2 192.168.56.10
```

Připoj počítač do domény. Otisk opiš z kroku 2.7:

```bash
sudo ad-client join --server 192.168.56.10 \
     --fingerprint A1:B2:C3:...:FF \
     --admin administrator
```

Program se zeptá na heslo správce. Pozor na pořadí: **otisk se ověří
dřív, než se heslo odešle.** Když otisk nesedí, neodejde nic.

Co se stane:

* vznikne počítačový účet na serveru,
* uloží se stav do `/var/lib/ad-client/` (práva jen pro roota),
* zazálohuje se `/etc/resolv.conf` a DNS se přepne na server,
* stáhnou se zásady.

Vyzkoušej:

```bash
ad-client status                      # stav připojení, DNS, zásady
ad-client logon --user jan.novak      # přihlášení v programu
ad-client passwd --user jan.novak     # změna hesla
ad-client policy --apply              # znovu stáhnout a použít zásady
```

> **Void Linux:** pokud chceš na klientovi používat `setcap` nebo
> instalovat server, přidej `sudo xbps-install libcap shadow`.
> Pro samotného klienta to potřeba není.

---

## 5. Klient na Windows

Příkazový řádek **jako správce**:

```powershell
mkdir C:\ad
copy ad-client.exe C:\ad\
cd C:\ad

.\ad-client.exe join --server 192.168.56.10 `
  --fingerprint A1:B2:C3:...:FF --admin administrator

.\ad-client.exe status
.\ad-client.exe logon --user jan.novak
```

Stav se ukládá do `C:\ProgramData\ad-client\`.

> **Co tenhle program nedělá:** nezasahuje do přihlašování do Windows.
> Doménovým účtem se přihlásíš **v tomhle programu**, ne na
> přihlašovací obrazovce. Je to záměr — špatně napsaný Credential
> Provider dokáže zamknout přihlášení do celého systému.

---

## 6. Ověř, že to funguje

### DNS

Z klienta (na Debianu `sudo apt install bind9-dnsutils`,
na Void `sudo xbps-install bind-utils`):

```bash
dig @192.168.56.10 dc01.skola.internal A       # adresa řadiče
dig @192.168.56.10 -x 192.168.56.10            # zpětný překlad
dig @192.168.56.10 _ad._tcp.skola.internal SRV # tímhle si klient najde server
dig @192.168.56.10 seznam.cz A                 # přeposlání dál
```

Na Windows: `nslookup dc01.skola.internal 192.168.56.10`

Po připojení klienta do domény už `@192.168.56.10` psát nemusíš —
klient má server nastavený jako svůj DNS, takže stačí
`dig dc01.skola.internal`.

### Doména

Ve správě serveru na přehledu musíš vidět připojený počítač
(**Počítače v doméně → 1**) a v **Uživatelé a počítače → Computers**
jeho účet.

### Zásady

Změň v zásadě uvítací zprávu, pak na klientovi:

```bash
ad-client logon --user jan.novak
```

Nová zpráva se musí objevit.

---

## 7. Odinstalace

Nic po sobě nenechává nic skrytého. Odinstalace je smazání dvou věcí:
služby a datového adresáře.

### Klient

```bash
sudo ad-client leave          # odpojí z domény a vrátí původní DNS
sudo rm /usr/local/bin/ad-client
```

`leave` vrátí `/etc/resolv.conf` přesně do stavu před připojením —
včetně toho, jestli to byl symbolický odkaz. Když server neodpovídá,
přidej `--force`; počítačový účet pak smaž ve správě ručně.

### Server

```bash
sudo ad-server uninstall-service          # ukáže, co udělá
sudo ad-server uninstall-service --yes    # odebere službu, data nechá
sudo ad-server uninstall-service --yes --purge   # i s daty domény

sudo rm /usr/local/bin/ad-server
sudo userdel ad-server        # systémový uživatel se nemaže sám
```

Na Debianu nezapomeň vrátit DNS:

```bash
sudo systemctl enable --now systemd-resolved
```

Na Windows totéž pomocí `ad-server.exe uninstall-service --yes`.

---

## 8. Řešení potíží

| Příznak | Co s tím |
|---|---|
| `ad-server install-service` hlásí „nepoznal jsem správce služeb" | Stroj nemá systemd ani runit. Spusť server ručně: `ad-server run`. |
| Služba se nespustí | `journalctl -u ad-server -n 50` (Debian), `tail /var/lib/ad-server/logs/current` (Void). |
| V přehledu je „DNS server neposlouchá" | Port 53 drží něco jiného. `sudo ss -tulpn \| grep ':53'`. |
| Kontrola předpokladů hlásí „IP adresa řadiče na tomto stroji není" | Zadal jsi adresu, kterou stroj nemá. Ověř `ip a`. |
| Správa v prohlížeči nenaběhne | Běží SSH tunel? Zkus na serveru `curl -s http://127.0.0.1:8080/ \| head -3`. |
| Zapomenutý jednorázový token | `sudo ad-server setup-token` vytvoří nový (jen dokud doména není). |
| Zapomenuté heslo správce | Přečíst se nedá. Jediná cesta je zrušit doménu a vytvořit ji znovu. |
| Klient: „otisk certifikační autority nesouhlasí" | Překlep v otisku, nebo se za server někdo vydává. Otisk ověř ve správě. |
| Klient: „nelze se připojit na …:8443" | Firewall na serveru, nebo špatná adresa. Zkus `ping` a `ss -tulpn \| grep 8443`. |
| Klient: „počítač už je v doméně" | `sudo ad-client leave`, pak znovu `join`. |
| Klient: heslo nejde zadat jako přepínač | Je to schválně — bylo by vidět v `ps`. Program se zeptá sám. |
| Po `leave` nefunguje internet | Zkontroluj `/etc/resolv.conf`. Záloha byla v `/var/lib/ad-client/dns-backup.json`. |

### Když potřebuješ začít znovu

```bash
# klient
sudo ad-client leave --force
sudo rm -rf /var/lib/ad-client

# server
sudo ad-server uninstall-service --yes --purge
sudo rm -rf /var/lib/ad-server /etc/ad-server
```

Pak se vrať k bodu 2.3.

---

## 9. Kam dál

| Dokument | O čem je |
|---|---|
| [`README.md`](../README.md) | přehled projektu a testy jednotlivých fází |
| [`ARCHITEKTURA.md`](ARCHITEKTURA.md) | jak to uvnitř funguje a proč zrovna takhle |
| [`PROTOKOL.md`](PROTOKOL.md) | protokol mezi klientem a serverem |
| [`BEZPECNOST.md`](BEZPECNOST.md) | model hrozeb, rozhodnutí a známé slabiny |
| [`TESTOVANI.md`](TESTOVANI.md) | příprava virtuálek pro testování |
