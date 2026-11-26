# Instalace krok za krokem

Návod od staženého souboru k funkční doméně. Píšu ho tak, jak bych to
dělal sám — včetně míst, kde se to obvykle zasekne.

Na konci je [řešení potíží](#9-řešení-potíží) a [odinstalace](#8-odinstalace).

---

## 0. Co budeš potřebovat

| | |
|---|---|
| **Server** | Debian 13 (bez grafiky stačí), Void Linux nebo Windows Server. Pevná IP adresa. |
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

Podle toho, co máš, pokračuj rovnou do správné kapitoly:

| Server běží na | Kapitola |
|---|---|
| Debian (a jiné se systemd) | [2. Server na Debianu](#2-server-na-debianu) |
| Windows Server | [3. Server na Windows Serveru](#3-server-na-windows-serveru) |
| Void Linux | [4. Server na Void Linuxu](#4-server-na-void-linuxu) |

| Klient běží na | Kapitola |
|---|---|
| Debian nebo Void | [5. Klient na Linuxu](#5-klient-na-linuxu-debian-i-void) |
| Windows | [6. Klient na Windows](#6-klient-na-windows) |

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

Postup je stejný jako na Debianu, liší se příkazy. **Všechno spouštěj
v PowerShellu otevřeném jako správce** (pravým tlačítkem na Start →
*Terminál (správce)*).

### 3.1 Odblokuj stažený soubor

Windows označí soubory stažené z internetu a SmartScreen je nepustí
spustit. Tenhle program není podepsaný žádným certifikátem, takže se
to stane.

```powershell
cd C:\ad
Unblock-File .\ad-server.exe
Get-FileHash .\ad-server.exe -Algorithm SHA256   # porovnej s SHA256SUMS
```

Kdyby přesto vyskočilo okno *Windows ochránil váš počítač*, klikni na
**Další informace → Přesto spustit**. Pokud soubor spolkne Defender,
přidej si v *Zabezpečení Windows → Ochrana před viry → Spravovat
nastavení → Vyloučení* složku `C:\ad`.

> Je to nepříjemné, ale je to správné chování Windows: neznámý
> nepodepsaný program z internetu si tuhle nedůvěru zaslouží. Proto
> jsou ke stažení kontrolní součty — ověř si je.

### 3.2 Pevná IP adresa a jméno

```powershell
Get-NetAdapter                      # zjisti jméno karty
New-NetIPAddress -InterfaceAlias "Ethernet" `
  -IPAddress 192.168.56.10 -PrefixLength 24

Rename-Computer -NewName DC01 -Restart
```

### 3.3 Uvolni port 53

```powershell
Get-NetTCPConnection -LocalPort 53 -ErrorAction SilentlyContinue
Get-Process -Id (Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue).OwningProcess
```

Pokud má server nainstalovanou **roli DNS od Microsoftu**, drží port 53
a náš server se nespustí. Buď ji odeber:

```powershell
Uninstall-WindowsFeature -Name DNS
```

…nebo nech naši službu poslouchat jinde. Po instalaci služby uprav
`C:\ProgramData\ad-server\config.toml`:

```toml
[dns]
bind = "0.0.0.0:5353"
```

### 3.4 Nainstaluj službu

```powershell
mkdir C:\ad -Force
copy ad-server.exe C:\ad\
cd C:\ad

.\ad-server.exe install-service            # jen ukáže, co udělá
.\ad-server.exe install-service --yes
.\ad-server.exe service-status
```

Co vznikne:

| Co | Kde |
|---|---|
| služba | `ADServer` (uvidíš ji v `services.msc`) |
| data | `C:\ProgramData\ad-server\` |
| konfigurace | `C:\ProgramData\ad-server\config.toml` |
| log | `C:\ProgramData\ad-server\logs\ad-server.log` |

`C:\ProgramData` je skrytá složka — do Průzkumníka ji napiš ručně,
nebo použij `explorer C:\ProgramData\ad-server`.

Služba běží pod účtem `LocalSystem`. To je víc oprávnění, než by bylo
potřeba, ale vlastní servisní účet by znamenal řešit jeho heslo
a oprávnění ke složkám. Je to vědomé zjednodušení.

Ovládání služby:

```powershell
Get-Service ADServer
Restart-Service ADServer
Stop-Service ADServer
Get-Content C:\ProgramData\ad-server\logs\ad-server.log -Tail 30 -Wait
```

### 3.5 Otevři správu

Windows Server má grafiku, takže stačí na něm otevřít prohlížeč
a jít na `http://127.0.0.1:8080`. Žádný tunel není potřeba.

Jednorázový token:

```powershell
Get-Content C:\ProgramData\ad-server\setup-token.txt
```

Dál pokračuj stejně jako na Debianu — [kroky 2.6 a 2.7](#26-přidej-role-a-vytvoř-doménu):
přidat role, povýšit na řadič domény, opsat si otisk.

### 3.6 Pusť server do sítě

```powershell
New-NetFirewallRule -DisplayName "AD doménové API" -Direction Inbound `
  -Protocol TCP -LocalPort 8443 -Action Allow
New-NetFirewallRule -DisplayName "AD DNS (UDP)" -Direction Inbound `
  -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "AD DNS (TCP)" -Direction Inbound `
  -Protocol TCP -LocalPort 53 -Action Allow
```

Port 8080 **neotvírej** — správa poslouchá jen na loopbacku.

### 3.7 Přepni server na vlastní DNS

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Resolve-DnsName dc01.skola.internal
Resolve-DnsName seznam.cz        # ověří přeposílání
```

Vrátit zpět na DHCP: `Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses`

## 4. Server na Void Linuxu

Void nemá systemd — služby řídí **runit**. Instalátor to pozná sám
a místo jednotky vytvoří adresář služby. Postup je jinak stejný jako
na Debianu, liší se příkazy a jména balíčků.

> Binárka je staticky slinkovaná, takže funguje na glibc i musl
> variantě Voidu. Nic doinstalovávat kvůli ní nemusíš.

### 4.1 Doinstaluj, co instalátor potřebuje

```bash
sudo xbps-install -S            # aktualizace seznamu balíčků
sudo xbps-install -y libcap shadow bind-utils
```

| Balíček | K čemu |
|---|---|
| `libcap` | `setcap` — bez něj server nedosáhne na port 53 |
| `shadow` | `useradd` — vytvoření systémového uživatele |
| `bind-utils` | `dig` na ověření DNS (nepovinné, ale hodí se) |

`runit`, `chpst` i `svlogd` jsou ve Voidu od začátku.

### 4.2 Pevná IP adresa a jméno

Void používá `dhcpcd`. Statickou adresu mu nastavíš v jeho konfiguraci:

```bash
echo dc01 | sudo tee /etc/hostname
sudo hostname dc01

ip -4 a                          # zjisti jméno karty, bývá enp0s8

sudo tee -a /etc/dhcpcd.conf >/dev/null <<'EOF'

interface enp0s8
static ip_address=192.168.56.10/24
EOF

sudo sv restart dhcpcd
ip -4 addr show enp0s8           # musí ukázat 192.168.56.10
```

### 4.3 Ať ti dhcpcd nepřepisuje resolv.conf

Tohle je na Voidu nejčastější zádrhel: `dhcpcd` si `/etc/resolv.conf`
přepisuje po svém, takže by nastavení DNS po restartu zmizelo.

```bash
# zapiš si, co tam je teď — bude to forwarder
cat /etc/resolv.conf

# řekni dhcpcd, ať na resolv.conf nesahá
echo 'nohook resolv.conf' | sudo tee -a /etc/dhcpcd.conf
sudo sv restart dhcpcd
```

Soubor zatím **nech, jak je** — má v něm zůstat stávající DNS server.
Průvodce povýšením si z něj přečte, kam přeposílat dotazy, a na
`127.0.0.1` přepneme až v kroku 4.7.

### 4.4 Uvolni port 53

Void ve výchozím stavu nic na portu 53 nemá, takže tenhle krok bývá
prázdný. Ověř si to:

```bash
sudo ss -tulpn | grep ':53'      # nemělo by nic vypsat
```

Kdyby tam něco bylo (`dnsmasq`, `unbound`), vypni to:
`sudo rm /var/service/dnsmasq`

### 4.5 Nainstaluj službu

```bash
chmod +x ad-server-linux
sudo cp ad-server-linux /usr/local/bin/ad-server

sudo ad-server install-service          # jen ukáže, co udělá
sudo ad-server install-service --yes
sudo ad-server service-status
```

Co vznikne:

| Co | Kde |
|---|---|
| skript služby | `/etc/sv/ad-server/run` |
| skript logování | `/etc/sv/ad-server/log/run` |
| zapnutí služby | odkaz `/var/service/ad-server` |
| data | `/var/lib/ad-server/` |
| konfigurace | `/etc/ad-server/config.toml` |
| log | `/var/lib/ad-server/logs/current` |

Ovládání:

```bash
sudo sv status ad-server
sudo sv restart ad-server
sudo sv down ad-server
tail -f /var/lib/ad-server/logs/current
```

> **Rozdíl proti systemd:** runit shodí oprávnění dřív, než se program
> dostane k portu. Proto instalátor volá `setcap` přímo na binárku
> (`cap_net_bind_service=+ep /usr/local/bin/ad-server`). Když binárku
> později nahradíš novější verzí, **setcap se ztratí** — po každé
> aktualizaci ho nastav znovu:
>
> ```bash
> sudo setcap cap_net_bind_service=+ep /usr/local/bin/ad-server
> sudo sv restart ad-server
> ```

### 4.6 Správa, role a doména

Správa poslouchá jen na `127.0.0.1:8080`. Ze svého počítače:

```bash
ssh -L 8080:127.0.0.1:8080 uzivatel@192.168.56.10
```

Jednorázový token: `sudo cat /var/lib/ad-server/setup-token.txt`

Dál postupuj stejně jako na Debianu —
[Přidej role a vytvoř doménu](#26-přidej-role-a-vytvoř-doménu)
a [opiš si otisk](#27-opiš-si-otisk-certifikátu).

### 4.7 Přepni server na vlastní DNS

```bash
sudo tee /etc/resolv.conf >/dev/null <<'EOF'
search skola.internal
nameserver 127.0.0.1
EOF

dig +short dc01.skola.internal   # vlastní doména
dig +short seznam.cz             # přeposílání dál
```

Díky `nohook resolv.conf` z kroku 4.3 to vydrží i po restartu.

### 4.8 Ověř, že to přežije restart

Tohle si na Voidu opravdu vyzkoušej — je to celý smysl toho, že server
běží jako služba:

```bash
sudo reboot
# po nastartování:
sudo sv status ad-server         # run: ad-server: (pid …) …s
dig +short dc01.skola.internal
```

## 5. Klient na Linuxu (Debian i Void)

Klient je jedna a tatáž binárka pro obě distribuce — je staticky
slinkovaná, takže nepotřebuje žádný balíček navíc.

```bash
chmod +x ad-client-linux
sudo cp ad-client-linux /usr/local/bin/ad-client
```

Na Voidu si přidej jen nástroje na ověřování (nepovinné):

```bash
sudo xbps-install -S bind-utils
```

A pokud na klientovi používáš `dhcpcd`, řekni mu, ať nesahá na
`resolv.conf` — jinak by po restartu přepsal nastavení, které tam
`ad-client` zapsal:

```bash
echo 'nohook resolv.conf' | sudo tee -a /etc/dhcpcd.conf
sudo sv restart dhcpcd
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

Klient na Voidu žádnou službu neinstaluje — je to program na
vyžádání, spouštíš ho, když ho potřebuješ.

---

## 6. Klient na Windows

Zase **PowerShell jako správce** — klient mění nastavení DNS a zapisuje
do `C:\ProgramData`.

```powershell
mkdir C:\ad -Force
copy ad-client.exe C:\ad\
cd C:\ad
Unblock-File .\ad-client.exe
```

Ověř, že na server vidíš:

```powershell
Test-NetConnection 192.168.56.10 -Port 8443    # TcpTestSucceeded : True
```

Připojení do domény (otisk opiš z kroku 3.5 / 2.7):

```powershell
.\ad-client.exe join --server 192.168.56.10 `
  --fingerprint A1:B2:C3:...:FF --admin administrator
```

Program se zeptá na heslo správce. Na Windows **nejde schovat psaní**,
takže heslo uvidíš — když ti to vadí, pošli ho vstupem:

```powershell
"Heslo-spravce" | .\ad-client.exe join --server 192.168.56.10 `
  --fingerprint A1:B2:...:FF --admin administrator --password-stdin
```

Dál:

```powershell
.\ad-client.exe status
.\ad-client.exe logon --user jan.novak
.\ad-client.exe passwd --user jan.novak
.\ad-client.exe policy --apply
.\ad-client.exe leave          # odpojení a návrat DNS
```

Stav se ukládá do `C:\ProgramData\ad-client\`, původní nastavení DNS
do `dns-backup.json` tamtéž.

Co klient na Windows mění:

| Co | Jak |
|---|---|
| DNS na síťových kartách | `Set-DnsClientServerAddress` (přes PowerShell) |
| tapeta | `SystemParametersInfo` + klíče v `HKCU\Control Panel\Desktop` |

> **Co tenhle program nedělá:** nezasahuje do přihlašování do Windows.
> Doménovým účtem se přihlásíš **v tomhle programu**, ne na
> přihlašovací obrazovce. Je to záměr — špatně napsaný Credential
> Provider dokáže zamknout přihlášení do celého systému.
>
> Z toho plyne i to, že tapeta se nastaví uživateli, který příkaz
> spustil, a volba „uživatel ji nemá měnit" je jen informace.

## 7. Ověř, že to funguje

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

## 8. Odinstalace

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

Na Voidu smaž řádek `nohook resolv.conf` z `/etc/dhcpcd.conf`
a restartuj `sudo sv restart dhcpcd` — resolv.conf si pak dhcpcd
spraví sám.

### Na Windows

```powershell
# klient
.\ad-client.exe leave
Remove-Item C:\ad\ad-client.exe

# server
.\ad-server.exe uninstall-service --yes            # data nechá
.\ad-server.exe uninstall-service --yes --purge    # i s daty domény

# pravidla firewallu
Remove-NetFirewallRule -DisplayName "AD doménové API","AD DNS (UDP)","AD DNS (TCP)"

# DNS zpátky na DHCP
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ResetServerAddresses
```

Po odinstalaci v systému nezůstane nic kromě složky `C:\ad`
s binárkami, kterou smažeš ručně.

---

## 9. Řešení potíží

| Příznak | Co s tím |
|---|---|
| `ad-server install-service` hlásí „nepoznal jsem správce služeb" | Stroj nemá systemd ani runit. Spusť server ručně: `ad-server run`. |
| Služba se nespustí | `journalctl -u ad-server -n 50` (Debian), `tail /var/lib/ad-server/logs/current` (Void). |
| V přehledu je „DNS server neposlouchá" | Port 53 drží něco jiného. `sudo ss -tulpn \| grep ':53'`. |
| Kontrola předpokladů hlásí „na port 53 se nedá navázat" | Dvě možné příčiny. Buď port drží cizí DNS (`sudo ss -tulpn \| grep ':53'`, pak kapitola 2.2), nebo server neběží jako služba ani jako root a na porty pod 1024 nemá právo: `sudo setcap cap_net_bind_service=+ep /usr/local/bin/ad-server`. Nouzově jde v `config.toml` nastavit `[dns] bind = "0.0.0.0:5353"`. |
| Kontrola předpokladů hlásí „IP adresa řadiče na tomto stroji není" | Zadal jsi adresu, kterou stroj nemá. Ověř `ip a`. |
| Správa v prohlížeči nenaběhne | Běží SSH tunel? Zkus na serveru `curl -s http://127.0.0.1:8080/ \| head -3`. |
| Zapomenutý jednorázový token | `sudo ad-server setup-token` vytvoří nový (jen dokud doména není). |
| Zapomenuté heslo správce | Přečíst se nedá. Jediná cesta je zrušit doménu a vytvořit ji znovu. |
| Klient: „otisk certifikační autority nesouhlasí" | Překlep v otisku, nebo se za server někdo vydává. Otisk ověř ve správě. |
| Klient: „nelze se připojit na …:8443" | Firewall na serveru, nebo špatná adresa. Zkus `ping` a `ss -tulpn \| grep 8443`. |
| Klient: „počítač už je v doméně" | `sudo ad-client leave`, pak znovu `join`. |
| Klient: heslo nejde zadat jako přepínač | Je to schválně — bylo by vidět v `ps`. Program se zeptá sám. |
| Po `leave` nefunguje internet | Zkontroluj `/etc/resolv.conf`. Záloha byla v `/var/lib/ad-client/dns-backup.json`. |

### Jen na Void Linuxu

| Příznak | Co s tím |
|---|---|
| `install-service` hlásí, že chybí `setcap` | `sudo xbps-install libcap` |
| `useradd: command not found` | `sudo xbps-install shadow` |
| Po restartu je v `resolv.conf` zase něco jiného | Chybí `nohook resolv.conf` v `/etc/dhcpcd.conf`. |
| Po výměně binárky nefunguje DNS na portu 53 | `setcap` se výměnou souboru ztratil: `sudo setcap cap_net_bind_service=+ep /usr/local/bin/ad-server && sudo sv restart ad-server` |
| `sv status ad-server` hlásí `down` | `tail -30 /var/lib/ad-server/logs/current` |
| `sv: fatal: unable to change to service directory` | Chybí odkaz: `sudo ln -s /etc/sv/ad-server /var/service/` |

### Jen na Windows

| Příznak | Co s tím |
|---|---|
| „Windows ochránil váš počítač" | Nepodepsaný program. **Další informace → Přesto spustit**, nebo `Unblock-File .\ad-server.exe`. |
| Defender soubor smaže | Přidej složku `C:\ad` do vyloučení v Zabezpečení Windows. |
| „Access is denied" při `install-service` | PowerShell není spuštěný jako správce. |
| Služba se zaregistruje, ale hned spadne | `Get-Content C:\ProgramData\ad-server\logs\ad-server.log -Tail 30`. Nejčastěji obsazený port 53 rolí DNS od Microsoftu. |
| `Get-Service ADServer` nic nenajde | Služba se nenainstalovala. Spusť `install-service --yes` znovu a přečti si výpis. |
| Nevidím `C:\ProgramData` | Je skrytá. Napiš cestu do Průzkumníka ručně, nebo `explorer C:\ProgramData\ad-server`. |
| Klient nenajde server | `Test-NetConnection 192.168.56.10 -Port 8443`. Když `False`, chybí pravidlo firewallu na serveru. |
| Heslo je při psaní vidět | Na Windows psaní neschováváme. Použij `--password-stdin`. |

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

## 10. Kam dál

| Dokument | O čem je |
|---|---|
| [`README.md`](../README.md) | přehled projektu a testy jednotlivých fází |
| [`ARCHITEKTURA.md`](ARCHITEKTURA.md) | jak to uvnitř funguje a proč zrovna takhle |
| [`PROTOKOL.md`](PROTOKOL.md) | protokol mezi klientem a serverem |
| [`BEZPECNOST.md`](BEZPECNOST.md) | model hrozeb, rozhodnutí a známé slabiny |
| [`TESTOVANI.md`](TESTOVANI.md) | příprava virtuálek pro testování |
