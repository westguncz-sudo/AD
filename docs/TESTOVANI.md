# Testování ve virtuálkách

Fáze 1 se testuje jen překladem a `cargo test` (viz README). Virtuálky
budou potřeba od fáze 2. Tady je příprava, kterou se vyplatí udělat
dopředu — než ji budeš potřebovat.

## Doporučená sestava

| Virtuálka | Systém | Role | Adresa |
|---|---|---|---|
| `dc01` | Debian 13 (bez GUI) | řadič domény | `192.168.56.10` |
| `pc01` | Windows 11 nebo Server 2025 | klient | `192.168.56.20` |
| `pc02` | Void Linux (musl) | klient | `192.168.56.21` |

Síť ve VirtualBoxu: **Host-only adapter** (`vboxnet0`, `192.168.56.0/24`)
pro doménový provoz. Druhý adaptér NAT, pokud potřebuješ internet —
jinak forwarder nebude mít kam přeposílat.

Doména: `skola.internal`. **Ne `.local`** — koliduje s mDNS a náš server
takové jméno odmítne.

## Příprava `dc01` (Debian)

```bash
# statická adresa
sudo tee /etc/systemd/network/10-host.network >/dev/null <<'EOF'
[Match]
Name=enp0s8
[Network]
Address=192.168.56.10/24
EOF

# jméno stroje
sudo hostnamectl set-hostname dc01

# ať je vidět, co měl systém za DNS předtím (klient i server to zálohují)
cat /etc/resolv.conf

# snapshot! Před každou fází se k němu vrátíš a test začne načisto.
```

Ve VirtualBoxu udělej snapshot `cista-instalace` u všech tří virtuálek.
Je to nejdůležitější krok celého testování — bez něj se nedá zopakovat
test po opravě.

## Příprava `pc01` (Windows)

```powershell
# statická adresa
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.20 `
  -PrefixLength 24

# co má systém za DNS teď (zapiš si to, klient to bude zálohovat)
Get-DnsClientServerAddress -AddressFamily IPv4

Rename-Computer -NewName PC-01 -Restart
```

## Příprava `pc02` (Void)

```bash
# Void s musl variantou, ať se potvrdí, že statická binárka opravdu stačí
sudo tee /etc/dhcpcd.conf >/dev/null <<'EOF'
interface eth1
static ip_address=192.168.56.21/24
EOF
sudo sv restart dhcpcd
```

## Vzdálená správa serveru bez GUI

Webová správa poslouchá jen na `127.0.0.1`. Z hostitele se k ní
dostaneš SSH tunelem:

```bash
ssh -L 8080:127.0.0.1:8080 uzivatel@192.168.56.10
# a pak v prohlížeči na hostiteli: http://127.0.0.1:8080
```

## Co se bude testovat v dalších fázích

| Fáze | Test |
|---|---|
| 2 | `curl` proti `/api/v1/hello`, vytvoření domény, přihlášení, restart serveru a kontrola, že data zůstala |
| 3 | `bash docs/test-faze3.sh`, nebo ručně v prohlížeči: přehled → role → povýšení → nástroje |
| 4 | `bash docs/test-faze4.sh`, nebo z klientské virtuálky: `dig @192.168.56.10 dc01.skola.internal`, `dig @192.168.56.10 -x 192.168.56.10`, `dig @192.168.56.10 _ad._tcp.skola.internal SRV`, `dig @192.168.56.10 seznam.cz` |
| 5 | `bash docs/test-faze5.sh` na jednom stroji; ve virtuálkách `ad-client join` na obou klientech, přihlášení uživatele, změna zásady a její dopad, `ad-client leave` a kontrola, že `/etc/resolv.conf` je zpátky |
| 6 | restart virtuálky — služba se spustí sama; `systemctl status`, `sv status`, `Get-Service` |
| 7 | stáhnout z `index.html`, ověřit SHA-256, spustit |

## Užitečné při ladění

```bash
# co poslouchá na portech
sudo ss -tulpn | grep -E ':(53|8080|8443)'

# na Debianu port 53 nejdřív uvolnit od systemd-resolved
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf && echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# oprávnění na port pod 1024 bez spouštění pod rootem
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/ad-server

# sleduj log serveru
sudo journalctl -u ad-server -f          # Debian
sudo tail -f /var/log/ad-server/current  # Void (svlogd)

# zkontroluj, že v logu není heslo (nahraď svým testovacím heslem)
sudo grep -ri 'Tajne1' /var/log/ad-server/ ; echo "nic nalezeno = dobře"

# databáze ručně
sqlite3 /var/lib/ad-server/domain.db '.tables'
sqlite3 /var/lib/ad-server/domain.db 'select sam, enabled from users;'
```
