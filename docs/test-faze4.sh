#!/usr/bin/env bash
# Test fáze 4 — vlastní DNS server.
#
# Spustí server na nesystémovém portu (aby nepotřeboval oprávnění),
# vytvoří doménu a pak se ho ptá pomocí `dig`: dopředné záznamy,
# reverzní, SRV, CNAME, neexistující jméno, odmítnuté typy dotazů,
# TCP i přeposílání.
#
# Potřebuje `dig`:
#   Debian/Ubuntu:  sudo apt install bind9-dnsutils
#   Void:           sudo xbps-install bind-utils
#
# Použití:  bash docs/test-faze4.sh
set -u

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${KOREN}/data-test-dns"
SERVER_BIN="${KOREN}/target/debug/ad-server"
PORT_DNS=15353
PORT_SPRAVA=18080
PORT_API=18443
SPRAVA="http://127.0.0.1:${PORT_SPRAVA}/admin/api/v1"
HESLO='Spravce-Heslo1'
DIG="dig -p ${PORT_DNS} @127.0.0.1 +timeout=3 +tries=1"

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export NO_PROXY='*' no_proxy='*'

zeleny=$'\e[32m'; cerveny=$'\e[31m'; zluty=$'\e[33m'; konec=$'\e[0m'
PROSLO=0; SPADLO=0
krok()  { printf '\n%s== %s ==%s\n' "$zluty" "$1" "$konec"; }
ok()    { printf '%s  OK  %s %s\n' "$zeleny" "$konec" "$1"; PROSLO=$((PROSLO+1)); }
chyba() { printf '%s FAIL %s %s\n' "$cerveny" "$konec" "$1"; SPADLO=$((SPADLO+1)); }
tvrd()  { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else chyba "$3: čekal jsem '$2', dostal '$1'"; fi; }
obsahuje() { if printf '%s' "$1" | grep -qF -- "$2"; then ok "$3"; else chyba "$3: v odpovědi chybí '$2'"; fi; }

uklid() {
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  fi
}
trap uklid EXIT

if [ ! -x "$SERVER_BIN" ]; then echo "Nejdřív: cargo build -p ad-server"; exit 1; fi
if ! command -v dig >/dev/null; then
  echo "Chybí dig. Debian/Ubuntu: sudo apt install bind9-dnsutils"
  exit 1
fi

krok "Start serveru s DNS na portu ${PORT_DNS}"
rm -rf "$DATA"; mkdir -p "$DATA"
cat > "$DATA/config.toml" <<EOF
[admin]
bind = "127.0.0.1:${PORT_SPRAVA}"
tls = false

[domain_api]
bind = "127.0.0.1:${PORT_API}"

[dns]
bind = "127.0.0.1:${PORT_DNS}"
enabled = true
forward_only_local = true

[log]
level = "info"
to_file = true
EOF

"$SERVER_BIN" --data-dir "$DATA" --config "$DATA/config.toml" run \
  >"$DATA/server.out" 2>"$DATA/server.log" &
PID=$!
for _ in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:${PORT_SPRAVA}/" && break; sleep 0.2; done
if curl -sf -o /dev/null "http://127.0.0.1:${PORT_SPRAVA}/"; then ok "server běží"
else chyba "server nenaběhl"; cat "$DATA/server.log"; exit 1; fi

krok "Před instalací role DNS server neposlouchá"
if $DIG skola.internal A 2>&1 | grep -q "status:"; then
  chyba "DNS odpovídá, i když role není nainstalovaná"
else
  ok "bez role DNS server na portu neposlouchá"
fi

krok "Role, doména a zóny"
TOKEN="$(tr -d '\n' < "$DATA/setup-token.txt")"
ODP="$(curl -s -c "$DATA/ck.txt" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"setup_token\",\"token\":\"$TOKEN\"}")"
CSRF="$(echo "$ODP" | jq -r .csrf_token)"
curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/roles" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true,"consent":true}' >/dev/null
ok "role nainstalované"

POV="{\"domain_dns_name\":\"skola.internal\",\"dc_hostname\":\"DC01\",
  \"dc_ip\":\"127.0.0.1\",\"administrator_password\":\"$HESLO\",
  \"dns\":{\"create_reverse\":true,\"reverse_prefix\":24,
  \"forwarders\":[\"127.0.0.1\"],\"enable_server\":true},\"confirm\":true}"
VYSLEDEK="$(curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/promote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "$POV")"
tvrd "$(echo "$VYSLEDEK" | jq -r '.domain.dns_name')" "skola.internal" "doména vytvořena"

# Povýšení ruší všechny session (jednorázový token přestal platit),
# takže se musíme přihlásit znovu jako doménový správce.
curl -s -c "$DATA/ck.txt" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"password\",\"username\":\"administrator\",\"password\":\"$HESLO\"}" >/dev/null
CSRF="$(curl -s -b "$DATA/ck.txt" "$SPRAVA/me" | jq -r .csrf_token)"
if [ -n "$CSRF" ] && [ "$CSRF" != "null" ]; then ok "správce přihlášen po povýšení"
else chyba "přihlášení správce selhalo"; fi

ZONA_ID="$(curl -s -b "$DATA/ck.txt" "$SPRAVA/dns/zones" \
  | jq -r '.[] | select(.kind=="forward") | .id')"

# DNS server se spouští po instalaci role, chvíli to trvá
for _ in $(seq 1 50); do
  $DIG +short dc01.skola.internal A 2>/dev/null | grep -q 127.0.0.1 && break
  sleep 0.2
done

krok "Dopředné záznamy"
tvrd "$($DIG +short dc01.skola.internal A)" "127.0.0.1" "A záznam řadiče"
ODPOVED="$($DIG dc01.skola.internal A)"
obsahuje "$ODPOVED" "status: NOERROR" "stav odpovědi NOERROR"
obsahuje "$ODPOVED" "flags: qr aa rd" "příznak aa (jsme autorita)"
tvrd "$($DIG +short DC01.SKOLA.INTERNAL A)" "127.0.0.1" "na velikosti písmen nezáleží"

krok "SOA, NS a TXT na vrcholu zóny"
obsahuje "$($DIG skola.internal SOA)" "dc01.skola.internal. hostmaster.skola.internal." "SOA zóny"
obsahuje "$($DIG +short skola.internal NS)" "dc01.skola.internal." "NS zóny"

krok "SRV — podle něj si klient najde řadič"
SRV="$($DIG +short _ad._tcp.skola.internal SRV)"
obsahuje "$SRV" "8443 dc01.skola.internal." "SRV ukazuje na řadič a port 8443"
obsahuje "$($DIG _ad._tcp.skola.internal SRV)" "ADDITIONAL SECTION" "adresa cíle přijde rovnou v additional"

krok "Reverzní zóna"
tvrd "$($DIG +short -x 127.0.0.1)" "dc01.skola.internal." "PTR záznam"

krok "CNAME se následuje uvnitř zóny"
ODP="$(curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/dns/zones/${ZONA_ID}/records" \
  -H "x-ad-csrf: $CSRF" -H 'content-type: application/json' \
  -d '{"name":"web","type":"CNAME","target":"dc01.skola.internal"}')"
tvrd "$(echo "$ODP" | jq -r '.name')" "web" "CNAME záznam vytvořen"
# +noall +answer vypíše jen sekci odpovědí, ať se nechytáme na patičku digu
VYSTUP="$($DIG +noall +answer web.skola.internal A)"
obsahuje "$VYSTUP" "CNAME" "odpověď obsahuje CNAME"
obsahuje "$VYSTUP" "dc01.skola.internal." "ukazuje na řadič"
tvrd "$(echo "$VYSTUP" | grep -c '127.0.0.1')" "1" "a rovnou i cílovou adresu"

krok "Neexistující jméno a typ"
obsahuje "$($DIG neni.skola.internal A)" "status: NXDOMAIN" "neexistující jméno = NXDOMAIN"
obsahuje "$($DIG neni.skola.internal A)" "AUTHORITY SECTION" "s SOA v authority"
VYSTUP="$($DIG dc01.skola.internal AAAA)"
obsahuje "$VYSTUP" "status: NOERROR" "existující jméno bez IPv6 není NXDOMAIN"
tvrd "$(echo "$VYSTUP" | grep -c '^dc01.skola.internal.*AAAA')" "0" "a nevrací žádnou odpověď"

krok "Co server odmítá"
obsahuje "$($DIG skola.internal AXFR)" "Transfer failed" "přenos zóny (AXFR) odmítnut"
obsahuje "$($DIG skola.internal ANY)" "status: REFUSED" "dotaz ANY odmítnut (zesílení útoku)"
obsahuje "$($DIG seznam.cz A +norecurse)" "status: REFUSED" "bez požadavku na rekurzi se nepřeposílá"

krok "Dotaz přes TCP"
tvrd "$($DIG +tcp +short dc01.skola.internal A)" "127.0.0.1" "TCP dotaz"
obsahuje "$($DIG +tcp skola.internal SOA)" "status: NOERROR" "TCP a SOA"

krok "Velká odpověď se zkrátí a tazatel přejde na TCP"
for i in $(seq 1 40); do
  curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/dns/zones/${ZONA_ID}/records" -H "x-ad-csrf: $CSRF" \
    -H 'content-type: application/json' \
    -d "{\"name\":\"velky\",\"type\":\"TXT\",\"text\":\"vypln-$i-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}" >/dev/null
done
obsahuje "$($DIG +ignore velky.skola.internal TXT)" " tc" "přes UDP přijde zkrácená odpověď (příznak tc)"
tvrd "$($DIG +tcp +noall +answer velky.skola.internal TXT | grep -c 'TXT')" "40" "přes TCP přijdou všechny záznamy"

krok "Přeposílání"
# Forwarder míří na nás samotné, takže dotaz mimo zónu nikam nevede —
# ověřujeme, že se server pokusí přeposlat a neodmítne to rovnou.
VYSTUP="$($DIG seznam.cz A)"
if printf '%s' "$VYSTUP" | grep -qE "status: (SERVFAIL|NOERROR|NXDOMAIN)"; then
  ok "dotaz mimo naše zóny šel na forwarder"
else
  chyba "dotaz mimo zóny nebyl přeposlán: $(printf '%s' "$VYSTUP" | grep status:)"
fi

curl -s -b "$DATA/ck.txt" -X PUT "$SPRAVA/dns/forwarders" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"forwarders":[]}' >/dev/null
obsahuje "$($DIG seznam.cz A)" "status: REFUSED" "bez forwarderu se dotaz mimo zóny odmítne"

krok "Statistiky ve správě"
STAV="$(curl -s -b "$DATA/ck.txt" "$SPRAVA/dns/status")"
tvrd "$(echo "$STAV" | jq -r '.running')" "true" "DNS server hlásí, že běží"
obsahuje "$(echo "$STAV" | jq -r '.listen | join(", ")')" "127.0.0.1:${PORT_DNS}" "adresa poslouchání"
if [ "$(echo "$STAV" | jq -r '.queries_total')" -gt 10 ]; then ok "počitadlo dotazů roste"
else chyba "počitadlo dotazů: $(echo "$STAV" | jq -r '.queries_total')"; fi
if [ "$(echo "$STAV" | jq -r '.queries_authoritative')" -gt 5 ]; then ok "počitadlo odpovědí z našich zón"
else chyba "odpovědi z našich zón: $(echo "$STAV" | jq -r '.queries_authoritative')"; fi
if [ "$(echo "$STAV" | jq -r '.queries_refused')" -gt 0 ]; then ok "počitadlo odmítnutých dotazů"
else chyba "odmítnuté: $(echo "$STAV" | jq -r '.queries_refused')"; fi
if [ "$(echo "$STAV" | jq -r '.queries_nxdomain')" -gt 0 ]; then ok "počitadlo neexistujících jmen"
else chyba "nxdomain: $(echo "$STAV" | jq -r '.queries_nxdomain')"; fi

krok "Registrace počítače se projeví v DNS"
JOIN="$(curl -sk -X POST "https://127.0.0.1:${PORT_API}/api/v1/join" \
  -H 'content-type: application/json' \
  -d "{\"computer_name\":\"PC-01\",\"admin_username\":\"administrator\",
       \"admin_password\":\"$HESLO\",\"os_name\":\"Debian\",\"os_version\":\"13\",
       \"client_version\":\"0.1.0\"}")"
tvrd "$(echo "$JOIN" | jq -r '.computer.name')" "PC-01" "počítač připojen"
tvrd "$($DIG +short pc-01.skola.internal A)" "127.0.0.1" "A záznam počítače je hned v DNS"

krok "Po zrušení domény server neodpovídá na doménová jména"
curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/demote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"confirm_domain_name":"skola.internal"}' >/dev/null
# Zrušení domény odebere i role, takže se DNS server zastaví.
for _ in $(seq 1 25); do
  $DIG dc01.skola.internal A 2>&1 | grep -q "status:" || break
  sleep 0.2
done
if $DIG dc01.skola.internal A 2>&1 | grep -q "status:"; then
  chyba "DNS stále odpovídá, i když doména i role jsou pryč"
else
  ok "po zrušení domény se DNS server zastavil"
fi

krok "V logu nejsou hesla"
if grep -qF -- "$HESLO" "$DATA/server.log" "$DATA/server.out" 2>/dev/null; then
  chyba "v logu je heslo"
else
  ok "v logu není heslo"
fi

printf '\n==================================================\n'
printf 'Prošlo: %s%d%s   Spadlo: %s%d%s\n' "$zeleny" "$PROSLO" "$konec" \
  "$([ "$SPADLO" -gt 0 ] && echo "$cerveny" || echo "$zeleny")" "$SPADLO" "$konec"
printf 'Log serveru: %s\n' "$DATA/server.log"
printf 'Data testu:  %s  (smazat: rm -rf %s)\n' "$DATA" "$DATA"
printf '==================================================\n'
[ "$SPADLO" -eq 0 ]
