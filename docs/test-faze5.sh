#!/usr/bin/env bash
# Test fáze 5 — klient a zásady.
#
# Server i klient běží na jednom stroji. Klient zapisuje do vlastního
# adresáře a nastavení DNS si přesměruje na dočasný soubor, takže
# o nastavení stroje nezavadí.
#
# Použití:  bash docs/test-faze5.sh
set -u

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${KOREN}/data-test-klient"
SERVER_DATA="${DATA}/server"
KLIENT_DATA="${DATA}/klient"
SERVER_BIN="${KOREN}/target/debug/ad-server"
KLIENT_BIN="${KOREN}/target/debug/ad-client"
PORT_SPRAVA=18080
PORT_API=18443
PORT_DNS=15353
SPRAVA="http://127.0.0.1:${PORT_SPRAVA}/admin/api/v1"
HESLO_SPRAVCE='Spravce-Heslo1'
HESLO_ZAKA='Zak-Heslo-2026'
NOVE_HESLO_ZAKA='Zak-Nove-Heslo-7'

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export NO_PROXY='*' no_proxy='*'
# Klient bude sahat jen sem, ne na /etc/resolv.conf tohoto stroje.
export AD_CLIENT_RESOLV_CONF="${DATA}/resolv.conf"

zeleny=$'\e[32m'; cerveny=$'\e[31m'; zluty=$'\e[33m'; konec=$'\e[0m'
PROSLO=0; SPADLO=0
krok()  { printf '\n%s== %s ==%s\n' "$zluty" "$1" "$konec"; }
ok()    { printf '%s  OK  %s %s\n' "$zeleny" "$konec" "$1"; PROSLO=$((PROSLO+1)); }
chyba() { printf '%s FAIL %s %s\n' "$cerveny" "$konec" "$1"; SPADLO=$((SPADLO+1)); }
tvrd()  { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else chyba "$3: čekal jsem '$2', dostal '$1'"; fi; }
obsahuje() { if printf '%s' "$1" | grep -qF -- "$2"; then ok "$3"; else chyba "$3: chybí '$2'"; fi; }
neobsahuje() { if printf '%s' "$1" | grep -qF -- "$2"; then chyba "$3"; else ok "$3"; fi; }

klient() { "$KLIENT_BIN" "$@" --data-dir "$KLIENT_DATA" 2>&1; }

uklid() {
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  fi
}
trap uklid EXIT

# Překlad je součástí testu. Bez toho se snadno stane, že test běží
# proti staré binárce a hlásí chyby, které už dávno nejsou.
if command -v cargo >/dev/null 2>&1; then
  echo "Překládám…"
  (cd "$KOREN" && cargo build --quiet) || { echo "Překlad selhal."; exit 1; }
fi
for b in "$SERVER_BIN" "$KLIENT_BIN"; do
  [ -x "$b" ] || { echo "Chybí $b — spusť: cargo build"; exit 1; }
done

krok "Příprava serveru a domény"
rm -rf "$DATA"; mkdir -p "$SERVER_DATA" "$KLIENT_DATA"
printf 'nameserver 1.1.1.1\nsearch puvodni.sit\n' > "$AD_CLIENT_RESOLV_CONF"

cat > "$SERVER_DATA/config.toml" <<EOF
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

"$SERVER_BIN" --data-dir "$SERVER_DATA" --config "$SERVER_DATA/config.toml" run \
  >"$SERVER_DATA/server.out" 2>"$SERVER_DATA/server.log" &
PID=$!
for _ in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:${PORT_SPRAVA}/" && break; sleep 0.2; done
curl -sf -o /dev/null "http://127.0.0.1:${PORT_SPRAVA}/" || { echo "server nenaběhl"; cat "$SERVER_DATA/server.log"; exit 1; }

TOKEN="$(tr -d '\n' < "$SERVER_DATA/setup-token.txt")"
CSRF="$(curl -s -c "$DATA/ck.txt" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"setup_token\",\"token\":\"$TOKEN\"}" | jq -r .csrf_token)"
curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/roles" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true,"consent":true}' >/dev/null
POV="{\"domain_dns_name\":\"skola.internal\",\"dc_hostname\":\"DC01\",
  \"dc_ip\":\"127.0.0.1\",\"administrator_password\":\"$HESLO_SPRAVCE\",
  \"dns\":{\"create_reverse\":true,\"reverse_prefix\":24,\"forwarders\":[],
  \"enable_server\":true},\"confirm\":true}"
VYSLEDEK="$(curl -s -b "$DATA/ck.txt" -X POST "$SPRAVA/promote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "$POV")"
OTISK="$(echo "$VYSLEDEK" | jq -r '.ca_fingerprint_sha256')"
tvrd "$(echo "$VYSLEDEK" | jq -r '.domain.dns_name')" "skola.internal" "doména vytvořena"

# po povýšení se musíme přihlásit znovu
curl -s -c "$DATA/ck.txt" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"password\",\"username\":\"administrator\",\"password\":\"$HESLO_SPRAVCE\"}" >/dev/null
CSRF="$(curl -s -b "$DATA/ck.txt" "$SPRAVA/me" | jq -r .csrf_token)"
spravce() { curl -s -b "$DATA/ck.txt" -H "x-ad-csrf: $CSRF" "$@"; }

OU_ID="$(spravce -X POST "$SPRAVA/ous" -H 'content-type: application/json' \
  -d '{"name":"Zaci","description":"Žáci"}' | jq -r '.id')"
spravce -X POST "$SPRAVA/users" -H 'content-type: application/json' \
  -d "{\"sam_account_name\":\"jan.novak\",\"given_name\":\"Jan\",\"surname\":\"Novák\",
       \"ou_id\":$OU_ID,\"password\":\"$HESLO_ZAKA\",\"must_change_password\":false}" >/dev/null
ok "uživatel jan.novak vytvořen"

krok "Zásada s uvítací zprávou a tapetou"
printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAgAAAAGCAIAAABxZ0isAAAAY0lEQVR4nA3JIQEAQQhFQZKgCbEh0Jvky5cCTYgNgSbR3dgxM9w4xjVklPGMNcwCD05wAwUVvGDjj8STk9xESSUv2fxDuDjiCokST6z+aLw5zW3UVPOa7T8GH85wBw01vGGHD8x/PnFB5PEWAAAAAElFTkSuQmCC' \
  | base64 -d > "$DATA/tapeta.png"
ASSET="$(curl -s -b "$DATA/ck.txt" -H "x-ad-csrf: $CSRF" -X POST \
  "$SPRAVA/assets?name=tapeta.png" -H 'content-type: image/png' \
  --data-binary "@$DATA/tapeta.png")"
ASSET_ID="$(echo "$ASSET" | jq -r '.asset_id')"
ASSET_SHA="$(echo "$ASSET" | jq -r '.sha256')"
tvrd "$(echo "$ASSET" | jq -r '.width')x'$(echo "$ASSET" | jq -r '.height')'" "8x'6'" "obrázek nahrán i s rozměry"
tvrd "$(echo "$ASSET" | jq -r '.format')" "png" "formát poznán z obsahu"

ODP="$(curl -s -b "$DATA/ck.txt" -H "x-ad-csrf: $CSRF" -X POST "$SPRAVA/assets?name=zly.png" \
  -H 'content-type: image/png' --data-binary '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "bad_request" "SVG se odmítne, i když se tváří jako PNG"

GPO="$(spravce -X POST "$SPRAVA/gpos" -H 'content-type: application/json' -d "{
  \"name\":\"Školní nastavení\",
  \"settings\":{
    \"password\":{\"min_length\":12,\"require_uppercase\":true,\"require_lowercase\":true,
      \"require_digit\":true,\"require_symbol\":false,\"max_age_days\":0,\"min_age_days\":0,
      \"history_length\":3,\"forbid_username\":true},
    \"lockout\":{\"threshold\":5,\"window_minutes\":15,\"duration_minutes\":15},
    \"welcome\":{\"enabled\":true,\"title\":\"Vítej ve škole\",
      \"body\":\"Tohle je školní počítač.\\nChovej se slušně.\"},
    \"wallpaper\":{\"enabled\":true,\"asset_id\":\"$ASSET_ID\",\"sha256\":\"$ASSET_SHA\",
      \"format\":\"png\",\"style\":\"fill\",\"lock_user_change\":true}}}")"
GPO_ID="$(echo "$GPO" | jq -r '.id')"
tvrd "$(echo "$GPO" | jq -r '.settings.wallpaper.enabled')" "true" "zásada s tapetou vytvořena"
spravce -X POST "$SPRAVA/gpos/$GPO_ID/links" -H 'content-type: application/json' \
  -d '{"target":{"scope":"domain"}}' >/dev/null
ok "zásada připojená na doménu"

krok "Připojení se špatným otiskem"
VYSTUP="$(klient join --server "127.0.0.1:${PORT_API}" --fingerprint "$(printf 'AB%.0s' {1..32})" \
  --admin administrator --password-stdin <<< "$HESLO_SPRAVCE" || true)"
obsahuje "$VYSTUP" "otisk" "klient odmítl spojení kvůli otisku"
if [ -f "$KLIENT_DATA/state.json" ]; then chyba "při neúspěchu se uložil stav"
else ok "nic se neuložilo"; fi
neobsahuje "$VYSTUP" "$HESLO_SPRAVCE" "heslo není ve výpisu"

krok "Připojení do domény"
VYSTUP="$(klient join --server "127.0.0.1:${PORT_API}" --fingerprint "$OTISK" \
  --admin administrator --name PC-01 --password-stdin <<< "$HESLO_SPRAVCE")"
obsahuje "$VYSTUP" "otisk souhlasí" "otisk ověřen"
obsahuje "$VYSTUP" "počítačový účet vytvořen" "účet vytvořen"
obsahuje "$VYSTUP" "DNS nastaveno" "DNS nastaveno"
obsahuje "$VYSTUP" "zásady staženy" "zásady staženy"
neobsahuje "$VYSTUP" "$HESLO_SPRAVCE" "heslo správce není ve výpisu"

tvrd "$(stat -c '%a' "$KLIENT_DATA/state.json")" "600" "soubor se stavem je jen pro vlastníka"
if [ -f "$KLIENT_DATA/ca.pem" ]; then ok "certifikát autority uložen"; else chyba "chybí ca.pem"; fi
tvrd "$(jq -r '.ca_fingerprint' "$KLIENT_DATA/state.json" | tr -d ':')" \
  "$(printf '%s' "$OTISK" | tr -d ':')" "uložený otisk je ten zadaný"

krok "DNS: záloha a přepnutí"
tvrd "$(grep -c 'nameserver 127.0.0.1' "$AD_CLIENT_RESOLV_CONF")" "1" "resolv.conf ukazuje na server"
obsahuje "$(cat "$AD_CLIENT_RESOLV_CONF")" "search skola.internal" "doplněna doména pro hledání"
obsahuje "$(jq -r '.resolv.obsah' "$KLIENT_DATA/dns-backup.json")" "1.1.1.1" "původní DNS v záloze"

krok "Počítač je vidět na serveru i v DNS"
tvrd "$(spravce "$SPRAVA/computers" | jq -r '.total')" "1" "počítač v seznamu"
tvrd "$(spravce "$SPRAVA/computers" | jq -r '.items[0].name')" "PC-01" "jméno počítače"
tvrd "$(dig -p $PORT_DNS @127.0.0.1 +short pc-01.skola.internal A)" "127.0.0.1" "A záznam počítače v DNS"

krok "Stav klienta"
VYSTUP="$(klient status)"
obsahuje "$VYSTUP" "skola.internal" "status zná doménu"
obsahuje "$VYSTUP" "odpovídá, otisk souhlasí" "status se spojí se serverem"
obsahuje "$VYSTUP" "1.1.1.1" "status ukazuje, co bylo v DNS před připojením"
neobsahuje "$VYSTUP" "$(jq -r '.machine_secret' "$KLIENT_DATA/state.json")" \
  "tajemství počítače není ve výpisu"

krok "Podvržený certifikát autority"
cp "$KLIENT_DATA/ca.pem" "$DATA/ca-zaloha.pem"
# Vyrobíme jiný certifikát tím, že vezmeme ten od jiné domény.
rm -rf "$DATA/falesny"; mkdir -p "$DATA/falesny"
printf -- "-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----\n" > "$KLIENT_DATA/ca.pem"
VYSTUP="$(klient status || true)"
obsahuje "$VYSTUP" "neodpovídá uloženému otisku" "klient pozná vyměněný certifikát"
cp "$DATA/ca-zaloha.pem" "$KLIENT_DATA/ca.pem"
ok "certifikát vrácen"

krok "Přihlášení uživatele"
VYSTUP="$(klient logon --user jan.novak --password-stdin <<< "SpatneHeslo1" || true)"
obsahuje "$VYSTUP" "jméno nebo heslo nesouhlasí" "špatné heslo se odmítne"

VYSTUP="$(klient logon --user jan.novak --password-stdin <<< "$HESLO_ZAKA")"
obsahuje "$VYSTUP" "Jan Novák" "uživatel přihlášen"
obsahuje "$VYSTUP" "Vítej ve škole" "uvítací zpráva se zobrazila"
obsahuje "$VYSTUP" "Chovej se slušně." "i tělo zprávy"
obsahuje "$VYSTUP" "/Zaci" "umístění uživatele"
obsahuje "$VYSTUP" "Domain Users" "skupiny uživatele"
obsahuje "$VYSTUP" "nejméně 12 znaků" "zásada hesel z GPO"
obsahuje "$VYSTUP" "tapeta" "tapeta se řešila"
neobsahuje "$VYSTUP" "$HESLO_ZAKA" "heslo uživatele není ve výpisu"

krok "Tapeta"
if [ -f "$KLIENT_DATA/tapeta.png" ]; then ok "tapeta stažena"
else chyba "tapeta se nestáhla"; fi
tvrd "$(sha256sum "$KLIENT_DATA/tapeta.png" | cut -d' ' -f1)" "$ASSET_SHA" "součet tapety sedí"
tvrd "$(cmp -s "$KLIENT_DATA/tapeta.png" "$DATA/tapeta.png" && echo same)" "same" \
  "stažený soubor je shodný s nahraným"

krok "Tapeta s podvrženým obsahem"
# Vyměníme soubor na serveru za jiný; klient musí odmítnout, protože
# kontrolní součet v zásadě už nesedí.
SOUBOR_NA_SERVERU="$SERVER_DATA/assets/${ASSET_ID}.png"
cp "$SOUBOR_NA_SERVERU" "$DATA/original.png"
printf '\x89PNG\r\n\x1a\n%.0s' 1 > "$SOUBOR_NA_SERVERU"
head -c 200 /dev/urandom >> "$SOUBOR_NA_SERVERU"
rm -f "$KLIENT_DATA/tapeta.png"
VYSTUP="$(klient policy --apply || true)"
obsahuje "$VYSTUP" "tapeta" "klient tapetu řešil"
if [ -f "$KLIENT_DATA/tapeta.png" ]; then chyba "podvržený soubor se uložil"
else ok "podvržený soubor se neuložil"; fi
cp "$DATA/original.png" "$SOUBOR_NA_SERVERU"

krok "Zásady bez použití a s použitím"
VYSTUP="$(klient policy)"
obsahuje "$VYSTUP" "nejméně 12 znaků" "policy vypíše zásady"
obsahuje "$VYSTUP" "jen stáhly" "bez --apply se nic nenastaví"
VYSTUP="$(klient policy --apply)"
obsahuje "$VYSTUP" "pravidla hesel" "s --apply se zásady použijí"
tvrd "$(jq -r '.applied_at != null' "$KLIENT_DATA/policy.json")" "true" "čas použití se uložil"

krok "Změna hesla"
VYSTUP="$(printf '%s\n%s\n' "$HESLO_ZAKA" "kratke" | klient passwd --user jan.novak --password-stdin || true)"
obsahuje "$VYSTUP" "nejméně 12 znaků" "slabé heslo se odmítne i s vysvětlením"
VYSTUP="$(printf '%s\n%s\n' "$HESLO_ZAKA" "$NOVE_HESLO_ZAKA" | klient passwd --user jan.novak --password-stdin)"
obsahuje "$VYSTUP" "Heslo změněno" "heslo změněno"
VYSTUP="$(klient logon --user jan.novak --password-stdin <<< "$NOVE_HESLO_ZAKA")"
obsahuje "$VYSTUP" "Jan Novák" "přihlášení novým heslem"

krok "Dvojí připojení"
VYSTUP="$(klient join --server "127.0.0.1:${PORT_API}" --fingerprint "$OTISK" \
  --admin administrator --password-stdin <<< "$HESLO_SPRAVCE" || true)"
obsahuje "$VYSTUP" "už je v doméně" "podruhé se připojit nejde"

krok "Odpojení z domény"
VYSTUP="$(klient leave)"
obsahuje "$VYSTUP" "počítačový účet na serveru smazán" "server o odpojení ví"
obsahuje "$VYSTUP" "DNS vráceno do původního stavu" "DNS vráceno"
obsahuje "$VYSTUP" "místní soubory smazány" "soubory uklizeny"

tvrd "$(cat "$AD_CLIENT_RESOLV_CONF")" "$(printf 'nameserver 1.1.1.1\nsearch puvodni.sit')" \
  "resolv.conf je přesně jako před připojením"
for f in state.json ca.pem policy.json dns-backup.json tapeta.png; do
  if [ -f "$KLIENT_DATA/$f" ]; then chyba "zůstal soubor $f"; else ok "smazáno: $f"; fi
done
tvrd "$(spravce "$SPRAVA/computers" | jq -r '.total')" "0" "počítač zmizel ze serveru"
tvrd "$(dig -p $PORT_DNS @127.0.0.1 +short pc-01.skola.internal A)" "" "DNS záznam počítače zmizel"
tvrd "$(klient status)" "$(printf 'Počítač není v žádné doméně.\nPřipojit ho můžeš příkazem:\n  ad-client join --server <adresa> --fingerprint <otisk> --admin administrator')" \
  "status hlásí, že počítač není v doméně"

krok "V logu serveru nejsou hesla"
NALEZENO=0
for tajne in "$HESLO_SPRAVCE" "$HESLO_ZAKA" "$NOVE_HESLO_ZAKA"; do
  if grep -qF -- "$tajne" "$SERVER_DATA/server.log" "$SERVER_DATA/server.out" 2>/dev/null; then
    chyba "v logu je heslo"; NALEZENO=1
  fi
done
[ "$NALEZENO" = 0 ] && ok "v logu serveru není žádné heslo"

printf '\n==================================================\n'
printf 'Prošlo: %s%d%s   Spadlo: %s%d%s\n' "$zeleny" "$PROSLO" "$konec" \
  "$([ "$SPADLO" -gt 0 ] && echo "$cerveny" || echo "$zeleny")" "$SPADLO" "$konec"
printf 'Log serveru: %s\n' "$SERVER_DATA/server.log"
printf 'Data testu:  %s  (smazat: rm -rf %s)\n' "$DATA" "$DATA"
printf '==================================================\n'
[ "$SPADLO" -eq 0 ]
