#!/usr/bin/env bash
# Test fáze 2 na jednom stroji, bez virtuálky.
# Spustí server, projde celý postup (role -> doména -> uživatelé ->
# připojení počítače -> přihlášení) a ověří i bezpečnostní chování.
#
# Použití:  bash docs/test-faze2.sh
set -u

# Všechno je lokální — žádná proxy, i kdyby byla v prostředí nastavená.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export NO_PROXY='*' no_proxy='*'

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${KOREN}/data-test"
SERVER_BIN="${KOREN}/target/debug/ad-server"
SPRAVA="http://127.0.0.1:8080/admin/api/v1"
API="https://127.0.0.1:8443/api/v1"
HESLO_SPRAVCE='Spravce-Heslo1'
HESLO_UZIVATELE='Zak-Heslo-2026'
COOKIES="${DATA}/cookies.txt"

zeleny=$'\e[32m'; cerveny=$'\e[31m'; zluty=$'\e[33m'; konec=$'\e[0m'
PROSLO=0; SPADLO=0

krok()  { printf '\n%s== %s ==%s\n' "$zluty" "$1" "$konec"; }
ok()    { printf '%s  OK  %s %s\n' "$zeleny" "$konec" "$1"; PROSLO=$((PROSLO+1)); }
chyba() { printf '%s FAIL %s %s\n' "$cerveny" "$konec" "$1"; SPADLO=$((SPADLO+1)); }
tvrd()  { if [ "$1" = "$2" ]; then ok "$3 ($1)"; else chyba "$3: čekal jsem '$2', dostal '$1'"; fi; }

uklid() {
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
}
trap uklid EXIT

# Překlad je součástí testu. Bez toho se snadno stane, že test běží
# proti staré binárce a hlásí chyby, které už dávno nejsou.
if command -v cargo >/dev/null 2>&1; then
  echo "Překládám…"
  (cd "$KOREN" && cargo build --quiet) || { echo "Překlad selhal."; exit 1; }
fi
for b in "$SERVER_BIN"; do
  [ -x "$b" ] || { echo "Chybí $b — spusť: cargo build"; exit 1; }
done

krok "Úklid a start serveru"
rm -rf "$DATA"; mkdir -p "$DATA"
"$SERVER_BIN" --data-dir "$DATA" --config "$DATA/config.toml" run \
  >"$DATA/server.out" 2>"$DATA/server.log" &
PID=$!
for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:8080/" && break
  sleep 0.2
done
if curl -sf -o /dev/null "http://127.0.0.1:8080/"; then ok "server poslouchá na 127.0.0.1:8080"
else chyba "server nenaběhl"; cat "$DATA/server.log"; exit 1; fi

TOKEN="$(tr -d '\n' < "$DATA/setup-token.txt")"
if [ -n "$TOKEN" ]; then ok "jednorázový token vytvořen"; else chyba "token chybí"; fi
PRAVA="$(stat -c '%a' "$DATA/setup-token.txt")"
tvrd "$PRAVA" "600" "práva souboru s tokenem"

krok "Správa je jen na loopbacku"
VNEJSI_IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
if [ -n "$VNEJSI_IP" ]; then
  if curl -s --max-time 3 -o /dev/null "http://${VNEJSI_IP}:8080/" 2>/dev/null; then
    chyba "správa odpovídá i na ${VNEJSI_IP} — měla by jen na loopbacku"
  else
    ok "na ${VNEJSI_IP}:8080 správa neposlouchá"
  fi
else
  printf '  (přeskočeno: nenašel jsem vnější IP)\n'
fi

krok "Přihlášení jednorázovým tokenem"
ODP="$(curl -s -c "$COOKIES" -X POST "$SPRAVA/session" \
  -H 'content-type: application/json' \
  -d "{\"method\":\"setup_token\",\"token\":\"$TOKEN\"}")"
CSRF="$(echo "$ODP" | jq -r '.csrf_token // empty')"
if [ -n "$CSRF" ]; then ok "přihlášen jako setup"; else chyba "přihlášení selhalo: $ODP"; fi
tvrd "$(echo "$ODP" | jq -r '.principal.kind')" "setup" "druh přihlášení"

ODP="$(curl -s -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d '{"method":"setup_token","token":"spatny-token"}')"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "invalid_credentials" "špatný token se odmítne"

krok "CSRF"
KOD="$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" -X POST "$SPRAVA/roles" \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true,"consent":true}')"
tvrd "$KOD" "403" "POST bez hlavičky x-ad-csrf"

KOD="$(curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" -X POST "$SPRAVA/roles" \
  -H "x-ad-csrf: $CSRF" -H 'origin: http://zlo.example' \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true,"consent":true}')"
tvrd "$KOD" "403" "POST s cizím Origin"

krok "Stav serveru a role"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.stage')" "fresh" "čistý server"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.alerts[0].code')" "install_roles" "upozornění na role"

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/roles" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true}')"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "bad_request" "instalace bez souhlasu se odmítne"

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/roles" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"directory":true,"dns":true,"consent":true}')"
tvrd "$(echo "$ODP" | jq -r '.directory')" "true" "role doménových služeb"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.alerts[0].code')" "promote_pending" "upozornění na povýšení"

krok "Kontrola předpokladů"
POVYSENI="{\"domain_dns_name\":\"skola.internal\",\"dc_hostname\":\"DC01\",
  \"dc_ip\":\"127.0.0.1\",\"administrator_password\":\"$HESLO_SPRAVCE\",
  \"dns\":{\"create_reverse\":true,\"reverse_prefix\":24,\"forwarders\":[\"1.1.1.1\"],
  \"enable_server\":false},\"confirm\":true}"
ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/promote/precheck" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "$POVYSENI")"
tvrd "$(echo "$ODP" | jq -r '.can_continue')" "true" "předpoklady splněny"
echo "$ODP" | jq -r '.items[] | "    \(.status | ascii_upcase)\t\(.title): \(.detail)"'

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/promote/precheck" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d "${POVYSENI/skola.internal/skola.local}")"
tvrd "$(echo "$ODP" | jq -r '.can_continue')" "false" "doména .local neprojde"

krok "Povýšení na řadič domény"
ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/promote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "$POVYSENI")"
tvrd "$(echo "$ODP" | jq -r '.domain.dns_name')" "skola.internal" "doména vytvořena"
tvrd "$(echo "$ODP" | jq -r '.domain.short_name')" "SKOLA" "krátké jméno"
tvrd "$(echo "$ODP" | jq -r '.zones | length')" "2" "dopředná i reverzní zóna"
OTISK="$(echo "$ODP" | jq -r '.ca_fingerprint_sha256')"
printf '    otisk CA: %s\n' "$OTISK"
if [ -f "$DATA/setup-token.txt" ]; then chyba "soubor s tokenem zůstal"; else ok "soubor s tokenem smazán"; fi
tvrd "$(stat -c '%a' "$DATA/pki/ca.key")" "600" "práva klíče CA"

krok "Přihlášení doménového správce"
ODP="$(curl -s -c "$COOKIES" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"password\",\"username\":\"administrator\",\"password\":\"$HESLO_SPRAVCE\"}")"
CSRF="$(echo "$ODP" | jq -r '.csrf_token // empty')"
tvrd "$(echo "$ODP" | jq -r '.principal.sam_account_name')" "administrator" "správce přihlášen"

ODP="$(curl -s -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"setup_token\",\"token\":\"$TOKEN\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "invalid_credentials" "jednorázový token už neplatí"

krok "Organizační jednotky, uživatelé, skupiny"
OU="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/ous" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"name":"Zaci","description":"Žáci školy"}')"
OU_ID="$(echo "$OU" | jq -r '.id')"
tvrd "$(echo "$OU" | jq -r '.path')" "/Zaci" "OU vytvořena"

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/users" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d "{\"sam_account_name\":\"jan.novak\",\"given_name\":\"Jan\",\"surname\":\"Novák\",
       \"ou_id\":$OU_ID,\"password\":\"$HESLO_UZIVATELE\",\"must_change_password\":false}")"
UID_JAN="$(echo "$ODP" | jq -r '.id')"
tvrd "$(echo "$ODP" | jq -r '.upn')" "jan.novak@skola.internal" "uživatel vytvořen"
tvrd "$(echo "$ODP" | jq -r '.display_name')" "Jan Novák" "zobrazované jméno"
if echo "$ODP" | grep -q 'password_hash'; then chyba "odpověď obsahuje hash hesla"; else ok "odpověď neobsahuje hash hesla"; fi

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/users" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d '{"sam_account_name":"petr.slaby","password":"heslo"}')"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "password_policy_violation" "slabé heslo se odmítne"
echo "$ODP" | jq -r '.error.details.complaints[] | "    porušeno: \(.rule)"'

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/users" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d "{\"sam_account_name\":\"administrator\",\"password\":\"$HESLO_UZIVATELE\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "reserved_name" "vyhrazené jméno se odmítne"

SKUPINA="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/groups" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"name":"Žáci 1.A","ou_id":'"$OU_ID"'}')"
GID="$(echo "$SKUPINA" | jq -r '.id')"
tvrd "$(echo "$SKUPINA" | jq -r '.sam_account_name')" "zaci-1-a" "jméno skupiny odvozeno z názvu"

curl -s -b "$COOKIES" -X POST "$SPRAVA/groups/$GID/members" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "{\"members\":[{\"kind\":\"user\",\"id\":$UID_JAN}]}" >/dev/null
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/users/$UID_JAN/groups" | jq -r 'sort | join(",")')" \
  "Domain Users,Žáci 1.A" "členství včetně Domain Users"

tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/ous/tree" | jq -r '.children[0].name')" "Computers" "strom OU"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/users?q=novak" | jq -r '.total')" "1" "hledání uživatele"

krok "Doménové API přes TLS"
CA="$DATA/pki/ca.pem"
# Poslouchátko doménového API se po povýšení spouští samo, chvíli to trvá.
for _ in $(seq 1 50); do
  curl -sk -o /dev/null "$API/hello" && break
  sleep 0.2
done
if curl -sk -o /dev/null "$API/hello"; then ok "doménové API naběhlo po povýšení"
else chyba "doménové API nenaběhlo"; fi
HELLO="$(curl -s --cacert "$CA" --resolve "dc01.skola.internal:8443:127.0.0.1" \
  "https://dc01.skola.internal:8443/api/v1/hello")"
tvrd "$(echo "$HELLO" | jq -r '.domain.dns_name')" "skola.internal" "/hello přes TLS s ověřeným certifikátem"
tvrd "$(echo "$HELLO" | jq -r '.ca_fingerprint_sha256')" "$OTISK" "otisk CA v /hello"
tvrd "$(echo "$HELLO" | jq -r '.proto_max')" "1" "verze protokolu"

KOD="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -k "$API/hello" \
  -H 'x-ad-proto: 99')"
tvrd "$KOD" "400" "neznámá verze protokolu se odmítne"

if curl -s --max-time 5 -o /dev/null "http://127.0.0.1:8443/api/v1/hello" 2>/dev/null; then
  chyba "doménové API odpovídá i bez TLS"
else
  ok "doménové API bez TLS neodpovídá"
fi

krok "Připojení počítače do domény"
JOIN="$(curl -s -k -X POST "$API/join" -H 'content-type: application/json' \
  -d "{\"computer_name\":\"PC-01\",\"admin_username\":\"SKOLA\\\\administrator\",
       \"admin_password\":\"$HESLO_SPRAVCE\",\"os_name\":\"Debian GNU/Linux\",
       \"os_version\":\"13\",\"client_version\":\"0.1.0\"}")"
MID="$(echo "$JOIN" | jq -r '.machine_id')"
MSECRET="$(echo "$JOIN" | jq -r '.machine_secret')"
tvrd "$(echo "$JOIN" | jq -r '.computer.name')" "PC-01" "počítačový účet vytvořen"
tvrd "$(echo "$JOIN" | jq -r '.computer.dns_name')" "pc-01.skola.internal" "DNS jméno počítače"
tvrd "$(echo "$JOIN" | jq -r '.dns_servers[0]')" "127.0.0.1" "klient dostal adresu DNS"
if echo "$JOIN" | jq -r '.ca_cert_pem' | grep -q 'BEGIN CERTIFICATE'; then
  ok "klient dostal certifikát CA"
else chyba "chybí certifikát CA"; fi

ODP="$(curl -s -k -X POST "$API/join" -H 'content-type: application/json' \
  -d "{\"computer_name\":\"PC-01\",\"admin_username\":\"administrator\",
       \"admin_password\":\"$HESLO_SPRAVCE\",\"os_name\":\"x\",\"os_version\":\"1\",
       \"client_version\":\"0.1.0\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "machine_already_joined" "dvakrát se připojit nejde"

ODP="$(curl -s -k -X POST "$API/join" -H 'content-type: application/json' \
  -d "{\"computer_name\":\"PC-02\",\"admin_username\":\"jan.novak\",
       \"admin_password\":\"$HESLO_UZIVATELE\",\"os_name\":\"x\",\"os_version\":\"1\",
       \"client_version\":\"0.1.0\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "permission_denied" "běžný uživatel počítač nepřipojí"

krok "Token počítače a přihlášení uživatele"
TOK="$(curl -s -k -X POST "$API/machine/token" -H 'content-type: application/json' \
  -d "{\"machine_id\":\"$MID\",\"machine_secret\":\"$MSECRET\"}" | jq -r '.token')"
if [ -n "$TOK" ] && [ "$TOK" != "null" ]; then ok "token počítače vydán"; else chyba "token nevydán"; fi

ODP="$(curl -s -k -X POST "$API/machine/token" -H 'content-type: application/json' \
  -d "{\"machine_id\":\"$MID\",\"machine_secret\":\"spatne-tajemstvi\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "machine_secret_invalid" "špatné tajemství se odmítne"

ODP="$(curl -s -k -X POST "$API/auth/logon" -H 'content-type: application/json' \
  -d "{\"username\":\"jan.novak\",\"password\":\"$HESLO_UZIVATELE\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "auth_required" "přihlášení bez tokenu počítače neprojde"

LOGON="$(curl -s -k -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"jan.novak\",\"password\":\"$HESLO_UZIVATELE\"}")"
tvrd "$(echo "$LOGON" | jq -r '.user.display_name')" "Jan Novák" "uživatel přihlášen"
tvrd "$(echo "$LOGON" | jq -r '.user.ou_path')" "/Zaci" "cesta k OU"
tvrd "$(echo "$LOGON" | jq -r '.policy.password.min_length')" "8" "zásady v odpovědi"
tvrd "$(echo "$LOGON" | jq -r '.must_change_password')" "false" "změna hesla není vynucená"

tvrd "$(curl -s -k -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"username":"jan.novak","password":"SpatneHeslo1"}' | jq -r '.error.code')" \
  "invalid_credentials" "špatné heslo"
tvrd "$(curl -s -k -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"username":"neexistuje","password":"SpatneHeslo1"}' | jq -r '.error.code')" \
  "invalid_credentials" "neexistující účet hlásí totéž"

krok "Zamykání účtu (zásada: 5 pokusů)"
for i in 1 2 3 4; do
  curl -s -k -o /dev/null -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
    -H 'content-type: application/json' \
    -d '{"username":"jan.novak","password":"Spatne'"$i"'Heslo"}'
done
ODP="$(curl -s -k -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"jan.novak\",\"password\":\"$HESLO_UZIVATELE\"}")"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "account_locked" "účet se po 5 chybách zamkl"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.counts.locked_users')" "1" "zamčený účet v přehledu"

curl -s -b "$COOKIES" -X POST "$SPRAVA/users/$UID_JAN/unlock" -H "x-ad-csrf: $CSRF" >/dev/null
tvrd "$(curl -s -k -X POST "$API/auth/logon" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"jan.novak\",\"password\":\"$HESLO_UZIVATELE\"}" | jq -r '.user.sam_account_name')" \
  "jan.novak" "po odemčení se přihlášení povede"

krok "Zásady skupiny"
GPO="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/gpos" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d '{"name":"Silná hesla pro žáky","settings":{"password":{"min_length":12,
       "require_uppercase":true,"require_lowercase":true,"require_digit":true,
       "require_symbol":true,"max_age_days":90,"min_age_days":0,
       "history_length":5,"forbid_username":true}}}')"
GPO_ID="$(echo "$GPO" | jq -r '.id')"
tvrd "$(echo "$GPO" | jq -r '.settings.password.min_length')" "12" "zásada vytvořena"

curl -s -b "$COOKIES" -X POST "$SPRAVA/gpos/$GPO_ID/links" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d "{\"target\":{\"scope\":\"ou\",\"ou_id\":$OU_ID}}" >/dev/null
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/gpos/effective?ou_id=$OU_ID" | jq -r '.policy.password.min_length')" \
  "12" "zásada platí v OU"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/gpos/effective" | jq -r '.policy.password.min_length')" \
  "8" "mimo OU platí výchozí"

ODP="$(curl -s -b "$COOKIES" -X POST "$SPRAVA/gpos" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' \
  -d '{"name":"Škodlivá","settings":{"run_command":"rm -rf /"}}')"
tvrd "$(echo "$ODP" | jq -r '.error.code')" "bad_request" "zásada s příkazem se odmítne"

krok "Zásady pro počítač a heartbeat"
ZASADY="$(curl -s -k "$API/machine/policy" -H "authorization: Bearer $TOK")"
SERIAL="$(echo "$ZASADY" | jq -r '.serial')"
tvrd "$(echo "$ZASADY" | jq -r '.policy.password.min_length')" "8" "počítač je mimo OU Zaci"
KOD="$(curl -s -k -o /dev/null -w '%{http_code}' "$API/machine/policy" \
  -H "authorization: Bearer $TOK" -H "if-none-match: \"$SERIAL\"")"
tvrd "$KOD" "304" "beze změny se zásady neposílají znovu"

tvrd "$(curl -s -k -X POST "$API/heartbeat" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d "{\"os_name\":\"Debian\",\"os_version\":\"13\",\"client_version\":\"0.1.0\",
       \"policy_serial\":$SERIAL}" | jq -r '.policy_changed')" "false" "heartbeat bez změny"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.counts.computers_online')" "1" "počítač je vidět jako online"

krok "DNS data (server poběží od fáze 4)"
ZONY="$(curl -s -b "$COOKIES" "$SPRAVA/dns/zones")"
tvrd "$(echo "$ZONY" | jq -r 'length')" "2" "dvě zóny"
Z_ID="$(echo "$ZONY" | jq -r '.[] | select(.kind=="forward") | .id')"
ZAZNAMY="$(curl -s -b "$COOKIES" "$SPRAVA/dns/zones/$Z_ID/records")"
tvrd "$(echo "$ZAZNAMY" | jq -r '[.[] | select(.name=="dc01" and .type=="A")] | length')" "1" "A záznam řadiče"
tvrd "$(echo "$ZAZNAMY" | jq -r '[.[] | select(.name=="_ad._tcp")] | length')" "1" "SRV záznam služby"
tvrd "$(echo "$ZAZNAMY" | jq -r '[.[] | select(.name=="pc-01")] | length')" "1" "A záznam připojeného počítače"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/dns/forwarders" | jq -r '.forwarders[0]')" "1.1.1.1" "forwarder"

krok "Hesla a tokeny nejsou v logu"
NALEZENO=0
for tajne in "$HESLO_SPRAVCE" "$HESLO_UZIVATELE" "$MSECRET" "$TOK" "$CSRF"; do
  if grep -qF -- "$tajne" "$DATA/server.log" "$DATA/server.out" 2>/dev/null; then
    chyba "v logu je tajemství: ${tajne:0:6}…"
    NALEZENO=1
  fi
done
[ "$NALEZENO" = 0 ] && ok "v logu není žádné heslo, tajemství ani token"

if grep -qF -- "$HESLO_UZIVATELE" "$DATA/domain.db" 2>/dev/null; then
  chyba "heslo je v databázi v čitelné podobě"
else
  ok "heslo není v databázi v čitelné podobě"
fi

krok "Audit"
AUDIT="$(curl -s -b "$COOKIES" "$SPRAVA/events?limit=200")"
for akce in domain.promote user.create computer.join auth.logon.ok auth.logon.failed; do
  if echo "$AUDIT" | jq -e --arg a "$akce" '.items[] | select(.action==$a)' >/dev/null; then
    ok "audit obsahuje $akce"
  else
    chyba "audit neobsahuje $akce"
  fi
done
if echo "$AUDIT" | grep -qF -- "$HESLO_UZIVATELE"; then chyba "audit obsahuje heslo"; else ok "audit neobsahuje heslo"; fi

krok "Restart serveru — data zůstávají"
kill "$PID"; wait "$PID" 2>/dev/null
"$SERVER_BIN" --data-dir "$DATA" --config "$DATA/config.toml" run \
  >>"$DATA/server.out" 2>>"$DATA/server.log" &
PID=$!
for _ in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:8080/" && break; sleep 0.2; done
ODP="$(curl -s -c "$COOKIES" -X POST "$SPRAVA/session" -H 'content-type: application/json' \
  -d "{\"method\":\"password\",\"username\":\"administrator\",\"password\":\"$HESLO_SPRAVCE\"}")"
CSRF="$(echo "$ODP" | jq -r '.csrf_token // empty')"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/status" | jq -r '.stage')" "domain_controller" "po restartu je stále řadičem"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/users?q=novak" | jq -r '.total')" "1" "uživatel po restartu existuje"
tvrd "$(curl -s -k "$API/hello" | jq -r '.domain.short_name')" "SKOLA" "doménové API po restartu"

krok "Odpojení počítače z domény"
TOK="$(curl -s -k -X POST "$API/machine/token" -H 'content-type: application/json' \
  -d "{\"machine_id\":\"$MID\",\"machine_secret\":\"$MSECRET\"}" | jq -r '.token')"
tvrd "$(curl -s -k -X POST "$API/unjoin" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{"remove_dns":true}' | jq -r '.ok')" "true" "počítač odpojen"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/computers" | jq -r '.total')" "0" "počítač zmizel ze seznamu"
tvrd "$(curl -s -b "$COOKIES" "$SPRAVA/dns/zones/$Z_ID/records" | jq -r '[.[] | select(.name=="pc-01")] | length')" \
  "0" "DNS záznam počítače smazán"

krok "Zrušení domény"
tvrd "$(curl -s -b "$COOKIES" -X POST "$SPRAVA/demote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"confirm_domain_name":"jina.internal"}' | jq -r '.error.code')" \
  "bad_request" "špatné jméno pro potvrzení nic nesmaže"
tvrd "$(curl -s -b "$COOKIES" -X POST "$SPRAVA/demote" -H "x-ad-csrf: $CSRF" \
  -H 'content-type: application/json' -d '{"confirm_domain_name":"skola.internal"}' | jq -r '.ok')" \
  "true" "doména zrušena"

printf '\n==================================================\n'
printf 'Prošlo: %s%d%s   Spadlo: %s%d%s\n' "$zeleny" "$PROSLO" "$konec" \
  "$([ "$SPADLO" -gt 0 ] && echo "$cerveny" || echo "$zeleny")" "$SPADLO" "$konec"
printf 'Log serveru: %s\n' "$DATA/server.log"
printf 'Data testu:  %s  (smazat: rm -rf %s)\n' "$DATA" "$DATA"
printf '==================================================\n'
[ "$SPADLO" -eq 0 ]
