#!/usr/bin/env bash
# Test fáze 6 — běh jako systémová služba.
#
# Ve výchozím stavu jen kontroluje, co by instalace udělala, a nic
# nemění. Skutečnou instalaci a odinstalaci spustíš přepínačem
# --opravdu; to chce práva správce a opravdu to do systému zasáhne
# (vytvoří uživatele, zapíše jednotku nebo skript, službu zapne).
#
# Použití:
#   bash docs/test-faze6.sh              jen nanečisto
#   sudo bash docs/test-faze6.sh --opravdu   včetně skutečné instalace
set -u

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${KOREN}/data-test-sluzba"
SERVER_BIN="${KOREN}/target/debug/ad-server"
OPRAVDU=0
[ "${1:-}" = "--opravdu" ] && OPRAVDU=1

zeleny=$'\e[32m'; cerveny=$'\e[31m'; zluty=$'\e[33m'; modry=$'\e[36m'; konec=$'\e[0m'
PROSLO=0; SPADLO=0; PRESKOCENO=0
krok()  { printf '\n%s== %s ==%s\n' "$zluty" "$1" "$konec"; }
ok()    { printf '%s  OK  %s %s\n' "$zeleny" "$konec" "$1"; PROSLO=$((PROSLO+1)); }
chyba() { printf '%s FAIL %s %s\n' "$cerveny" "$konec" "$1"; SPADLO=$((SPADLO+1)); }
preskoc(){ printf '%s SKIP %s %s\n' "$modry" "$konec" "$1"; PRESKOCENO=$((PRESKOCENO+1)); }
obsahuje() { if printf '%s' "$1" | grep -qF -- "$2"; then ok "$3"; else chyba "$3: chybí '$2'"; fi; }
neobsahuje() { if printf '%s' "$1" | grep -qF -- "$2"; then chyba "$3"; else ok "$3"; fi; }

if command -v cargo >/dev/null 2>&1; then
  echo "Překládám…"
  (cd "$KOREN" && cargo build --quiet) || { echo "Překlad selhal."; exit 1; }
fi
[ -x "$SERVER_BIN" ] || { echo "Chybí $SERVER_BIN"; exit 1; }

rm -rf "$DATA"; mkdir -p "$DATA"
server() { "$SERVER_BIN" --data-dir "$DATA" --config "$DATA/config.toml" "$@" 2>&1; }

krok "Rozpoznání správce služeb"
VYSTUP="$(server service-status)"
echo "$VYSTUP" | sed 's/^/    /'
if printf '%s' "$VYSTUP" | grep -q "Správce služeb:"; then ok "service-status vypíše, co na stroji je"
else chyba "service-status nic nevypsal"; fi

krok "Instalace bez souhlasu nic neudělá"
VYSTUP="$(server install-service)"
obsahuje "$VYSTUP" "Co se stane:" "vypíše se plán"
obsahuje "$VYSTUP" "Nic jsem neudělal" "bez --yes se nic nestane"
obsahuje "$VYSTUP" "uninstall-service" "rovnou říká, jak to odebrat"
if [ -f /etc/systemd/system/ad-server.service ] || [ -d /etc/sv/ad-server ]; then
  chyba "něco se přesto nainstalovalo"
else
  ok "v systému nic nepřibylo"
fi

krok "Obsah jednotky systemd a skriptu runit"
# Vygenerované soubory kontrolují jednotkové testy; tady ověříme,
# že to, co se chystá udělat, odpovídá tomu, co slibujeme.
cargo test --quiet -p ad-server sluzba:: 2>&1 | tail -3 | sed 's/^/    /'
if (cd "$KOREN" && cargo test --quiet -p ad-server sluzba:: >/dev/null 2>&1); then
  ok "jednotkové testy jednotky i skriptu prošly"
else
  chyba "jednotkové testy služby selhaly"
fi

if [ "$OPRAVDU" != 1 ]; then
  krok "Skutečná instalace"
  preskoc "spusť s --opravdu (a jako root), ať se otestuje i zápis do systému"
  printf '\n==================================================\n'
  printf 'Prošlo: %s%d%s   Spadlo: %s%d%s   Přeskočeno: %d\n' \
    "$zeleny" "$PROSLO" "$konec" \
    "$([ "$SPADLO" -gt 0 ] && echo "$cerveny" || echo "$zeleny")" "$SPADLO" "$konec" "$PRESKOCENO"
  printf '==================================================\n'
  [ "$SPADLO" -eq 0 ]
  exit $?
fi

if [ "$(id -u)" != "0" ]; then
  echo "Skutečná instalace potřebuje práva správce: sudo bash $0 --opravdu"
  exit 1
fi

krok "Skutečná instalace služby"
VYSTUP="$(server install-service --user ad-server-test --yes)"
echo "$VYSTUP" | sed 's/^/    /'

SPRAVCE="$(server service-status | head -1)"
if printf '%s' "$SPRAVCE" | grep -q systemd; then
  JEDNOTKA=/etc/systemd/system/ad-server.service
  if [ -f "$JEDNOTKA" ]; then ok "jednotka $JEDNOTKA existuje"; else chyba "jednotka nevznikla"; fi
  OBSAH="$(cat "$JEDNOTKA" 2>/dev/null || true)"
  obsahuje "$OBSAH" "User=ad-server-test" "služba běží pod zadaným uživatelem"
  neobsahuje "$OBSAH" "User=root" "služba neběží pod rootem"
  obsahuje "$OBSAH" "AmbientCapabilities=CAP_NET_BIND_SERVICE" "port 53 bez práv roota"
  obsahuje "$OBSAH" "ProtectSystem=strict" "služba nesmí zapisovat kam chce"
  if systemctl is-enabled ad-server >/dev/null 2>&1; then ok "služba je zapnutá"
  else chyba "služba není zapnutá"; fi
  sleep 2
  if systemctl is-active ad-server >/dev/null 2>&1; then ok "služba běží"
  else chyba "služba neběží: $(systemctl status ad-server --no-pager -l 2>&1 | tail -5)"; fi
elif printf '%s' "$SPRAVCE" | grep -q runit; then
  if [ -x /etc/sv/ad-server/run ]; then ok "/etc/sv/ad-server/run existuje a je spustitelný"
  else chyba "run skript nevznikl"; fi
  if [ -x /etc/sv/ad-server/log/run ]; then ok "log/run existuje"; else chyba "log/run nevznikl"; fi
  OBSAH="$(cat /etc/sv/ad-server/run 2>/dev/null || true)"
  obsahuje "$OBSAH" "chpst -u ad-server-test" "služba běží pod zadaným uživatelem"
  if [ -L /var/service/ad-server ] || [ -L /run/runit/service/ad-server ]; then
    ok "služba je zapnutá odkazem"
  else chyba "chybí odkaz pro zapnutí"; fi
  if command -v getcap >/dev/null && getcap "$SERVER_BIN" | grep -q cap_net_bind_service; then
    ok "binárka smí na port 53 (setcap)"
  else preskoc "setcap se neověřil (chybí getcap nebo libcap)"; fi
else
  preskoc "tenhle stroj nemá systemd ani runit, instalaci nelze ověřit"
fi

if id ad-server-test >/dev/null 2>&1; then ok "systémový uživatel vytvořen"
else chyba "uživatel nevznikl"; fi

krok "Odinstalace"
VYSTUP="$(server uninstall-service)"
obsahuje "$VYSTUP" "Nic jsem neudělal" "bez --yes se neodinstaluje"
VYSTUP="$(server uninstall-service --yes)"
echo "$VYSTUP" | sed 's/^/    /'
if [ -f /etc/systemd/system/ad-server.service ] || [ -d /etc/sv/ad-server ]; then
  chyba "po odinstalaci něco zbylo"
else
  ok "po odinstalaci v systému nic nezbylo"
fi
if [ -d "$DATA" ]; then ok "data zůstala (bez --purge se nemažou)"; else chyba "data zmizela bez --purge"; fi

krok "Odinstalace i s daty"
server install-service --user ad-server-test --yes >/dev/null
server uninstall-service --yes --purge >/dev/null
if [ -d "$DATA" ]; then chyba "s --purge měla data zmizet"; else ok "s --purge data zmizela"; fi

# uklid po sobě
userdel ad-server-test 2>/dev/null || true
rm -rf /etc/sv/ad-server /var/service/ad-server /etc/systemd/system/ad-server.service
systemctl daemon-reload 2>/dev/null || true

printf '\n==================================================\n'
printf 'Prošlo: %s%d%s   Spadlo: %s%d%s   Přeskočeno: %d\n' \
  "$zeleny" "$PROSLO" "$konec" \
  "$([ "$SPADLO" -gt 0 ] && echo "$cerveny" || echo "$zeleny")" "$SPADLO" "$konec" "$PRESKOCENO"
printf 'Data testu: %s\n' "$DATA"
printf '==================================================\n'
[ "$SPADLO" -eq 0 ]
