#!/usr/bin/env bash
# Test fáze 3 — webové rozhraní v headless prohlížeči.
#
# Projde celý postup očima uživatele: přihlášení jednorázovým tokenem,
# průvodce Přidat role a funkce, konfigurační průvodce s kontrolou
# předpokladů, nástroje (Uživatelé a počítače, Správce DNS, Zásady
# skupiny) a bezpečnostní chování v prohlížeči. Průběžně ukládá snímky
# obrazovky.
#
# Potřebuje Node.js a Playwright:
#   npm install -g playwright && npx playwright install chromium
#
# Použití:  bash docs/test-faze3.sh
set -u

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${KOREN}/data-test-ui"
SNIMKY="${DATA}/snimky"
SERVER_BIN="${KOREN}/target/debug/ad-server"

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
export NO_PROXY='*' no_proxy='*'

if [ ! -x "$SERVER_BIN" ]; then
  echo "Nejdřív přelož server:  cargo build -p ad-server"
  exit 1
fi
if ! command -v node >/dev/null; then
  echo "Chybí Node.js. Test rozhraní bez něj spustit nejde."
  exit 1
fi

uklid() {
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
  fi
}
trap uklid EXIT

rm -rf "$DATA"
mkdir -p "$SNIMKY"

echo "Startuji server s prázdnou databází…"
"$SERVER_BIN" --data-dir "$DATA" --config "$DATA/config.toml" run \
  >"$DATA/server.out" 2>"$DATA/server.log" &
PID=$!

for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:8080/" && break
  sleep 0.2
done
if ! curl -sf -o /dev/null "http://127.0.0.1:8080/"; then
  echo "Server nenaběhl:"
  cat "$DATA/server.log"
  exit 1
fi

node "${KOREN}/docs/test-faze3.mjs" "$DATA" "$SNIMKY"
VYSLEDEK=$?

echo
echo "Snímky obrazovky: $SNIMKY"
echo "Log serveru:      $DATA/server.log"
echo "Data testu:       $DATA  (smazat: rm -rf $DATA)"
exit "$VYSLEDEK"
