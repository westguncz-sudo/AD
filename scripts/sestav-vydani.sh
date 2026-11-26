#!/usr/bin/env bash
# Sestaví všechny čtyři binárky, spočítá kontrolní součty a vyrobí
# index.html ke stažení.
#
# Běží stejně na vývojářském stroji i v GitHub Actions — žádné kroky
# navíc, které by se daly zapomenout. Windows binárky se křížově
# překládají z Linuxu přes mingw; výsledné .exe nepotřebují žádnou
# přibalenou knihovnu.
#
# Použití:
#   bash scripts/sestav-vydani.sh [ZÁKLADNÍ_URL]
#
# ZÁKLADNÍ_URL je předpona odkazů ke stažení. Bez ní odkazují soubory
# vedle index.html (hodí se k prohlédnutí lokálně).
set -euo pipefail

KOREN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VEN="${KOREN}/dist"
SABLONA="${VEN}/index.template.html"
ZAKLAD="${1:-}"
REPO="https://github.com/westguncz-sudo/AD"

CIL_LINUX=x86_64-unknown-linux-musl
CIL_WIN=x86_64-pc-windows-gnu

cd "$KOREN"

echo "== Kontrola nástrojů =="
chybi=0
for n in cargo rustup sha256sum; do
  command -v "$n" >/dev/null || { echo "  chybí $n"; chybi=1; }
done
command -v musl-gcc >/dev/null || {
  echo "  chybí musl-gcc (Debian: apt install musl-tools, Void: xbps-install musl-devel)"; chybi=1; }
command -v x86_64-w64-mingw32-gcc >/dev/null || {
  echo "  chybí mingw (Debian: apt install mingw-w64, Void: xbps-install mingw-w64)"; chybi=1; }
[ "$chybi" = 0 ] || exit 1
rustup target add "$CIL_LINUX" "$CIL_WIN" >/dev/null
echo "  v pořádku"

echo
echo "== Překlad =="
cargo build --release --target "$CIL_LINUX"
cargo build --release --target "$CIL_WIN"

echo
echo "== Sbírám výstupy =="
rm -rf "${VEN}/soubory"
mkdir -p "${VEN}/soubory"
cp "target/${CIL_LINUX}/release/ad-server" "${VEN}/soubory/ad-server-linux"
cp "target/${CIL_LINUX}/release/ad-client" "${VEN}/soubory/ad-client-linux"
cp "target/${CIL_WIN}/release/ad-server.exe" "${VEN}/soubory/ad-server.exe"
cp "target/${CIL_WIN}/release/ad-client.exe" "${VEN}/soubory/ad-client.exe"
chmod +x "${VEN}/soubory/ad-server-linux" "${VEN}/soubory/ad-client-linux"

# Linuxové binárky musí být statické — jinak by na Void nenaběhly.
for f in ad-server-linux ad-client-linux; do
  if file "${VEN}/soubory/$f" | grep -q "static"; then
    echo "  $f: staticky slinkované"
  else
    echo "  $f: NENÍ statické — na jiné distribuci nemusí naběhnout"
    exit 1
  fi
done
# Windows binárky nesmí potřebovat přibalenou DLL.
if command -v x86_64-w64-mingw32-objdump >/dev/null; then
  for f in ad-server.exe ad-client.exe; do
    if x86_64-w64-mingw32-objdump -p "${VEN}/soubory/$f" | grep -i "DLL Name:" \
       | grep -qiE "libgcc|libwinpthread|libstdc"; then
      echo "  $f: potřebuje knihovnu z mingw — to nechceme"
      exit 1
    fi
    echo "  $f: jen systémové knihovny Windows"
  done
fi

cd "${VEN}/soubory"
sha256sum ad-server.exe ad-client.exe ad-server-linux ad-client-linux > SHA256SUMS
cd "$KOREN"

soucet() { grep " $1\$" "${VEN}/soubory/SHA256SUMS" | cut -d' ' -f1; }
# Velikost v jednotce, která dává smysl — u souboru se součty by
# "0.0 MiB" vypadalo jako chyba.
velikost() {
  local b; b=$(stat -c '%s' "${VEN}/soubory/$1")
  awk -v b="$b" 'BEGIN {
    if (b >= 1048576)   printf "%.1f MiB", b/1048576;
    else if (b >= 1024) printf "%.0f KiB", b/1024;
    else                printf "%d B", b;
  }'
}

echo
echo "== Kontrolní součty =="
cat "${VEN}/soubory/SHA256SUMS" | sed 's/^/  /'

VERZE="$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
DATUM="$(date -u '+%d. %m. %Y')"
COMMIT_PLNY="$(git rev-parse HEAD 2>/dev/null || echo 'bez gitu')"
COMMIT="$(printf '%s' "$COMMIT_PLNY" | cut -c1-8)"

echo
echo "== index.html =="
nahrad() { printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'; }
sed \
  -e "s|@@VERZE@@|$(nahrad "$VERZE")|g" \
  -e "s|@@DATUM@@|$(nahrad "$DATUM")|g" \
  -e "s|@@COMMIT@@|$(nahrad "$COMMIT")|g" \
  -e "s|@@COMMIT_PLNY@@|$(nahrad "$COMMIT_PLNY")|g" \
  -e "s|@@REPO@@|$(nahrad "$REPO")|g" \
  -e "s|@@ZAKLAD@@|$(nahrad "$ZAKLAD")|g" \
  -e "s|@@SHA_SERVER_WIN@@|$(soucet ad-server.exe)|g" \
  -e "s|@@SHA_KLIENT_WIN@@|$(soucet ad-client.exe)|g" \
  -e "s|@@SHA_SERVER_LINUX@@|$(soucet ad-server-linux)|g" \
  -e "s|@@SHA_KLIENT_LINUX@@|$(soucet ad-client-linux)|g" \
  -e "s|@@VELIKOST_SERVER_WIN@@|$(velikost ad-server.exe)|g" \
  -e "s|@@VELIKOST_KLIENT_WIN@@|$(velikost ad-client.exe)|g" \
  -e "s|@@VELIKOST_SERVER_LINUX@@|$(velikost ad-server-linux)|g" \
  -e "s|@@VELIKOST_KLIENT_LINUX@@|$(velikost ad-client-linux)|g" \
  -e "s|@@VELIKOST_SUMS@@|$(velikost SHA256SUMS)|g" \
  "$SABLONA" > "${VEN}/index.html"

# Ve vygenerované stránce nesmí zůstat nevyplněné místo.
if grep -q '@@' "${VEN}/index.html"; then
  echo "  ZBYLY nevyplněné zástupné texty:"
  grep -o '@@[A-Z_]*@@' "${VEN}/index.html" | sort -u | sed 's/^/    /'
  exit 1
fi
cp "${VEN}/soubory/"* "${VEN}/" 2>/dev/null || true
echo "  ${VEN}/index.html"

echo
echo "Hotovo. Obsah ${VEN}:"
ls -la "$VEN" | grep -v '^total' | grep -v 'soubory\|template' | sed 's/^/  /'
