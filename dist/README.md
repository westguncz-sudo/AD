# dist/ — sestavené vydání

V repozitáři je tady **jen šablona** `index.template.html`.

Hotová stránka `index.html` a binárky vznikají až při sestavení a do
gitu se nedávají — git si pamatuje každou verzi navždycky a čtyři
binárky mají dohromady přes 13 MB. Po deseti přeloženích by měl
repozitář 130 MB, i když by v něm reálně byla jen poslední verze.

## Jak se k souborům dostat

### Sestavit si je

```bash
bash scripts/sestav-vydani.sh
```

Do tohohle adresáře to položí `index.html`, čtyři binárky
a `SHA256SUMS`. **Odkazy ve stránce jsou relativní**, takže funguje
jen tehdy, když binárky leží vedle ní — tak, jak je skript vyrobí.
Otevři `dist/index.html` v prohlížeči a stahování bude fungovat.

### Nebo je vzít z vydání

```bash
git tag -a v0.1.0 -m "První vydání"
git push origin v0.1.0
```

GitHub Actions soubory přeloží, spočítají součty a připnou je
k vydání. Ve vydání je i `index.html`, ve kterém jsou odkazy přepsané
na adresy ke stažení z GitHubu — ta stránka funguje odkudkoli, i když
ji otevřeš samotnou.

## Co se tu neverzuje

| Soubor | Proč |
|---|---|
| `index.html` | generuje se ze šablony při každém sestavení |
| `ad-server.exe`, `ad-client.exe` | binárky, patří do vydání |
| `ad-server-linux`, `ad-client-linux` | totéž |
| `SHA256SUMS` | platí vždy jen pro konkrétní sestavení |
