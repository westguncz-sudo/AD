//! Použití zásad, které přišly ze serveru.
//!
//! # Pravidlo: zásada je data, ne příkaz
//! Server nemůže klientovi říct „spusť tohle". Struktury v `ad-core`
//! žádné takové pole nemají a mají `deny_unknown_fields`, takže cokoli
//! navíc se odmítne už při čtení odpovědi.
//!
//! Klient navíc přijatou zásadu **znovu zvaliduje** (rozsahy, délky,
//! řídicí znaky). Nevěří ani vlastnímu serveru — kdyby se do databáze
//! dostal nesmysl, nemá se podle něj chovat.

use crate::spojeni::Klient;
use crate::stav::Cesty;
use ad_core::policy::{EffectivePolicy, WallpaperStyle};
use ad_core::{secret, AdError, Result};

/// Co se při použití zásad povedlo a co ne.
#[derive(Debug, Default)]
pub struct Vysledek {
    pub radky: Vec<String>,
    pub varovani: Vec<String>,
}

impl Vysledek {
    fn hotovo(&mut self, text: impl Into<String>) {
        self.radky.push(text.into());
    }
    fn varuj(&mut self, text: impl Into<String>) {
        self.varovani.push(text.into());
    }
}

/// Zkontroluje zásadu přijatou ze serveru.
pub fn zkontroluj(zasada: &EffectivePolicy) -> Result<()> {
    zasada.validuj().map_err(|e| {
        AdError::bad_request(format!(
            "server poslal zásadu, která nedává smysl ({}). Nepoužiju ji.",
            e.message
        ))
    })
}

/// Vypíše uvítací zprávu.
///
/// Text je od správce, tedy cizí vstup. Server řídicí znaky odmítá,
/// ale pro jistotu je zahodíme ještě tady — ANSI sekvence umí přepsat
/// výpis v terminálu a podvrhnout uživateli něco jiného.
pub fn uvitani(zasada: &EffectivePolicy) -> Option<String> {
    let w = &zasada.welcome;
    if !w.enabled {
        return None;
    }
    let titulek = ocisti(&w.title);
    let telo = ocisti(&w.body);
    if titulek.trim().is_empty() && telo.trim().is_empty() {
        return None;
    }
    let mut out = String::new();
    out.push_str("\n╔══════════════════════════════════════════════════════════════╗\n");
    if !titulek.trim().is_empty() {
        out.push_str(&format!("  {titulek}\n"));
        out.push_str("  ────────────────────────────────────────────────────────────\n");
    }
    for radek in telo.lines() {
        out.push_str(&format!("  {radek}\n"));
    }
    out.push_str("╚══════════════════════════════════════════════════════════════╝\n");
    Some(out)
}

/// Zahodí řídicí znaky kromě nového řádku a tabulátoru.
pub fn ocisti(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect()
}

/// Použije zásady: stáhne a nastaví tapetu, připraví uvítací zprávu.
pub async fn pouzij(
    cesty: &Cesty,
    klient: &Klient,
    token: &str,
    zasada: &EffectivePolicy,
) -> Result<Vysledek> {
    zkontroluj(zasada)?;
    let mut v = Vysledek::default();

    // --- pravidla hesel a zamykání: vynucuje je server ---
    v.hotovo(format!(
        "pravidla hesel: nejméně {} znaků{}",
        zasada.password.min_length,
        slozitost(zasada)
    ));
    v.hotovo(if zasada.lockout.threshold == 0 {
        "zamykání účtu: vypnuté".to_string()
    } else {
        format!(
            "zamykání účtu: po {} chybách na {} minut",
            zasada.lockout.threshold, zasada.lockout.duration_minutes
        )
    });

    // --- uvítací zpráva ---
    if zasada.welcome.enabled {
        v.hotovo("uvítací zpráva: zapnutá");
    }

    // --- tapeta ---
    if zasada.wallpaper.enabled {
        match tapeta(cesty, klient, token, zasada).await {
            Ok(zprava) => v.hotovo(zprava),
            Err(e) => v.varuj(format!("tapeta: {}", e.message)),
        }
    }

    Ok(v)
}

fn slozitost(z: &EffectivePolicy) -> String {
    let mut casti = Vec::new();
    if z.password.require_uppercase {
        casti.push("velké písmeno");
    }
    if z.password.require_lowercase {
        casti.push("malé písmeno");
    }
    if z.password.require_digit {
        casti.push("číslice");
    }
    if z.password.require_symbol {
        casti.push("symbol");
    }
    if casti.is_empty() {
        String::new()
    } else {
        format!(", vyžaduje {}", casti.join(", "))
    }
}

/// Stáhne tapetu, ověří ji a zkusí nastavit.
async fn tapeta(
    cesty: &Cesty,
    klient: &Klient,
    token: &str,
    zasada: &EffectivePolicy,
) -> Result<String> {
    let w = &zasada.wallpaper;
    let (Some(id), Some(ocekavany_soucet), Some(format)) =
        (w.asset_id, w.sha256.as_ref(), w.format)
    else {
        return Err(AdError::bad_request("zásada tapety je neúplná"));
    };

    let odpoved =
        klient.poslat("GET", &format!("/api/v1/machine/asset/{id}"), None, Some(token)).await?;
    if odpoved.status != 200 {
        return Err(odpoved.chyba());
    }

    // 1. Souhlasí kontrolní součet s tím, co je v zásadě?
    //
    // Rozhoduje hodnota ze zásady, ne hlavička v odpovědi — tu si
    // posílá server sám. Hlavičku porovnáme taky, ale jen proto, aby
    // byla chyba srozumitelnější.
    let skutecny = secret::sha256_hex(&odpoved.telo);
    if let Some(z_hlavicky) = odpoved.hlavicka("x-ad-sha256") {
        if !secret::rovno_v_konstantnim_case(&skutecny, &z_hlavicky.to_lowercase()) {
            return Err(AdError::bad_request(
                "stažený soubor neodpovídá ani součtu, který server sám poslal                  v hlavičce — přenos se cestou poškodil",
            ));
        }
    }
    if !secret::rovno_v_konstantnim_case(&skutecny, &ocekavany_soucet.to_lowercase()) {
        return Err(AdError::bad_request(format!(
            "stažený obrázek neodpovídá kontrolnímu součtu v zásadě \
             (čekal jsem {}…, mám {}…). Soubor zahazuji.",
            &ocekavany_soucet[..16.min(ocekavany_soucet.len())],
            &skutecny[..16]
        )));
    }

    // 2. Je to opravdu obrázek? Poznáme to z obsahu, ne z hlavičky.
    let Some(skutecny_format) = ad_core::policy::ImageFormat::poznej(&odpoved.telo) else {
        return Err(AdError::bad_request("stažený soubor není PNG ani JPEG, zahazuji ho"));
    };
    if skutecny_format != format {
        return Err(AdError::bad_request(format!(
            "zásada slibovala {:?}, ale soubor je {:?}",
            format, skutecny_format
        )));
    }

    // 3. Uložíme a zkusíme nastavit.
    cesty.priprav()?;
    let cesta = cesty.tapeta().with_extension(format.pripona());
    std::fs::write(&cesta, &odpoved.telo)
        .map_err(|e| AdError::internal(format!("nelze uložit tapetu: {e}")))?;

    let zprava = match nastav_tapetu(&cesta, w.style) {
        Ok(kde) => format!("tapeta: nastavena ({kde}), soubor {}", cesta.display()),
        Err(e) => format!(
            "tapeta: stažena a ověřena, uložena v {} — nastavit ji se nepovedlo ({})",
            cesta.display(),
            e.message
        ),
    };
    Ok(zprava)
}

/// Nastaví tapetu v prostředí přihlášeného uživatele.
///
/// Tohle je jediná část zásad, která sahá mimo náš adresář, a je
/// záměrně slabá: měníme pozadí **přihlášenému uživateli**, nic
/// nevynucujeme a do přihlašování do systému nezasahujeme. `lock_user_change`
/// v zásadě je proto jen informace — uživatel si tapetu může změnit zpět.
#[cfg(unix)]
fn nastav_tapetu(cesta: &std::path::Path, styl: WallpaperStyle) -> Result<String> {
    let uri = format!("file://{}", cesta.display());
    let rezim = match styl {
        WallpaperStyle::Fill => "zoom",
        WallpaperStyle::Fit => "scaled",
        WallpaperStyle::Stretch => "stretched",
        WallpaperStyle::Center => "centered",
        WallpaperStyle::Tile => "wallpaper",
    };

    // GNOME. Na jiných prostředích se liší příkaz i názvy klíčů, takže
    // to nepředstíráme — soubor zůstane uložený a uživatel si ho
    // nastaví sám.
    if std::process::Command::new("gsettings").arg("--version").output().is_err() {
        return Err(AdError::bad_request("gsettings tu není — tapetu umíme nastavit jen v GNOME"));
    }
    for (klic, hodnota) in [
        ("picture-uri", uri.as_str()),
        ("picture-uri-dark", uri.as_str()),
        ("picture-options", rezim),
    ] {
        let vystup = std::process::Command::new("gsettings")
            .args(["set", "org.gnome.desktop.background", klic, hodnota])
            .output()
            .map_err(|e| AdError::internal(format!("gsettings: {e}")))?;
        if !vystup.status.success() {
            return Err(AdError::internal(format!(
                "gsettings set {klic} selhal: {}",
                String::from_utf8_lossy(&vystup.stderr).trim()
            )));
        }
    }
    Ok("GNOME".to_string())
}

/// Nastavení tapety na Windows.
///
/// **Tuhle část nemám jak vyzkoušet**, je napsaná podle dokumentace
/// k `SystemParametersInfo`. Otestuj ji ve virtuálce s Windows.
#[cfg(windows)]
fn nastav_tapetu(cesta: &std::path::Path, styl: WallpaperStyle) -> Result<String> {
    // WallpaperStyle a TileWallpaper v registru určují umístění.
    let (styl_cislo, dlazdice) = match styl {
        WallpaperStyle::Fill => ("10", "0"),
        WallpaperStyle::Fit => ("6", "0"),
        WallpaperStyle::Stretch => ("2", "0"),
        WallpaperStyle::Center => ("0", "0"),
        WallpaperStyle::Tile => ("0", "1"),
    };
    let soubor = cesta.to_string_lossy().replace('\'', "''");

    // SPI_SETDESKWALLPAPER = 20, SPIF_UPDATEINIFILE|SPIF_SENDCHANGE = 3
    let skript = format!(
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name WallpaperStyle -Value '{styl_cislo}';
         Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name TileWallpaper -Value '{dlazdice}';
         Add-Type -Namespace AdClient -Name Plocha -MemberDefinition '
           [DllImport(\"user32.dll\", CharSet=CharSet.Unicode, SetLastError=true)]
           public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);';
         [AdClient.Plocha]::SystemParametersInfo(20, 0, '{soubor}', 3)"
    );
    let vystup = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &skript])
        .output()
        .map_err(|e| AdError::internal(format!("nelze spustit powershell: {e}")))?;
    if !vystup.status.success() {
        return Err(AdError::internal(format!(
            "nastavení tapety selhalo: {}",
            String::from_utf8_lossy(&vystup.stderr).trim()
        )));
    }
    Ok("Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ad_core::policy::WelcomeMessage;

    #[test]
    fn ridici_znaky_se_zahodi() {
        assert_eq!(ocisti("ahoj\u{1b}[2Jsvete"), "ahoj[2Jsvete");
        assert_eq!(ocisti("prvni\ndruhy\ttretí"), "prvni\ndruhy\ttretí");
        assert_eq!(ocisti("a\u{7}b"), "ab");
    }

    #[test]
    fn uvitani_vypnute_nic_nevrati() {
        let z = EffectivePolicy::default();
        assert!(uvitani(&z).is_none());
    }

    #[test]
    fn uvitani_se_vypise_s_ramem() {
        let z = EffectivePolicy {
            welcome: WelcomeMessage {
                enabled: true,
                title: "Vítej ve škole".into(),
                body: "Tohle je školní počítač.\nChovej se slušně.".into(),
            },
            ..Default::default()
        };
        let text = uvitani(&z).unwrap();
        assert!(text.contains("Vítej ve škole"));
        assert!(text.contains("Chovej se slušně."));
        assert!(text.contains("╔"));
    }

    #[test]
    fn uvitani_s_ansi_sekvenci_se_ocisti() {
        let z = EffectivePolicy {
            welcome: WelcomeMessage {
                enabled: true,
                title: "Pozor\u{1b}[31m".into(),
                body: "text\u{1b}[0m".into(),
            },
            ..Default::default()
        };
        let text = uvitani(&z).unwrap();
        assert!(!text.contains('\u{1b}'), "v textu nesmí zůstat escape sekvence");
    }

    #[test]
    fn prazdna_zapnuta_zprava_se_nevypise() {
        let z = EffectivePolicy {
            welcome: WelcomeMessage { enabled: true, title: "  ".into(), body: String::new() },
            ..Default::default()
        };
        assert!(uvitani(&z).is_none());
    }

    #[test]
    fn nesmyslna_zasada_se_odmitne() {
        let mut z = EffectivePolicy::default();
        // mimo povolený rozsah
        z.password.min_length = 2;
        let e = zkontroluj(&z).unwrap_err();
        assert!(e.message.contains("nedává smysl"), "{}", e.message);
    }

    #[test]
    fn popis_slozitosti() {
        let mut z = EffectivePolicy::default();
        assert!(slozitost(&z).contains("velké písmeno"));
        z.password.require_uppercase = false;
        z.password.require_lowercase = false;
        z.password.require_digit = false;
        z.password.require_symbol = false;
        assert_eq!(slozitost(&z), "");
    }
}
