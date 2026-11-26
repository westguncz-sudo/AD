//! Soubory pro zásady — zatím jen tapety.
//!
//! Obrázek se uloží na disk pod svým identifikátorem a do databáze se
//! zapíše jeho kontrolní součet. Klient si ho stáhne a součet si ověří;
//! když nesedí, soubor zahodí.
//!
//! # Proč tu není SVG
//! SVG je XML a umí v sobě mít skript. Nechat ho zobrazit je totéž jako
//! spustit cizí kód. Bereme jen PNG a JPEG a **poznáváme je podle
//! obsahu**, ne podle přípony nebo hlavičky `Content-Type` — ty si určuje
//! ten, kdo soubor posílá.

use crate::config::Cesty;
use crate::store::Store;
use ad_core::ids::Guid;
use ad_core::policy::{ImageFormat, MAX_TAPETA_BAJTU};
use ad_core::proto::UploadAssetResponse;
use ad_core::{secret, AdError, ErrorCode, Result};
use std::path::PathBuf;

/// Uloží nahraný obrázek a vrátí jeho popis.
pub fn uloz(
    store: &Store,
    cesty: &Cesty,
    data: &[u8],
    puvodni_jmeno: &str,
) -> Result<UploadAssetResponse> {
    if data.is_empty() {
        return Err(AdError::bad_request("soubor je prázdný"));
    }
    if data.len() as u64 > MAX_TAPETA_BAJTU {
        return Err(AdError::out_of_range(format!(
            "obrázek je větší než {} MiB",
            MAX_TAPETA_BAJTU / 1024 / 1024
        )));
    }

    let Some(format) = ImageFormat::poznej(data) else {
        return Err(AdError::bad_request(
            "tohle není PNG ani JPEG. Jiné formáty nebereme — SVG je XML \
             a umí v sobě mít skript.",
        ));
    };
    let (sirka, vyska) = rozmery(data, format)?;
    if sirka == 0 || vyska == 0 {
        return Err(AdError::bad_request("obrázek má nulový rozměr"));
    }

    let id = ad_core::ids::novy_guid();
    let sha = secret::sha256_hex(data);
    let cesta = soubor(cesty, id, format);
    std::fs::create_dir_all(cesty.assets())
        .map_err(|e| AdError::internal(format!("adresář pro soubory: {e}")))?;
    std::fs::write(&cesta, data)
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesta.display())))?;

    let popis = UploadAssetResponse {
        asset_id: id,
        sha256: sha,
        size: data.len() as u64,
        format,
        width: sirka,
        height: vyska,
    };
    store.vloz_asset(&popis, &crate::store::objects::omez_text(puvodni_jmeno, 120))?;
    Ok(popis)
}

/// Cesta k uloženému souboru.
pub fn soubor(cesty: &Cesty, id: Guid, format: ImageFormat) -> PathBuf {
    cesty.assets().join(format!("{id}.{}", format.pripona()))
}

/// Načte obrázek z disku i s jeho popisem z databáze.
pub fn nacti(store: &Store, cesty: &Cesty, id: Guid) -> Result<(Vec<u8>, UploadAssetResponse)> {
    let popis = store.asset(id)?;
    let cesta = soubor(cesty, id, popis.format);
    let data = std::fs::read(&cesta).map_err(|e| {
        AdError::new(ErrorCode::NotFound, format!("soubor {} na disku chybí: {e}", cesta.display()))
    })?;
    // Co je na disku, musí sedět s tím, co slíbila databáze. Kdyby
    // někdo soubor vyměnil, klient by ho stejně odmítl — ať to pozná
    // server dřív.
    if secret::sha256_hex(&data) != popis.sha256 {
        return Err(AdError::internal(format!(
            "soubor {} neodpovídá kontrolnímu součtu v databázi",
            cesta.display()
        )));
    }
    Ok((data, popis))
}

/// Rozměry obrázku z jeho hlavičky.
///
/// Píšeme si to sami, abychom kvůli dvěma číslům netahali celou
/// knihovnu na dekódování obrázků — a hlavně abychom obrázek nemuseli
/// doopravdy rozbalovat. Rozbalování cizích dat je přesně ten druh
/// kódu, kde vznikají díry.
fn rozmery(data: &[u8], format: ImageFormat) -> Result<(u32, u32)> {
    match format {
        ImageFormat::Png => {
            // Hlavička PNG: 8 bajtů podpis, délka, "IHDR", šířka, výška.
            if data.len() < 24 || &data[12..16] != b"IHDR" {
                return Err(AdError::bad_request("PNG má poškozenou hlavičku"));
            }
            let w = u32::from_be_bytes(data[16..20].try_into().unwrap());
            let h = u32::from_be_bytes(data[20..24].try_into().unwrap());
            Ok((w, h))
        }
        ImageFormat::Jpeg => {
            // JPEG je posloupnost značek. Hledáme SOF (start of frame),
            // kde jsou rozměry. Značky SOF4, SOF8 a SOF12 jsou něco
            // jiného, ty přeskakujeme.
            let mut i = 2usize;
            while i + 9 < data.len() {
                if data[i] != 0xFF {
                    i += 1;
                    continue;
                }
                let znacka = data[i + 1];
                if (0xC0..=0xCF).contains(&znacka)
                    && znacka != 0xC4
                    && znacka != 0xC8
                    && znacka != 0xCC
                {
                    let h = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
                    let w = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
                    return Ok((w, h));
                }
                let delka = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                if delka < 2 {
                    break;
                }
                i += 2 + delka;
            }
            Err(AdError::bad_request("v JPEG se nepodařilo najít rozměry"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nejmenší platné PNG 1×1.
    fn male_png() -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&1920u32.to_be_bytes());
        v.extend_from_slice(&1080u32.to_be_bytes());
        v.extend_from_slice(&[8, 2, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]); // CRC, nekontrolujeme
        v
    }

    fn male_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8]; // SOI
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]); // APP0 délky 16
        v.extend_from_slice(&[0u8; 14]);
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]); // SOF0
        v.extend_from_slice(&800u16.to_be_bytes()); // výška
        v.extend_from_slice(&600u16.to_be_bytes()); // šířka
        v.extend_from_slice(&[0u8; 10]);
        v
    }

    #[test]
    fn rozmery_png() {
        assert_eq!(rozmery(&male_png(), ImageFormat::Png).unwrap(), (1920, 1080));
    }

    #[test]
    fn rozmery_jpeg() {
        assert_eq!(rozmery(&male_jpeg(), ImageFormat::Jpeg).unwrap(), (600, 800));
    }

    #[test]
    fn poskozene_png() {
        let mut data = male_png();
        data[13] = b'X';
        assert!(rozmery(&data, ImageFormat::Png).is_err());
        assert!(rozmery(&data[..10], ImageFormat::Png).is_err());
    }

    #[test]
    fn format_se_pozna_podle_obsahu() {
        assert_eq!(ImageFormat::poznej(&male_png()), Some(ImageFormat::Png));
        assert_eq!(ImageFormat::poznej(&male_jpeg()), Some(ImageFormat::Jpeg));
        // Obsah rozhoduje, ne přípona ani content-type.
        assert_eq!(ImageFormat::poznej(b"<svg xmlns=\"http://www.w3.org/2000/svg\">"), None);
        assert_eq!(ImageFormat::poznej(b"GIF89a"), None);
        assert_eq!(ImageFormat::poznej(b"%PDF-1.4"), None);
    }
}
