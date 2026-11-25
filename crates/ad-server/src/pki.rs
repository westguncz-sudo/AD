//! Vlastní certifikační autorita a certifikát serveru.
//!
//! Při povýšení na řadič domény vznikne CA a jí podepsaný certifikát
//! serveru. Klient si **připne otisk CA** (ne serveru), takže se dá
//! certifikát serveru obnovit, aniž by to klientům něco rozbilo.
//!
//! Soubory v `pki/`:
//! * `ca.pem` — certifikát CA, tenhle dostane klient
//! * `ca.key` — privátní klíč CA (práva 0600), nikdy nikam neodchází
//! * `server.pem`, `server.key` — certifikát serveru a jeho klíč
//!
//! CA se po vytvoření **nemění**. Parametry se skládají deterministicky
//! ze jména domény, takže k podepsání dalšího certifikátu stačí klíč
//! a jméno domény z databáze — nemusíme certifikát parsovat.

use ad_core::{secret, AdError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// Jak dlouho platí certifikát CA.
pub const PLATNOST_CA_DNU: i64 = 3650;
/// Jak dlouho platí certifikát serveru.
pub const PLATNOST_SERVERU_DNU: i64 = 395;
/// Kolik dní před vypršením certifikát serveru obnovíme (fáze 6).
#[allow(dead_code)]
pub const OBNOVIT_PRED_DNY: i64 = 30;

/// Certifikát a jeho klíč v PEM.
#[derive(Debug, Clone)]
pub struct Vydany {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Složí jméno (DN) certifikační autority domény.
fn dn_ca(domena: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("AD Domain CA ({domena})"));
    dn.push(DnType::OrganizationName, domena.to_string());
    dn
}

/// Parametry CA. Deterministické — ze stejné domény vždy stejné.
fn params_ca(domena: &str, nyni: OffsetDateTime) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AdError::internal(format!("parametry CA: {e}")))?;
    p.distinguished_name = dn_ca(domena);
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = nyni - Duration::hours(1);
    p.not_after = nyni + Duration::days(PLATNOST_CA_DNU);
    Ok(p)
}

/// Vytvoří novou certifikační autoritu domény.
pub fn vytvor_ca(domena: &str) -> Result<Vydany> {
    let nyni = OffsetDateTime::now_utc();
    let params = params_ca(domena, nyni)?;
    let klic = KeyPair::generate().map_err(|e| AdError::internal(format!("klíč CA: {e}")))?;
    let cert =
        params.self_signed(&klic).map_err(|e| AdError::internal(format!("podpis CA: {e}")))?;
    Ok(Vydany { cert_pem: cert.pem(), key_pem: klic.serialize_pem() })
}

/// Vydá certifikát serveru podepsaný naší CA.
///
/// `jmena` jsou DNS jména (např. `dc01.skola.internal`, `dc01`),
/// `adresy` IP adresy, na kterých je server dostupný. Obojí se dostane
/// do SAN — klient se smí připojit jen na jméno nebo adresu, která tam je.
pub fn vydej_server_cert(
    domena: &str,
    ca_key_pem: &str,
    jmena: &[String],
    adresy: &[IpAddr],
) -> Result<Vydany> {
    if jmena.is_empty() && adresy.is_empty() {
        return Err(AdError::bad_request("certifikát serveru musí mít alespoň jedno jméno"));
    }
    let nyni = OffsetDateTime::now_utc();

    let ca_klic = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| AdError::internal(format!("klíč CA nelze přečíst: {e}")))?;
    let ca_params = params_ca(domena, nyni)?;
    let vydavatel = Issuer::new(ca_params, ca_klic);

    let mut p = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AdError::internal(format!("parametry certifikátu: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, jmena.first().cloned().unwrap_or_else(|| domena.to_string()));
    dn.push(DnType::OrganizationName, domena.to_string());
    p.distinguished_name = dn;
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.not_before = nyni - Duration::hours(1);
    p.not_after = nyni + Duration::days(PLATNOST_SERVERU_DNU);

    let mut san = Vec::new();
    for j in jmena {
        san.push(SanType::DnsName(
            j.clone().try_into().map_err(|_| {
                AdError::bad_request(format!("jméno {j} se nedá dát do certifikátu"))
            })?,
        ));
    }
    for a in adresy {
        san.push(SanType::IpAddress(*a));
    }
    p.subject_alt_names = san;

    let klic = KeyPair::generate().map_err(|e| AdError::internal(format!("klíč serveru: {e}")))?;
    let cert = p
        .signed_by(&klic, &vydavatel)
        .map_err(|e| AdError::internal(format!("podpis certifikátu serveru: {e}")))?;
    Ok(Vydany { cert_pem: cert.pem(), key_pem: klic.serialize_pem() })
}

/// Cesty k souborům PKI.
pub struct SouboryPki {
    pub ca_cert: std::path::PathBuf,
    pub ca_key: std::path::PathBuf,
    pub server_cert: std::path::PathBuf,
    pub server_key: std::path::PathBuf,
}

impl SouboryPki {
    pub fn v(dir: &Path) -> Self {
        Self {
            ca_cert: dir.join("ca.pem"),
            ca_key: dir.join("ca.key"),
            server_cert: dir.join("server.pem"),
            server_key: dir.join("server.key"),
        }
    }

    pub fn existuji(&self) -> bool {
        self.ca_cert.exists() && self.ca_key.exists() && self.server_cert.exists()
    }
}

/// Uloží CA a certifikát serveru na disk se správnými právy.
pub fn uloz(dir: &Path, ca: &Vydany, server: &Vydany) -> Result<()> {
    let s = SouboryPki::v(dir);
    // Certifikáty jsou veřejné, klíče ne.
    zapis(&s.ca_cert, &ca.cert_pem, false)?;
    zapis(&s.ca_key, &ca.key_pem, true)?;
    zapis(&s.server_cert, &server.cert_pem, false)?;
    zapis(&s.server_key, &server.key_pem, true)?;
    Ok(())
}

fn zapis(cesta: &Path, obsah: &str, tajne: bool) -> Result<()> {
    std::fs::write(cesta, obsah)
        .map_err(|e| AdError::internal(format!("nelze zapsat {}: {e}", cesta.display())))?;
    if tajne {
        crate::config::omez_prava(cesta)?;
    }
    Ok(())
}

/// Načte otisk CA z disku. Používá to i test povýšení.
#[allow(dead_code)]
pub fn otisk_ca(dir: &Path) -> Result<String> {
    let s = SouboryPki::v(dir);
    let pem = std::fs::read_to_string(&s.ca_cert)
        .map_err(|e| AdError::internal(format!("nelze přečíst {}: {e}", s.ca_cert.display())))?;
    secret::otisk_z_pem(&pem)
}

/// Načte certifikát CA v PEM (posílá se klientovi při připojení).
pub fn ca_pem(dir: &Path) -> Result<String> {
    let s = SouboryPki::v(dir);
    std::fs::read_to_string(&s.ca_cert)
        .map_err(|e| AdError::internal(format!("nelze přečíst {}: {e}", s.ca_cert.display())))
}

/// Postaví konfiguraci TLS pro `rustls` z uložených souborů.
///
/// Posíláme celý řetězec (certifikát serveru + CA), aby klient uměl
/// ověřit i bez toho, že by CA už měl — připnutý otisk ale pořád platí.
pub fn tls_config(dir: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let s = SouboryPki::v(dir);
    let cert_pem = std::fs::read_to_string(&s.server_cert).map_err(|e| {
        AdError::internal(format!("nelze přečíst {}: {e}", s.server_cert.display()))
    })?;
    let key_pem = std::fs::read_to_string(&s.server_key)
        .map_err(|e| AdError::internal(format!("nelze přečíst {}: {e}", s.server_key.display())))?;
    let ca_cert_pem = std::fs::read_to_string(&s.ca_cert)
        .map_err(|e| AdError::internal(format!("nelze přečíst {}: {e}", s.ca_cert.display())))?;

    let mut retez: Vec<rustls::pki_types::CertificateDer<'static>> =
        secret::pem_bloky(&cert_pem, "CERTIFICATE")?
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
    retez.extend(
        secret::pem_bloky(&ca_cert_pem, "CERTIFICATE")?
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from),
    );

    let klic_der = secret::der_z_pem(&key_pem, "PRIVATE KEY")?;
    let klic = rustls::pki_types::PrivateKeyDer::Pkcs8(klic_der.into());

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(retez, klic)
        .map_err(|e| AdError::internal(format!("TLS konfigurace: {e}")))?;
    // HTTP/1.1 — HTTP/2 zatím nepoužíváme, ať je protokol jednoduchý.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Nainstaluje kryptografického poskytovatele pro `rustls`.
/// Musí se zavolat jednou při startu, dřív než se postaví TLS.
pub fn init_rustls() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| AdError::internal("poskytovatele kryptografie už někdo nainstaloval"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_a_server_cert_se_vytvori() {
        let ca = vytvor_ca("skola.internal").unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("BEGIN PRIVATE KEY"));

        let server = vydej_server_cert(
            "skola.internal",
            &ca.key_pem,
            &["dc01.skola.internal".to_string(), "dc01".to_string()],
            &["192.168.56.10".parse().unwrap()],
        )
        .unwrap();
        assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_ne!(server.cert_pem, ca.cert_pem);
    }

    #[test]
    fn otisk_ca_je_stabilni_a_jiny_nez_serveru() {
        let ca = vytvor_ca("skola.internal").unwrap();
        let o1 = secret::otisk_z_pem(&ca.cert_pem).unwrap();
        let o2 = secret::otisk_z_pem(&ca.cert_pem).unwrap();
        assert_eq!(o1, o2, "otisk téhož certifikátu se nesmí měnit");
        assert_eq!(o1.len(), 95);

        let server =
            vydej_server_cert("skola.internal", &ca.key_pem, &["dc01.skola.internal".into()], &[])
                .unwrap();
        assert_ne!(o1, secret::otisk_z_pem(&server.cert_pem).unwrap());
    }

    #[test]
    fn dve_ca_maji_jiny_otisk() {
        let a = vytvor_ca("skola.internal").unwrap();
        let b = vytvor_ca("skola.internal").unwrap();
        assert_ne!(
            secret::otisk_z_pem(&a.cert_pem).unwrap(),
            secret::otisk_z_pem(&b.cert_pem).unwrap(),
            "podvržená CA se stejným jménem musí mít jiný otisk"
        );
    }

    #[test]
    fn obnova_certifikatu_serveru_nemeni_otisk_ca() {
        // To je ten důvod, proč klient připíná CA a ne server.
        let ca = vytvor_ca("skola.internal").unwrap();
        let otisk_pred = secret::otisk_z_pem(&ca.cert_pem).unwrap();
        let s1 =
            vydej_server_cert("skola.internal", &ca.key_pem, &["dc01.skola.internal".into()], &[])
                .unwrap();
        let s2 =
            vydej_server_cert("skola.internal", &ca.key_pem, &["dc01.skola.internal".into()], &[])
                .unwrap();
        assert_ne!(s1.cert_pem, s2.cert_pem, "nový certifikát serveru je jiný");
        assert_eq!(otisk_pred, secret::otisk_z_pem(&ca.cert_pem).unwrap());
    }

    #[test]
    fn cert_bez_jmena_i_adresy_je_chyba() {
        let ca = vytvor_ca("skola.internal").unwrap();
        assert!(vydej_server_cert("skola.internal", &ca.key_pem, &[], &[]).is_err());
    }

    #[test]
    fn tls_konfigurace_se_postavi_ze_souboru() {
        let _ = init_rustls();
        let dir = std::env::temp_dir().join(format!("ad-pki-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = vytvor_ca("skola.internal").unwrap();
        let server =
            vydej_server_cert("skola.internal", &ca.key_pem, &["dc01.skola.internal".into()], &[])
                .unwrap();
        uloz(&dir, &ca, &server).unwrap();
        assert!(SouboryPki::v(&dir).existuji());
        assert_eq!(otisk_ca(&dir).unwrap(), secret::otisk_z_pem(&ca.cert_pem).unwrap());
        tls_config(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
