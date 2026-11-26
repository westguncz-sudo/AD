//! Spojení se serverem: TLS s připnutým otiskem a volání API.
//!
//! # Jak funguje připnutí otisku
//! Certifikát naší domény nepodepsala žádná veřejná autorita, takže ho
//! systémové úložiště nezná. Místo toho si klient pamatuje **otisk
//! certifikační autority domény** — ten mu nadiktuje správce při
//! připojení do domény.
//!
//! Samotná shoda otisku by ale nestačila. Certifikát CA je veřejný,
//! takže by ho útočník mohl poslat taky — a k němu svůj vlastní
//! certifikát serveru. Proto se dělají **dvě** věci:
//!
//! 1. Spočítá se otisk autority z řetězce a porovná se s připnutým.
//! 2. Ověří se, že certifikát serveru je **touhle autoritou podepsaný**
//!    a že platí pro jméno, na které jsme se připojili.
//!
//! Bez privátního klíče CA útočník druhý krok neobejde.

use ad_core::{secret, AdError, ErrorCode, Result};
use hyper::body::Bytes;
use hyper::Request;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::{Arc, Mutex};

/// Ověřovatel certifikátu serveru s připnutým otiskem autority.
#[derive(Debug)]
pub struct PripnutaAutorita {
    /// Otisk, který čekáme — 64 hexadecimálních znaků velkými písmeny.
    ocekavany_otisk: String,
    /// Certifikát autority, pokud už ho máme uložený z připojení.
    znama_ca: Option<CertificateDer<'static>>,
    /// Sem si uložíme autoritu, kterou server poslal — při připojení
    /// do domény si ji pak klient uloží na disk.
    zachycena_ca: Mutex<Option<Vec<u8>>>,
    provider: Arc<CryptoProvider>,
}

impl PripnutaAutorita {
    pub fn nova(otisk: &str, znama_ca_pem: Option<&str>) -> Result<Arc<Self>> {
        let ocekavany_otisk = secret::normalizuj_otisk(otisk)?;
        let znama_ca = match znama_ca_pem {
            Some(pem) => {
                let der = secret::der_z_pem(pem, "CERTIFICATE")?;
                // Uložená autorita musí sedět s uloženým otiskem.
                // Kdyby někdo přepsal soubor s certifikátem, poznáme to.
                let otisk_souboru = secret::otisk_certifikatu(&der);
                if !secret::otisky_se_rovnaji(&ocekavany_otisk, &otisk_souboru)? {
                    return Err(AdError::new(
                        ErrorCode::FingerprintMismatch,
                        "uložený certifikát autority neodpovídá uloženému otisku — \
                         někdo soubor vyměnil. Připoj počítač do domény znovu.",
                    ));
                }
                Some(CertificateDer::from(der))
            }
            None => None,
        };
        Ok(Arc::new(Self {
            ocekavany_otisk,
            znama_ca,
            zachycena_ca: Mutex::new(None),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }))
    }

    /// Certifikát autority, který server poslal (po úspěšném spojení).
    pub fn zachycena_ca(&self) -> Option<Vec<u8>> {
        self.zachycena_ca.lock().ok().and_then(|v| v.clone())
    }
}

impl ServerCertVerifier for PripnutaAutorita {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // 1. Kterou autoritu budeme považovat za kořen?
        let kandidat: CertificateDer<'static> = match &self.znama_ca {
            Some(ca) => ca.clone(),
            // Při prvním připojení autoritu neznáme — vezmeme poslední
            // certifikát z řetězce, který server poslal.
            None => match intermediates.last() {
                Some(c) => c.clone().into_owned(),
                None => end_entity.clone().into_owned(),
            },
        };

        // 2. Otisk musí sedět. Porovnání v konstantním čase.
        let otisk = secret::otisk_certifikatu(&kandidat);
        let sedi = secret::otisky_se_rovnaji(&self.ocekavany_otisk, &otisk).unwrap_or(false);
        if !sedi {
            return Err(rustls::Error::General(format!(
                "otisk certifikační autority nesouhlasí.\n  čekal jsem: {}\n  server má:  {}\n\
                 Buď jsi otisk opsal špatně, nebo se za server někdo vydává.",
                self.ocekavany_otisk, otisk
            )));
        }

        // 3. A teď to podstatné: certifikát serveru musí být touhle
        //    autoritou skutečně podepsaný a platit pro jméno, na které
        //    jsme se připojili. Samotná shoda otisku nestačí —
        //    certifikát autority je veřejný.
        let mut koreny = RootCertStore::empty();
        koreny.add(kandidat.clone()).map_err(|e| {
            rustls::Error::General(format!("certifikát autority nelze použít jako kořen: {e}"))
        })?;
        let overovatel = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(koreny),
            self.provider.clone(),
        )
        .build()
        .map_err(|e| rustls::Error::General(format!("nelze postavit ověřovatele: {e}")))?;

        overovatel.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;

        if let Ok(mut z) = self.zachycena_ca.lock() {
            *z = Some(kandidat.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Klient doménového API.
pub struct Klient {
    host: String,
    port: u16,
    config: Arc<ClientConfig>,
    overovatel: Arc<PripnutaAutorita>,
}

/// Odpověď serveru.
pub struct Odpoved {
    pub status: u16,
    pub telo: Vec<u8>,
    pub hlavicky: Vec<(String, String)>,
}

impl Odpoved {
    /// Rozebere tělo jako JSON, nebo vrátí chybu serveru.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        if !(200..300).contains(&self.status) {
            return Err(self.chyba());
        }
        serde_json::from_slice(&self.telo).map_err(|e| {
            AdError::internal(format!(
                "odpověď serveru se nepodařilo přečíst: {e}. Mluvíme opravdu s ad-serverem?"
            ))
        })
    }

    /// Chyba z odpovědi serveru v naší podobě.
    pub fn chyba(&self) -> AdError {
        match serde_json::from_slice::<ad_core::ErrorResponse>(&self.telo) {
            Ok(r) => r.error,
            Err(_) => AdError::internal(format!(
                "server odpověděl {} a tělo nedává smysl: {}",
                self.status,
                String::from_utf8_lossy(&self.telo).chars().take(200).collect::<String>()
            )),
        }
    }

    pub fn hlavicka(&self, jmeno: &str) -> Option<&str> {
        self.hlavicky.iter().find(|(k, _)| k.eq_ignore_ascii_case(jmeno)).map(|(_, v)| v.as_str())
    }
}

impl Klient {
    /// Vytvoří klienta pro daný server a připnutý otisk.
    pub fn novy(host: &str, port: u16, otisk: &str, ca_pem: Option<&str>) -> Result<Self> {
        // Poskytovatele kryptografie nainstalujeme jednou za běh programu.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let overovatel = PripnutaAutorita::nova(otisk, ca_pem)?;
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(overovatel.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self { host: host.to_string(), port, config: Arc::new(config), overovatel })
    }

    pub fn zachycena_ca_pem(&self) -> Option<String> {
        self.overovatel.zachycena_ca().map(|der| do_pem(&der))
    }

    /// Pošle požadavek na doménové API.
    pub async fn poslat(
        &self,
        metoda: &str,
        cesta: &str,
        telo: Option<&serde_json::Value>,
        token: Option<&str>,
    ) -> Result<Odpoved> {
        use http_body_util::{BodyExt, Full};

        let adresa = format!("{}:{}", self.host, self.port);
        let proud = tokio::net::TcpStream::connect(&adresa).await.map_err(|e| {
            AdError::internal(format!(
                "nelze se připojit na {adresa}: {e}. Běží server a je ta adresa správná?"
            ))
        })?;
        let _ = proud.set_nodelay(true);

        // Jméno v certifikátu se kontroluje proti tomu, co jsme zadali.
        let jmeno = ServerName::try_from(self.host.clone()).map_err(|_| {
            AdError::bad_request(format!("{} není platné jméno ani adresa serveru", self.host))
        })?;
        let konektor = tokio_rustls::TlsConnector::from(self.config.clone());
        let tls = konektor.connect(jmeno, proud).await.map_err(|e| {
            let text = e.to_string();
            if text.contains("otisk certifikační autority") {
                AdError::new(ErrorCode::FingerprintMismatch, text)
            } else {
                AdError::internal(format!("TLS spojení selhalo: {text}"))
            }
        })?;

        let (mut odesilatel, spojeni) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| AdError::internal(format!("HTTP spojení selhalo: {e}")))?;
        tokio::spawn(async move {
            let _ = spojeni.await;
        });

        let data = match telo {
            Some(v) => serde_json::to_vec(v)
                .map_err(|e| AdError::internal(format!("tělo požadavku: {e}")))?,
            None => Vec::new(),
        };

        let mut stavitel = Request::builder()
            .method(metoda)
            .uri(cesta)
            .header("host", format!("{}:{}", self.host, self.port))
            .header(ad_core::proto::HLAVICKA_PROTO, ad_core::proto::PROTO_VERZE.to_string())
            .header(ad_core::proto::HLAVICKA_KLIENT, format!("ad-client/{}", ad_core::VERZE))
            .header("accept", "application/json");
        if telo.is_some() {
            stavitel = stavitel.header("content-type", "application/json");
        }
        if let Some(t) = token {
            stavitel = stavitel.header("authorization", format!("Bearer {t}"));
        }

        let pozadavek = stavitel
            .body(Full::new(Bytes::from(data)))
            .map_err(|e| AdError::internal(format!("požadavek: {e}")))?;

        let odpoved = odesilatel
            .send_request(pozadavek)
            .await
            .map_err(|e| AdError::internal(format!("požadavek selhal: {e}")))?;

        let status = odpoved.status().as_u16();
        let hlavicky: Vec<(String, String)> = odpoved
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let telo = odpoved
            .into_body()
            .collect()
            .await
            .map_err(|e| AdError::internal(format!("tělo odpovědi: {e}")))?
            .to_bytes()
            .to_vec();

        Ok(Odpoved { status, telo, hlavicky })
    }
}

/// Certifikát v DER na PEM.
pub fn do_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for radek in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(radek).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otisk_se_pri_vytvoreni_znormalizuje() {
        let o = "ab:cd".to_string() + &"ef".repeat(30);
        let v = PripnutaAutorita::nova(&o, None).unwrap();
        assert_eq!(v.ocekavany_otisk.len(), 64);
        assert!(v.ocekavany_otisk.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn nesmyslny_otisk_se_odmitne() {
        assert!(PripnutaAutorita::nova("abc", None).is_err());
        assert!(PripnutaAutorita::nova("", None).is_err());
        assert!(PripnutaAutorita::nova(&"z".repeat(64), None).is_err());
    }

    #[test]
    fn ulozena_ca_musi_sedet_s_otiskem() {
        let der = b"predstirany certifikat";
        let pem = do_pem(der);
        let spravny = secret::otisk_certifikatu(der);

        // Se správným otiskem to projde.
        PripnutaAutorita::nova(&spravny, Some(&pem)).unwrap();

        // S cizím otiskem ne — někdo vyměnil soubor s certifikátem.
        let cizi = secret::otisk_certifikatu(b"jiny certifikat");
        let e = PripnutaAutorita::nova(&cizi, Some(&pem)).unwrap_err();
        assert_eq!(e.code, ErrorCode::FingerprintMismatch);
    }

    #[test]
    fn pem_tam_a_zpet() {
        let der = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pem = do_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(secret::der_z_pem(&pem, "CERTIFICATE").unwrap(), der);
    }

    #[test]
    fn dlouhy_der_se_zalomi_po_64_znacich() {
        let der = vec![0xABu8; 200];
        let pem = do_pem(&der);
        for radek in pem.lines().filter(|r| !r.starts_with("-----")) {
            assert!(radek.len() <= 64, "řádek PEM je delší než 64 znaků");
        }
        assert_eq!(secret::der_z_pem(&pem, "CERTIFICATE").unwrap(), der);
    }
}
