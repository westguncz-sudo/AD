//! Chybové kódy společné pro server i klienta.
//!
//! Každá chyba má stabilní strojový kód (`code`) a lidský text (`message`).
//! Klient i webové rozhraní se rozhodují podle `code`, nikdy podle textu —
//! texty se dají překládat, kódy ne.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stabilní strojové kódy chyb. Serializují se jako `snake_case` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // --- obecné ---
    /// Vstup nesplňuje schéma (chybí pole, špatný typ, neznámé pole).
    BadRequest,
    /// Objekt neexistuje.
    NotFound,
    /// Objekt už existuje / konflikt stavu.
    Conflict,
    /// Vnitřní chyba serveru (podrobnosti jen do logu, ne klientovi).
    Internal,
    /// Příliš mnoho požadavků (ochrana proti hádání hesel).
    RateLimited,
    /// Klient mluví jinou verzí protokolu.
    ProtoVersionUnsupported,
    /// Požadovaná funkce ještě není implementovaná.
    NotImplemented,

    // --- autentizace a autorizace ---
    /// Chybí přihlášení (session cookie / bearer token).
    AuthRequired,
    /// Jméno nebo heslo nesouhlasí. Nikdy neprozrazujeme, co z toho.
    InvalidCredentials,
    /// Účet je vypnutý.
    AccountDisabled,
    /// Účet je zamčený po příliš mnoha neúspěšných pokusech.
    AccountLocked,
    /// Heslo vypršelo nebo je vynucena změna při příštím přihlášení.
    PasswordChangeRequired,
    /// Nové heslo nesplňuje zásady.
    PasswordPolicyViolation,
    /// Přihlášený uživatel nemá dost práv.
    PermissionDenied,
    /// Chybí nebo nesouhlasí CSRF token.
    CsrfFailed,
    /// Session vypršela.
    SessionExpired,

    // --- stav domény ---
    /// Role (AD / DNS) není nainstalovaná.
    RoleNotInstalled,
    /// Server ještě není řadič domény.
    DomainNotCreated,
    /// Doména už existuje, nelze vytvořit druhou.
    DomainAlreadyExists,
    /// Kontrola předpokladů povýšení neprošla.
    PrerequisiteFailed,

    // --- připojení počítače ---
    /// Server nezná tento počítačový účet.
    MachineUnknown,
    /// Tajemství počítačového účtu nesouhlasí.
    MachineSecretInvalid,
    /// Počítač už je v doméně.
    MachineAlreadyJoined,
    /// Otisk certifikátu serveru nesouhlasí s uloženým (možný MITM).
    FingerprintMismatch,

    // --- validace jmen a hodnot ---
    /// Jméno nesplňuje pravidla.
    InvalidName,
    /// Jméno domény nesplňuje pravidla (např. `.local`).
    InvalidDomainName,
    /// Jméno je vyhrazené pro systém.
    ReservedName,
    /// Hodnota je mimo povolený rozsah.
    OutOfRange,

    // --- DNS ---
    /// Zóna neexistuje.
    ZoneNotFound,
    /// Záznam koliduje s jiným (např. dvě CNAME na stejném jménu).
    RecordConflict,
}

impl ErrorCode {
    /// HTTP status, který se k chybě hodí.
    pub fn http_status(self) -> u16 {
        use ErrorCode::*;
        match self {
            BadRequest
            | InvalidName
            | InvalidDomainName
            | ReservedName
            | OutOfRange
            | PasswordPolicyViolation
            | ProtoVersionUnsupported => 400,
            AuthRequired | InvalidCredentials | SessionExpired | MachineSecretInvalid => 401,
            PermissionDenied
            | CsrfFailed
            | AccountDisabled
            | AccountLocked
            | PasswordChangeRequired
            | FingerprintMismatch => 403,
            NotFound | ZoneNotFound | MachineUnknown => 404,
            Conflict | DomainAlreadyExists | MachineAlreadyJoined | RecordConflict
            | RoleNotInstalled | DomainNotCreated | PrerequisiteFailed => 409,
            RateLimited => 429,
            NotImplemented => 501,
            Internal => 500,
        }
    }

    /// Řetězcová podoba kódu (stejná jako v JSON).
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            BadRequest => "bad_request",
            NotFound => "not_found",
            Conflict => "conflict",
            Internal => "internal",
            RateLimited => "rate_limited",
            ProtoVersionUnsupported => "proto_version_unsupported",
            NotImplemented => "not_implemented",
            AuthRequired => "auth_required",
            InvalidCredentials => "invalid_credentials",
            AccountDisabled => "account_disabled",
            AccountLocked => "account_locked",
            PasswordChangeRequired => "password_change_required",
            PasswordPolicyViolation => "password_policy_violation",
            PermissionDenied => "permission_denied",
            CsrfFailed => "csrf_failed",
            SessionExpired => "session_expired",
            RoleNotInstalled => "role_not_installed",
            DomainNotCreated => "domain_not_created",
            DomainAlreadyExists => "domain_already_exists",
            PrerequisiteFailed => "prerequisite_failed",
            MachineUnknown => "machine_unknown",
            MachineSecretInvalid => "machine_secret_invalid",
            MachineAlreadyJoined => "machine_already_joined",
            FingerprintMismatch => "fingerprint_mismatch",
            InvalidName => "invalid_name",
            InvalidDomainName => "invalid_domain_name",
            ReservedName => "reserved_name",
            OutOfRange => "out_of_range",
            ZoneNotFound => "zone_not_found",
            RecordConflict => "record_conflict",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Chyba, kterou lze poslat po drátě.
///
/// `details` je volitelná mapa pro strojové podrobnosti (např. která pravidla
/// hesla selhala). Nikdy do ní nedáváme hesla ani hashe.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct AdError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl AdError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: None }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    // Zkratky pro nejčastější případy.
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, m)
    }
    pub fn invalid_name(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidName, m)
    }
    pub fn out_of_range(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::OutOfRange, m)
    }
    pub fn permission_denied(m: impl Into<String>) -> Self {
        Self::new(ErrorCode::PermissionDenied, m)
    }
}

/// Obálka chyby v odpovědi HTTP: `{"error": {...}}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: AdError,
}

impl From<AdError> for ErrorResponse {
    fn from(error: AdError) -> Self {
        Self { error }
    }
}

pub type Result<T, E = AdError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kod_se_serializuje_jako_snake_case() {
        let e = AdError::new(ErrorCode::InvalidCredentials, "ne");
        let j = serde_json::to_string(&ErrorResponse::from(e)).unwrap();
        assert_eq!(j, r#"{"error":{"code":"invalid_credentials","message":"ne"}}"#);
    }

    #[test]
    fn as_str_odpovida_serde() {
        for c in [
            ErrorCode::BadRequest,
            ErrorCode::FingerprintMismatch,
            ErrorCode::PasswordPolicyViolation,
            ErrorCode::ZoneNotFound,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(j, format!("\"{}\"", c.as_str()));
        }
    }

    #[test]
    fn status_kody_jsou_rozumne() {
        assert_eq!(ErrorCode::InvalidCredentials.http_status(), 401);
        assert_eq!(ErrorCode::RateLimited.http_status(), 429);
        assert_eq!(ErrorCode::DomainAlreadyExists.http_status(), 409);
    }
}
