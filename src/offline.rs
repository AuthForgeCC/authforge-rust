//! Offline license files (`.authforge`).
//!
//! A cloud-minted, Ed25519-signed document for machines that never phone
//! home. This is a **separate** mode from the grace period: the grace period
//! continues a signed session after one online activation, while an offline
//! file is verified locally with only the app public key and the machine
//! HWID. Nothing in this module performs network I/O or starts online
//! check-ins.
//!
//! Format (version 1):
//!
//! ```text
//! -----BEGIN AUTHFORGE LICENSE-----
//! Version: 1
//! App-Id: <appId>
//! License: <licenseKey>
//! Key-Id: <kid>
//! Expires-At: <ISO-8601 | never>
//!
//! <base64 JSON payload, wrapped at 64 columns>
//! -----END AUTHFORGE LICENSE-----
//! -----BEGIN AUTHFORGE SIGNATURE-----
//! <base64 Ed25519 signature>
//! -----END AUTHFORGE SIGNATURE-----
//! ```
//!
//! Signed bytes: the UTF-8 bytes of the base64 payload string (body lines
//! joined, whitespace removed) - the same contract as `/auth/validate`.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::verify_payload_signature_ed25519_any;

use sha2::{Digest, Sha256};

/// The only `.authforge` format version this SDK accepts.
pub const OFFLINE_LICENSE_FILE_VERSION: u64 = 1;

const BEGIN_LICENSE: &str = "-----BEGIN AUTHFORGE LICENSE-----";
const END_LICENSE: &str = "-----END AUTHFORGE LICENSE-----";
const BEGIN_SIGNATURE: &str = "-----BEGIN AUTHFORGE SIGNATURE-----";
const END_SIGNATURE: &str = "-----END AUTHFORGE SIGNATURE-----";

/// Why an offline license file was rejected. Variants are listed in check
/// order, which is fixed across every SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineLicenseError {
    /// Not well-formed `.authforge` armor.
    BadArmor,
    /// Signature does not verify against any configured public key.
    BadSignature,
    /// Payload `v` is not a version this SDK understands.
    UnsupportedVersion,
    /// Signed payload is not a valid v1 license document.
    MalformedPayload,
    /// Payload `appId` differs from the configured app.
    WrongApp,
    /// `expiresAt` is in the past.
    Expired,
    /// File is HWID-bound and the local HWID is not in the list.
    HwidMismatch,
    /// The path could not be read (only from the client `*_from_file` helpers).
    ReadError(String)
}

impl OfflineLicenseError {
    /// Cross-SDK error code (`bad_armor`, `bad_signature`, ...).
    pub fn code(&self) -> &'static str {
        match self {
            OfflineLicenseError::BadArmor => "bad_armor",
            OfflineLicenseError::BadSignature => "bad_signature",
            OfflineLicenseError::UnsupportedVersion => "unsupported_version",
            OfflineLicenseError::MalformedPayload => "malformed_payload",
            OfflineLicenseError::WrongApp => "wrong_app",
            OfflineLicenseError::Expired => "expired",
            OfflineLicenseError::HwidMismatch => "hwid_mismatch",
            OfflineLicenseError::ReadError(_) => "read_error"
        }
    }
}

impl fmt::Display for OfflineLicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OfflineLicenseError::ReadError(detail) => write!(f, "read_error: {detail}"),
            other => f.write_str(other.code())
        }
    }
}

impl std::error::Error for OfflineLicenseError {}

/// HWID binding policy embedded in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineHwidPolicy {
    /// Verifies only when the local HWID is one of these.
    Bound(Vec<String>),
    /// Verifies on any machine.
    Any
}

/// Verified content of a `.authforge` file.
#[derive(Debug, Clone)]
pub struct OfflineLicense {
    pub app_id: String,
    pub license_key: String,
    /// Unique id of this minted file.
    pub jti: String,
    /// App signing key id that signed the file.
    pub key_id: String,
    pub issued_at: String,
    /// `None` for a lifetime file.
    pub expires_at: Option<String>,
    pub hwid_policy: OfflineHwidPolicy,
    pub label: Option<String>,
    /// `Some(None)` when the license itself is perpetual; `None` when absent.
    pub license_expires_at: Option<Option<String>>,
    pub license_variables: Option<HashMap<String, Value>>,
    pub app_variables: Option<HashMap<String, Value>>,
    /// Full decoded payload (unknown fields preserved).
    pub payload: Value,
    /// Canonical signed string and its signature.
    pub payload_base64: String,
    pub signature_base64: String
}

/// Raw armor split into parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLicenseFile {
    pub headers: HashMap<String, String>,
    /// Exactly the string the signature covers.
    pub payload_base64: String,
    pub signature_base64: String
}

fn is_base64_text(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() && (bytes[idx].is_ascii_alphanumeric() || bytes[idx] == b'+' || bytes[idx] == b'/') {
        idx += 1;
    }
    if idx == 0 {
        return false;
    }
    let padding = &bytes[idx..];
    padding.len() <= 2 && padding.iter().all(|b| *b == b'=')
}

/// Split armored `.authforge` text into headers, the canonical base64 payload
/// string and the base64 signature. Tolerates CRLF, a UTF-8 BOM, arbitrary
/// re-wrapping of the base64 body and text before/after the armor.
pub fn parse_license_file(text: &str) -> Result<ParsedLicenseFile, OfflineLicenseError> {
    let normalized = text
        .trim_start_matches('\u{FEFF}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();

    let find = |marker: &str, start: usize| -> Option<usize> {
        (start..lines.len()).find(|&i| lines[i].trim() == marker)
    };

    let begin_idx = find(BEGIN_LICENSE, 0).ok_or(OfflineLicenseError::BadArmor)?;
    let end_idx = find(END_LICENSE, begin_idx + 1).ok_or(OfflineLicenseError::BadArmor)?;
    let sig_begin_idx = find(BEGIN_SIGNATURE, end_idx + 1).ok_or(OfflineLicenseError::BadArmor)?;
    let sig_end_idx = find(END_SIGNATURE, sig_begin_idx + 1).ok_or(OfflineLicenseError::BadArmor)?;

    let block = &lines[begin_idx + 1..end_idx];
    let blank_idx = block
        .iter()
        .position(|line| line.trim().is_empty())
        .ok_or(OfflineLicenseError::BadArmor)?;

    let mut headers = HashMap::new();
    for raw in &block[..blank_idx] {
        let line = raw.trim();
        let colon = line.find(':').ok_or(OfflineLicenseError::BadArmor)?;
        if colon == 0 {
            return Err(OfflineLicenseError::BadArmor);
        }
        headers.insert(line[..colon].trim().to_string(), line[colon + 1..].trim().to_string());
    }

    let strip_ws = |parts: &[&str]| -> String {
        parts
            .iter()
            .flat_map(|line| line.chars())
            .filter(|c| !c.is_whitespace())
            .collect()
    };
    let payload_base64 = strip_ws(&block[blank_idx + 1..]);
    let signature_base64 = strip_ws(&lines[sig_begin_idx + 1..sig_end_idx]);
    if !is_base64_text(&payload_base64) || !is_base64_text(&signature_base64) {
        return Err(OfflineLicenseError::BadArmor);
    }
    Ok(ParsedLicenseFile {
        headers,
        payload_base64,
        signature_base64
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawHwidPolicy {
    mode: String,
    hwids: Option<Vec<String>>
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPayload {
    typ: Option<String>,
    app_id: Option<String>,
    license_key: Option<String>,
    jti: Option<String>,
    kid: Option<String>,
    issued_at: Option<String>,
    // `Option<Option<_>>` distinguishes "absent" from explicit `null`.
    #[serde(default, deserialize_with = "deserialize_double_option")]
    expires_at: Option<Option<String>>,
    hwid: Option<RawHwidPolicy>,
    label: Option<String>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    license_expires_at: Option<Option<String>>,
    license_variables: Option<HashMap<String, Value>>,
    app_variables: Option<HashMap<String, Value>>
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>
{
    Option::<String>::deserialize(deserializer).map(Some)
}

/// Options for [`verify_license_file`].
#[derive(Debug, Clone, Default)]
pub struct VerifyLicenseFileOptions {
    /// Must equal the payload `appId`.
    pub app_id: String,
    /// Trusted raw-32-byte Ed25519 keys, standard base64 (same forms as the
    /// client config). A signature matching any key is accepted.
    pub public_keys: Vec<String>,
    /// Local machine id; required for HWID-bound files.
    pub hwid: Option<String>,
    /// Clock override in epoch milliseconds (tests). `None` = now.
    pub now_epoch_ms: Option<i64>
}

fn non_empty(value: Option<String>) -> Result<String, OfflineLicenseError> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(OfflineLicenseError::MalformedPayload)
    }
}

/// Verify armored `.authforge` text with NO network access. The signature is
/// checked before the payload JSON is decoded so a forged file never reaches
/// the parser.
pub fn verify_license_file(
    file: &str,
    opts: &VerifyLicenseFileOptions
) -> Result<OfflineLicense, OfflineLicenseError> {
    let parsed = parse_license_file(file)?;

    let keys: Vec<String> = opts
        .public_keys
        .iter()
        .flat_map(|entry| entry.split(','))
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let verified = verify_payload_signature_ed25519_any(&parsed.payload_base64, &parsed.signature_base64, &keys)
        .unwrap_or(false);
    if !verified {
        return Err(OfflineLicenseError::BadSignature);
    }

    let decoded = STANDARD
        .decode(&parsed.payload_base64)
        .map_err(|_| OfflineLicenseError::MalformedPayload)?;
    let payload: Value = serde_json::from_slice(&decoded).map_err(|_| OfflineLicenseError::MalformedPayload)?;
    if !payload.is_object() {
        return Err(OfflineLicenseError::MalformedPayload);
    }
    match payload.get("v").and_then(Value::as_u64) {
        Some(v) if v == OFFLINE_LICENSE_FILE_VERSION => {}
        _ => return Err(OfflineLicenseError::UnsupportedVersion)
    }

    let raw: RawPayload = serde_json::from_value(payload.clone()).map_err(|_| OfflineLicenseError::MalformedPayload)?;
    if raw.typ.as_deref() != Some("authforge-license") {
        return Err(OfflineLicenseError::MalformedPayload);
    }
    let app_id = non_empty(raw.app_id)?;
    let license_key = non_empty(raw.license_key)?;
    let jti = non_empty(raw.jti)?;
    let key_id = non_empty(raw.kid)?;
    let issued_at = non_empty(raw.issued_at)?;
    let expires_at = match raw.expires_at {
        None => return Err(OfflineLicenseError::MalformedPayload),
        Some(None) => None,
        Some(Some(value)) if !value.is_empty() => Some(value),
        Some(Some(_)) => return Err(OfflineLicenseError::MalformedPayload)
    };
    let hwid_policy = match raw.hwid {
        Some(RawHwidPolicy { mode, hwids }) if mode == "bound" => {
            let list = hwids.unwrap_or_default();
            if list.is_empty() || list.iter().any(String::is_empty) {
                return Err(OfflineLicenseError::MalformedPayload);
            }
            OfflineHwidPolicy::Bound(list)
        }
        Some(RawHwidPolicy { mode, .. }) if mode == "any" => OfflineHwidPolicy::Any,
        _ => return Err(OfflineLicenseError::MalformedPayload)
    };

    if app_id != opts.app_id.trim() {
        return Err(OfflineLicenseError::WrongApp);
    }

    let now_ms = opts.now_epoch_ms.unwrap_or_else(epoch_now_ms);
    if let Some(exp) = &expires_at {
        match parse_iso8601_ms(exp) {
            Some(exp_ms) if exp_ms > now_ms => {}
            _ => return Err(OfflineLicenseError::Expired)
        }
    }

    if let OfflineHwidPolicy::Bound(list) = &hwid_policy {
        let local = opts.hwid.as_deref().map(str::trim).unwrap_or("");
        if local.is_empty() || !list.iter().any(|h| h == local) {
            return Err(OfflineLicenseError::HwidMismatch);
        }
    }

    Ok(OfflineLicense {
        app_id,
        license_key,
        jti,
        key_id,
        issued_at,
        expires_at,
        hwid_policy,
        label: raw.label,
        license_expires_at: raw.license_expires_at,
        license_variables: raw.license_variables,
        app_variables: raw.app_variables,
        payload,
        payload_base64: parsed.payload_base64,
        signature_base64: parsed.signature_base64
    })
}

pub(crate) fn epoch_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn contains_armor(text: &str) -> bool {
    text.contains(BEGIN_LICENSE)
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]` into epoch milliseconds
/// without pulling in a date-time crate. Returns `None` for anything else.
pub fn parse_iso8601_ms(value: &str) -> Option<i64> {
    let s = value.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b' ') || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s.get(from..to)?.parse::<i64>().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &s[19..];
    let mut millis: i64 = 0;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len == 0 {
            return None;
        }
        let digits = &after_dot[..digits_len];
        let scaled: String = digits.chars().chain(std::iter::repeat('0')).take(3).collect();
        millis = scaled.parse::<i64>().ok()?;
        rest = &after_dot[digits_len..];
    }

    let offset_seconds: i64 = if rest.is_empty() || rest == "Z" || rest == "z" {
        0
    } else {
        let sign = match rest.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None
        };
        let body = &rest[1..];
        let (oh, om) = if body.len() == 5 && body.as_bytes()[2] == b':' {
            (body[..2].parse::<i64>().ok()?, body[3..].parse::<i64>().ok()?)
        } else if body.len() == 4 {
            (body[..2].parse::<i64>().ok()?, body[2..].parse::<i64>().ok()?)
        } else if body.len() == 2 {
            (body.parse::<i64>().ok()?, 0)
        } else {
            return None;
        };
        sign * (oh * 3600 + om * 60)
    };

    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_seconds;
    Some(seconds * 1000 + millis)
}

/// Howard Hinnant's days-from-civil: days since 1970-01-01 for a proleptic
/// Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Activation requests (`.authforge-request`)
// ---------------------------------------------------------------------------

const ACTIVATION_REQUEST_VERSION: u64 = 1;
const ACTIVATION_REQUEST_TYP: &str = "authforge-activation-request";
const BEGIN_ACTIVATION_REQUEST: &str = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----";
const END_ACTIVATION_REQUEST: &str = "-----END AUTHFORGE ACTIVATION REQUEST-----";
// Derived from Cargo.toml so a version bump cannot leave this behind.
const ACTIVATION_REQUEST_SDK_TAG: &str = concat!("rust/", env!("CARGO_PKG_VERSION"));
const ARMOR_LINE_WIDTH: usize = 64;
const MAX_REQUEST_HWID: usize = 256;
const MAX_REQUEST_MACHINE_NAME: usize = 128;
const MAX_REQUEST_OS: usize = 64;
const MAX_REQUEST_SDK: usize = 64;
const MAX_REQUEST_LICENSE_KEY: usize = 64;

/// Optional fields for [`crate::AuthForgeClient::create_activation_request`].
/// `machine_name` is omitted unless `include_machine_name` is true.
#[derive(Debug, Clone, Default)]
pub struct ActivationRequestOptions {
    pub include_machine_name: bool,
    pub machine_name: Option<String>,
    pub os: Option<String>,
    pub omit_os: bool,
    pub sdk: Option<String>,
    pub omit_sdk: bool,
    pub license_key: Option<String>,
    pub created_at: Option<String>
}

fn clip_request_field(value: &str, max: usize) -> &str {
    if value.len() <= max {
        value
    } else {
        &value[..max]
    }
}

fn json_escape_request(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c)
        }
    }
    out.push('"');
    out
}

fn wrap_armor_64(value: &str) -> String {
    let mut lines = Vec::new();
    let mut i = 0;
    while i < value.len() {
        let end = (i + ARMOR_LINE_WIDTH).min(value.len());
        lines.push(&value[i..end]);
        i = end;
    }
    lines.join("\n")
}

fn detect_os_label() -> String {
    let label = match std::env::consts::OS {
        "windows" => format!("Windows {}", std::env::consts::ARCH),
        "macos" => format!("macOS {}", std::env::consts::ARCH),
        "linux" => format!("Linux {}", std::env::consts::ARCH),
        other => other.to_string()
    };
    clip_request_field(&label, MAX_REQUEST_OS).to_string()
}

fn canonical_activation_request_json(
    app_id: &str,
    hwid: &str,
    created_at: &str,
    machine_name: Option<&str>,
    os: Option<&str>,
    sdk: Option<&str>,
    license_key: Option<&str>
) -> String {
    let mut parts = vec![
        format!("\"v\":{ACTIVATION_REQUEST_VERSION}"),
        format!("\"typ\":{}", json_escape_request(ACTIVATION_REQUEST_TYP)),
        format!("\"appId\":{}", json_escape_request(app_id)),
        format!("\"hwid\":{}", json_escape_request(clip_request_field(hwid, MAX_REQUEST_HWID))),
        format!("\"createdAt\":{}", json_escape_request(created_at))
    ];
    if let Some(name) = machine_name.filter(|s| !s.is_empty()) {
        parts.push(format!(
            "\"machineName\":{}",
            json_escape_request(clip_request_field(name, MAX_REQUEST_MACHINE_NAME))
        ));
    }
    if let Some(os_name) = os.filter(|s| !s.is_empty()) {
        parts.push(format!(
            "\"os\":{}",
            json_escape_request(clip_request_field(os_name, MAX_REQUEST_OS))
        ));
    }
    if let Some(sdk) = sdk.filter(|s| !s.is_empty()) {
        parts.push(format!(
            "\"sdk\":{}",
            json_escape_request(clip_request_field(sdk, MAX_REQUEST_SDK))
        ));
    }
    if let Some(key) = license_key.filter(|s| !s.is_empty()) {
        parts.push(format!(
            "\"licenseKey\":{}",
            json_escape_request(clip_request_field(key, MAX_REQUEST_LICENSE_KEY))
        ));
    }
    format!("{{{}}}", parts.join(","))
}

fn utc_iso_ms_now() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    civil_iso(dur.as_secs(), dur.subsec_millis())
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d)
}

fn civil_iso(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Armored `.authforge-request` text from explicit fields.
pub fn format_activation_request(
    app_id: &str,
    hwid: &str,
    created_at: &str,
    machine_name: Option<&str>,
    os: Option<&str>,
    sdk: Option<&str>,
    license_key: Option<&str>
) -> String {
    let json = canonical_activation_request_json(app_id, hwid, created_at, machine_name, os, sdk, license_key);
    let payload_b64 = STANDARD.encode(json.as_bytes());
    let checksum = format!("{:x}", Sha256::digest(payload_b64.as_bytes()));
    let checksum16 = &checksum[..16];
    let clean = app_id.replace(['\r', '\n'], " ");
    [
        BEGIN_ACTIVATION_REQUEST,
        &format!("Version: {ACTIVATION_REQUEST_VERSION}"),
        &format!("App-Id: {}", clean.trim()),
        &format!("Checksum: {checksum16}"),
        "",
        &wrap_armor_64(&payload_b64),
        END_ACTIVATION_REQUEST,
        ""
    ]
    .join("\n")
}

pub(crate) fn sdk_tag() -> &'static str {
    ACTIVATION_REQUEST_SDK_TAG
}

pub(crate) fn default_os_label() -> String {
    detect_os_label()
}

pub(crate) fn now_iso_ms() -> String {
    utc_iso_ms_now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_iso8601_variants() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00.250Z"), Some(250));
        assert_eq!(parse_iso8601_ms("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_iso8601_ms("2027-01-01T00:00:00.000Z"), Some(1_798_761_600_000));
        assert_eq!(parse_iso8601_ms("2026-09-11T12:00:00.000Z"), Some(1_789_128_000_000));
        assert_eq!(parse_iso8601_ms("not a date"), None);
        assert_eq!(parse_iso8601_ms("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn base64_text_check() {
        assert!(is_base64_text("QUJD"));
        assert!(is_base64_text("QUJDRA=="));
        assert!(!is_base64_text("@@@@"));
        assert!(!is_base64_text(""));
        assert!(!is_base64_text("QUJD==="));
    }
}
