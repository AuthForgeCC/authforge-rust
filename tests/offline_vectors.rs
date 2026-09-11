use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use authforge::{
    parse_iso8601_ms, parse_license_file, verify_license_file, AuthForgeClient, AuthForgeConfig,
    AuthForgeError, OfflineHwidPolicy, OfflineLicenseError, SessionKind, VerifyLicenseFileOptions
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct OfflineVectors {
    version: u64,
    keys: OfflineKeys,
    cases: Vec<OfflineCase>
}

#[derive(Deserialize)]
struct OfflineKeys {
    #[serde(rename = "wrongPublicKey")]
    wrong_public_key: String
}

#[derive(Deserialize, Clone)]
struct OfflineCase {
    name: String,
    #[serde(rename = "appId")]
    app_id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    hwid: String,
    now: String,
    file: String,
    expect: String,
    #[serde(rename = "payloadBase64")]
    payload_base64: Option<String>,
    #[serde(rename = "signatureBase64")]
    signature_base64: Option<String>,
    payload: Option<Value>
}

fn load_vectors() -> OfflineVectors {
    let vectors: OfflineVectors =
        serde_json::from_str(include_str!("../offline_license_vectors.json")).expect("valid offline vector json");
    assert_eq!(vectors.version, 1);
    assert!(vectors.cases.len() >= 15);
    vectors
}

fn case(vectors: &OfflineVectors, name: &str) -> OfflineCase {
    vectors
        .cases
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("case {name} missing"))
        .clone()
}

fn opts_for(c: &OfflineCase) -> VerifyLicenseFileOptions {
    VerifyLicenseFileOptions {
        app_id: c.app_id.clone(),
        public_keys: vec![c.public_key.clone()],
        hwid: Some(c.hwid.clone()),
        now_epoch_ms: Some(parse_iso8601_ms(&c.now).expect("vector now parses"))
    }
}

#[test]
fn every_vector_case_matches_expected_result() {
    let vectors = load_vectors();
    for c in &vectors.cases {
        let result = verify_license_file(&c.file, &opts_for(c));
        let got = match &result {
            Ok(_) => "ok".to_string(),
            Err(err) => err.code().to_string()
        };
        assert_eq!(got, c.expect, "case {}", c.name);
        if let (Ok(lic), Some(payload)) = (&result, &c.payload) {
            assert_eq!(&lic.payload, payload, "case {}", c.name);
            assert_eq!(Some(&lic.payload_base64), c.payload_base64.as_ref());
            assert_eq!(Some(&lic.signature_base64), c.signature_base64.as_ref());
        }
    }
}

#[test]
fn parse_recovers_canonical_signed_string() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_bound");
    let parsed = parse_license_file(&good.file).expect("parses");
    assert_eq!(Some(&parsed.payload_base64), good.payload_base64.as_ref());
    assert_eq!(Some(&parsed.signature_base64), good.signature_base64.as_ref());
    assert_eq!(parsed.headers.get("Version").map(String::as_str), Some("1"));
    assert_eq!(parsed.headers.get("App-Id"), Some(&good.app_id));
    assert_eq!(parse_license_file("nope"), Err(OfflineLicenseError::BadArmor));
}

#[test]
fn good_file_exposes_entitlements() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_bound");
    let lic = verify_license_file(&good.file, &opts_for(&good)).expect("verifies");
    assert_eq!(lic.license_key, "TEST-KEY0-0000-0000");
    assert_eq!(lic.key_id, "kid-test-0001");
    assert_eq!(
        lic.hwid_policy,
        OfflineHwidPolicy::Bound(vec!["testhwid".to_string(), "second-machine".to_string()])
    );
    assert_eq!(lic.label.as_deref(), Some("Vector license"));
    assert_eq!(lic.expires_at.as_deref(), Some("2027-01-01T00:00:00.000Z"));
    assert_eq!(lic.license_expires_at, Some(None));
    let vars = lic.license_variables.expect("license variables");
    assert_eq!(vars.get("tier"), Some(&Value::String("pro".to_string())));
    assert_eq!(vars.get("seats"), Some(&Value::from(3)));
    let app_vars = lic.app_variables.expect("app variables");
    assert_eq!(app_vars.get("theme"), Some(&Value::String("dark".to_string())));
}

fn make_client(good: &OfflineCase, mutate: impl FnOnce(&mut AuthForgeConfig)) -> (AuthForgeClient, Arc<Mutex<Vec<String>>>) {
    let failures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failures);
    let mut cfg = AuthForgeConfig {
        app_id: good.app_id.clone(),
        app_secret: String::new(),
        public_key: good.public_key.clone(),
        hwid_override: Some(good.hwid.clone()),
        // Any network call would hit a closed port and fail loudly.
        api_base_url: "http://127.0.0.1:9".to_string(),
        on_failure: Some(Box::new(move |msg: &str| {
            sink.lock().unwrap().push(msg.to_string());
        })),
        ..Default::default()
    };
    mutate(&mut cfg);
    (AuthForgeClient::new(cfg), failures)
}

#[test]
fn login_from_file_is_offline_and_starts_no_heartbeat() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_lifetime");
    let (client, failures) = make_client(&good, |_| {});

    assert_eq!(client.hwid(), good.hwid);
    assert_eq!(client.get_session_kind(), None);
    let lic = client.login_from_file(&good.file).expect("login from file");
    assert!(client.is_authenticated());
    assert_eq!(client.get_session_kind(), Some(SessionKind::Offline));
    assert_eq!(lic.jti, "00000000-0000-4000-8000-000000000003");
    let offline = client.get_offline_license().expect("offline license present");
    assert_eq!(offline.jti, lic.jti);
    assert_eq!(offline.expires_at, None);
    let vars = client.get_license_variables().expect("license variables");
    assert_eq!(vars.get("tier"), Some(&Value::String("pro".to_string())));
    let app_vars = client.get_app_variables().expect("app variables");
    assert_eq!(app_vars.get("theme"), Some(&Value::String("dark".to_string())));
    let session = client.get_session_data().expect("session data");
    assert_eq!(session.get("licenseKey"), Some(&Value::String("TEST-KEY0-0000-0000".to_string())));
    assert!(failures.lock().unwrap().is_empty());

    client.logout();
    assert!(!client.is_authenticated());
    assert_eq!(client.get_session_kind(), None);
    assert!(client.get_offline_license().is_none());

    let err = client.login("XXXX-XXXX-XXXX-XXXX").unwrap_err();
    assert!(matches!(err, AuthForgeError::InvalidApp));
}

/// Minimal one-shot HTTP server that records the request body it receives
/// and answers `{"status":"ok"}`. Returns the address and a receiver for the
/// captured body.
fn capture_server() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let (body_tx, body_rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        // Headers and body may arrive in separate writes: keep reading until
        // the announced Content-Length has been received.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n
            };
            raw.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&raw);
            if let Some(split) = text.find("\r\n\r\n") {
                let headers = &text[..split];
                let body_len = text.len() - split - 4;
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if body_len >= content_length {
                    break;
                }
            }
        }
        let raw = String::from_utf8_lossy(&raw).to_string();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        let _ = body_tx.send(body);
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        let _ = stream.write_all(response.as_bytes());
    });
    (format!("http://{addr}"), body_rx)
}

#[test]
fn offline_self_ban_is_local_error_and_never_posts() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_lifetime");
    let (base_url, body_rx) = capture_server();
    let (client, _) = make_client(&good, |cfg| {
        cfg.api_base_url = base_url;
        // Explicit-license self_ban is an online API; this test covers that
        // dual-mode path. Offline-only clients omit the secret entirely.
        cfg.app_secret = "online-selfban".to_string();
    });
    client.login_from_file(&good.file).expect("login from file");

    for revoke in [true, false] {
        match client.self_ban(None, None, revoke, false, false) {
            Err(AuthForgeError::Other(code)) => assert_eq!(code, "offline_session"),
            other => panic!("expected Other(offline_session), got {other:?}")
        }
    }
    // Nothing reached the server; the capture channel stays empty.
    assert!(body_rx.recv_timeout(Duration::from_millis(200)).is_err());
    // Still authenticated offline afterwards; nothing was torn down.
    assert!(client.is_authenticated());

    // An explicit license key is a request about a different credential and
    // legitimately takes the pre-session path with a fresh nonce.
    client
        .self_ban(Some("OTHER-KEY0-0000-0000"), None, true, true, true)
        .expect("explicit-license self-ban");
    let body: Value = serde_json::from_str(&body_rx.recv_timeout(Duration::from_secs(2)).expect("one request"))
        .expect("json body");
    assert_eq!(body["licenseKey"], Value::String("OTHER-KEY0-0000-0000".to_string()));
    assert_eq!(body["revokeLicense"], Value::Bool(false));
    assert!(body.get("sessionToken").is_none(), "pre-session self-ban must not carry a session token");
    assert!(body["nonce"].as_str().map(|n| !n.is_empty()).unwrap_or(false));
}

#[test]
fn offline_session_never_starts_heartbeat_even_with_online_checkins_enabled() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_lifetime");
    let (client, failures) = make_client(&good, |cfg| {
        cfg.online_heartbeat = true;
        cfg.heartbeat_interval = 10;
    });
    client.login_from_file(&good.file).expect("login from file");
    // A heartbeat thread would hit the closed port and report a failure; an
    // offline session must stay authenticated with none.
    thread::sleep(Duration::from_millis(100));
    assert!(client.is_authenticated());
    assert_eq!(client.get_session_kind(), Some(SessionKind::Offline));
    assert!(failures.lock().unwrap().is_empty());
}

#[test]
fn login_from_file_rejects_with_typed_errors() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_lifetime");
    let wrong_key = vectors.keys.wrong_public_key.clone();

    type RejectCase<'a> = (&'a str, Box<dyn FnOnce(&mut AuthForgeConfig)>, String, OfflineLicenseError);
    let cases: Vec<RejectCase> = vec![
        ("tampered", Box::new(|_| {}), case(&vectors, "bad_signature_tampered_body").file, OfflineLicenseError::BadSignature),
        ("wrong key", Box::new(move |c| c.public_key = wrong_key), good.file.clone(), OfflineLicenseError::BadSignature),
        ("expired", Box::new(|_| {}), case(&vectors, "expired").file, OfflineLicenseError::Expired),
        ("hwid mismatch", Box::new(|c| c.hwid_override = Some("otherhwid".to_string())), good.file.clone(), OfflineLicenseError::HwidMismatch),
        ("wrong app", Box::new(|c| c.app_id = "other-app".to_string()), good.file.clone(), OfflineLicenseError::WrongApp),
        ("unsupported version", Box::new(|_| {}), case(&vectors, "unsupported_version").file, OfflineLicenseError::UnsupportedVersion),
        ("bad armor", Box::new(|_| {}), format!("{}\n-----BEGIN AUTHFORGE LICENSE-----", case(&vectors, "bad_armor_garbage").file), OfflineLicenseError::BadArmor)
    ];

    for (name, mutate, file, want) in cases {
        let (client, failures) = make_client(&good, mutate);
        let result = client.login_from_file(&file);
        assert_eq!(result.map(|_| ()), Err(want.clone()), "case {name}");
        assert!(!client.is_authenticated(), "case {name}");
        let recorded = failures.lock().unwrap().clone();
        assert_eq!(recorded, vec![format!("offline_login_failed: {}", want.code())], "case {name}");
    }
}

#[test]
fn login_from_file_reads_from_disk_and_verify_is_side_effect_free() {
    let vectors = load_vectors();
    let good = case(&vectors, "good_lifetime");
    let (client, _) = make_client(&good, |_| {});

    let dir = std::env::temp_dir().join(format!("authforge-offline-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("license.authforge");
    std::fs::write(&path, &good.file).unwrap();
    let path_str = path.to_string_lossy().to_string();

    assert!(client.verify_license_file(&path_str).is_ok());
    assert!(!client.is_authenticated());
    assert!(client.login_from_file(&path_str).is_ok());
    assert!(client.is_authenticated());

    let missing = dir.join("missing.authforge").to_string_lossy().to_string();
    assert!(matches!(client.login_from_file(&missing), Err(OfflineLicenseError::ReadError(_))));

    let _ = std::fs::remove_dir_all(&dir);
}
