//! `activate_offline` against the shared `self_serve_activation_vectors.json`.
//! In-crate so the tests can skip the rate-limit retry sleeps and read the
//! server's `replay` flag.

use super::mock_http::{read_request, write_response};
use super::*;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;

const NONCE: &str = "nonce-offline-activate-001";
const STALE: &str = "stale contents, not a license\n";

fn vectors() -> Value {
    serde_json::from_str(include_str!("../self_serve_activation_vectors.json")).expect("vectors")
}

fn no_sleep(_: Duration) {}

fn use_test_nonce() {
    TEST_NONCE.with(|nonce| *nonce.borrow_mut() = Some(NONCE.to_string()));
}

struct Request {
    method: String,
    path: String,
    body: Value,
}

/// Answers every request with the same status and body and records them.
struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl MockServer {
    fn start(status: u16, body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    return;
                };
                let raw = read_request(&mut stream);
                let text = String::from_utf8_lossy(&raw).to_string();
                let (head, body_text) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let mut request_line = head.lines().next().unwrap_or_default().split(' ');
                recorded.lock().expect("requests").push(Request {
                    method: request_line.next().unwrap_or_default().to_string(),
                    path: request_line.next().unwrap_or_default().to_string(),
                    body: serde_json::from_str(body_text).unwrap_or(Value::Null),
                });
                write_response(&mut stream, status, &body);
            }
        });
        Self { url, requests }
    }

    fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut *self.requests.lock().expect("requests"))
    }
}

/// Client configured from the vector `config`, with HWID override and no
/// retry sleeps.
fn client_for(url: &str, configure: impl FnOnce(&mut AuthForgeConfig)) -> AuthForgeClient {
    let vectors = vectors();
    let config = &vectors["config"];
    let mut cfg = AuthForgeConfig {
        app_id: config["appId"].as_str().expect("appId").into(),
        app_secret: config["appSecret"].as_str().expect("appSecret").into(),
        public_key: config["publicKey"].as_str().expect("publicKey").into(),
        api_base_url: url.into(),
        hwid_override: Some(config["hwid"].as_str().expect("hwid").into()),
        ..Default::default()
    };
    configure(&mut cfg);
    let mut client = AuthForgeClient::new(cfg);
    Arc::get_mut(&mut client.inner)
        .expect("unique client")
        .sleep = no_sleep;
    client
}

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "authforge-activate-{}-{}-{label}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn entries(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.0.join(sub))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn as_map(value: &Value) -> HashMap<String, Value> {
    serde_json::from_value(value.clone()).expect("object")
}

fn assert_request(name: &str, client: &AuthForgeClient, request: &Request) {
    let vectors = vectors();
    let config = &vectors["config"];
    let spec = &vectors["request"];
    assert_eq!(request.method, spec["method"].as_str().unwrap(), "{name}");
    assert_eq!(request.path, spec["path"].as_str().unwrap(), "{name}");

    let body = request
        .body
        .as_object()
        .unwrap_or_else(|| panic!("{name}: body is not an object"));
    let mut fields: Vec<&str> = body.keys().map(String::as_str).collect();
    fields.sort_unstable();
    let mut expected: Vec<&str> = spec["bodyFields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    expected.sort_unstable();
    assert_eq!(fields, expected, "{name}: body fields");

    assert_eq!(body["appId"], config["appId"], "{name}");
    assert_eq!(body["appSecret"], config["appSecret"], "{name}");
    assert_eq!(body["licenseKey"], config["licenseKey"], "{name}");
    assert_eq!(body["hwid"], config["hwid"], "{name}");
    assert_eq!(body["hwid"].as_str(), Some(client.hwid()), "{name}");
    // TEST_NONCE is only returned by generate_nonce(), so this proves the
    // request used the SDK's existing nonce generator.
    assert_eq!(body["nonce"].as_str(), Some(NONCE), "{name}");
}

fn assert_unauthenticated(name: &str, client: &AuthForgeClient) {
    assert!(!client.is_authenticated(), "{name}");
    assert_eq!(client.get_session_kind(), None, "{name}");
    assert!(client.get_offline_license().is_none(), "{name}");
    assert!(client.get_license_variables().is_none(), "{name}");
    assert!(client.get_app_variables().is_none(), "{name}");
}

#[test]
fn every_vector_case_matches() {
    let vectors = vectors();
    assert_eq!(vectors["format"], "authforge-self-serve-activation");
    assert_eq!(vectors["version"], 1);
    let config = &vectors["config"];
    let license_key = config["licenseKey"].as_str().unwrap();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 17);

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expect = &case["expect"];
        let server = MockServer::start(
            case["response"]["status"].as_u64().unwrap() as u16,
            case["response"]["body"].to_string(),
        );
        let client = client_for(&server.url, |_| {});
        let dir = TempDir::new(name);
        let path = dir
            .0
            .join("nested")
            .join("deeper")
            .join("license.authforge");

        use_test_nonce();
        let result = client.activate_offline_inner(license_key, Some(&path));

        // rate_limited is retried exactly as login() does it: 3 attempts.
        let requests = server.take_requests();
        let attempts = if expect["errorCode"] == "rate_limited" {
            3
        } else {
            1
        };
        assert_eq!(requests.len(), attempts, "{name}: requests");
        for request in &requests {
            assert_request(name, &client, request);
        }

        match expect["outcome"].as_str().unwrap() {
            "activated" => {
                let replay = result.unwrap_or_else(|err| panic!("{name}: {err:?}"));
                assert_eq!(Value::Bool(replay), expect["replay"], "{name}: replay");
                assert_eq!(expect["writesFile"], true, "{name}");
                let written = fs::read(&path).unwrap_or_else(|err| panic!("{name}: {err}"));
                assert_eq!(
                    written,
                    expect["fileWritten"].as_str().unwrap().as_bytes(),
                    "{name}"
                );
                assert_eq!(
                    dir.entries("nested/deeper"),
                    vec!["license.authforge"],
                    "{name}: temp file left"
                );

                assert!(client.is_authenticated(), "{name}");
                assert_eq!(expect["sessionKind"], "offline", "{name}");
                assert_eq!(
                    client.get_session_kind(),
                    Some(SessionKind::Offline),
                    "{name}"
                );
                assert_eq!(
                    client.get_license_variables(),
                    Some(as_map(&expect["licenseVariables"])),
                    "{name}"
                );
                assert_eq!(
                    client.get_app_variables(),
                    Some(as_map(&expect["appVariables"])),
                    "{name}"
                );
                let lic = client.get_offline_license().expect("offline license");
                assert_eq!(
                    lic.jti,
                    case["response"]["body"]["jti"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(lic.license_key, license_key, "{name}");
                assert!(
                    client.inner.heartbeat_handle.lock().unwrap().is_none(),
                    "{name}: heartbeat started"
                );
            }
            "error" => {
                let err = result.expect_err(name);
                let code = expect["errorCode"].as_str().unwrap();
                assert_eq!(err.code(), code, "{name}: {err:?}");
                let fatal = expect["fatal"].as_bool().unwrap();
                assert_eq!(err.is_fatal(), fatal, "{name}");
                assert_eq!(err.is_transient(), !fatal, "{name}");
                assert_eq!(is_transient_error_code(code), !fatal, "{name}");
                if let Some(detail) = expect["detail"].as_str() {
                    assert_eq!(err.to_string(), format!("{code}: {detail}"), "{name}");
                }
                assert_eq!(expect["writesFile"], false, "{name}");
                assert!(!path.exists(), "{name}: file written");
                assert!(dir.entries("").is_empty(), "{name}: directories created");
                assert_unauthenticated(name, &client);
            }
            other => panic!("{name}: unknown outcome {other}"),
        }

        // A file already at the path: replaced byte-for-byte on success,
        // untouched on error. Uses the public signature.
        let existing = dir.0.join("existing.authforge");
        fs::write(&existing, STALE).expect("seed existing file");
        let client = client_for(&server.url, |_| {});
        use_test_nonce();
        let result = client.activate_offline(license_key, Some(&existing));
        let after = fs::read(&existing).expect("existing file");
        if expect["outcome"] == "activated" {
            result.unwrap_or_else(|err| panic!("{name}: {err:?}"));
            assert_eq!(
                after,
                expect["fileWritten"].as_str().unwrap().as_bytes(),
                "{name}"
            );
        } else {
            assert_eq!(
                result.expect_err(name).code(),
                expect["errorCode"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(after, STALE.as_bytes(), "{name}: existing file modified");
            assert_unauthenticated(name, &client);
        }
        let mut leftovers = dir.entries("");
        leftovers.retain(|entry| entry != "nested");
        assert_eq!(
            leftovers,
            vec!["existing.authforge"],
            "{name}: temp file left"
        );
    }
}

#[test]
fn without_a_path_nothing_is_written_and_the_session_starts() {
    let vectors = vectors();
    let case = &vectors["cases"][0];
    assert_eq!(case["name"], "activated_new_machine");
    let server = MockServer::start(201, case["response"]["body"].to_string());
    let client = client_for(&server.url, |_| {});

    use_test_nonce();
    client
        .activate_offline(vectors["config"]["licenseKey"].as_str().unwrap(), None)
        .expect("activate");
    assert_eq!(server.take_requests().len(), 1);
    assert_eq!(client.get_session_kind(), Some(SessionKind::Offline));
    assert!(client.is_authenticated());
    // An offline session never phones home on its own.
    assert_eq!(
        client
            .self_ban(None, None, false, true, false)
            .unwrap_err()
            .code(),
        "offline_session"
    );
    assert!(server.take_requests().is_empty());
}

#[test]
fn missing_app_secret_fails_fast_without_a_request() {
    let server = MockServer::start(
        500,
        r#"{"status":"failed","error":"system_error"}"#.to_string(),
    );
    let dir = TempDir::new("no-secret");
    let path = dir.0.join("license.authforge");
    for secret in ["", "   "] {
        let client = client_for(&server.url, |cfg| cfg.app_secret = secret.into());
        let err = client
            .activate_offline("TEST-KEY0-0000-0000", Some(&path))
            .expect_err("no secret");
        assert!(matches!(err, AuthForgeError::InvalidApp), "{err:?}");
        assert!(
            server.take_requests().is_empty(),
            "request sent without a secret"
        );
        assert!(!path.exists());
        assert_unauthenticated("no secret", &client);
    }

    // Fail-fast order: the license key is checked before the app secret.
    for secret in ["test-app-secret", ""] {
        let client = client_for(&server.url, |cfg| cfg.app_secret = secret.into());
        let err = client
            .activate_offline("  ", Some(&path))
            .expect_err("no key");
        assert!(matches!(err, AuthForgeError::InvalidKey), "{err:?}");
        assert!(server.take_requests().is_empty());
    }
}

#[test]
fn errors_never_invoke_on_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let closed = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    let server = MockServer::start(410, r#"{"status":"failed","error":"revoked"}"#.to_string());
    for (url, code) in [(closed, "network_error"), (server.url.clone(), "revoked")] {
        let messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&messages);
        let client = client_for(&url, |cfg| {
            cfg.on_failure = Some(Box::new(move |message: &str| {
                recorded.lock().expect("messages").push(message.to_string());
            }));
        });
        let err = client
            .activate_offline("TEST-KEY0-0000-0000", None)
            .expect_err(code);
        assert_eq!(err.code(), code, "{err:?}");
        assert!(
            messages.lock().expect("messages").is_empty(),
            "{code}: on_failure called"
        );
        assert_unauthenticated(code, &client);
    }
}

#[test]
fn a_failed_activation_keeps_an_existing_session() {
    let vectors = vectors();
    let key = vectors["config"]["licenseKey"].as_str().unwrap();
    let ok = MockServer::start(201, vectors["cases"][0]["response"]["body"].to_string());
    let refused = MockServer::start(
        403,
        r#"{"status":"failed","error":"offline_activation_limit_reached"}"#.to_string(),
    );
    let client = client_for(&ok.url, |_| {});
    use_test_nonce();
    client.activate_offline(key, None).expect("activate");
    let jti = client.get_offline_license().expect("offline license").jti;

    // Carry the activated session over to a client whose server refuses.
    let refusing = client_for(&refused.url, |_| {});
    *refusing.inner.state.lock().unwrap() = client.inner.state.lock().unwrap().clone();
    let err = refusing.activate_offline(key, None).expect_err("refused");
    assert_eq!(err.code(), "offline_activation_limit_reached");
    assert!(refusing.is_authenticated());
    assert_eq!(refusing.get_session_kind(), Some(SessionKind::Offline));
    assert_eq!(
        refusing.get_offline_license().expect("still there").jti,
        jti
    );
}

#[test]
fn activation_sends_the_same_hwid_as_login() {
    // Generated fingerprint, no override: both requests must carry it.
    let server = MockServer::start(
        401,
        r#"{"status":"failed","error":"invalid_key"}"#.to_string(),
    );
    let client = client_for(&server.url, |cfg| cfg.hwid_override = None);
    assert!(matches!(
        client.login("TEST-KEY0-0000-0000"),
        Err(AuthForgeError::InvalidKey)
    ));
    assert!(matches!(
        client.activate_offline("TEST-KEY0-0000-0000", None),
        Err(AuthForgeError::InvalidKey)
    ));
    let requests = server.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, "/auth/validate");
    assert_eq!(requests[1].path, "/auth/offline/activate");
    assert_eq!(requests[0].body["hwid"], requests[1].body["hwid"]);
    assert_eq!(requests[1].body["hwid"].as_str(), Some(client.hwid()));
    assert!(!client.hwid().is_empty());
    let nonce = requests[1].body["nonce"].as_str().expect("nonce");
    assert!(!nonce.is_empty());
}

#[test]
fn unwritable_path_is_an_error_and_leaves_the_client_unauthenticated() {
    let vectors = vectors();
    let case = &vectors["cases"][0];
    let server = MockServer::start(201, case["response"]["body"].to_string());
    let client = client_for(&server.url, |_| {});
    let dir = TempDir::new("unwritable");
    // The parent "directory" is a regular file, so it cannot be created.
    let blocker = dir.0.join("blocker");
    fs::write(&blocker, STALE).expect("blocker");
    use_test_nonce();
    let err = client
        .activate_offline(
            "TEST-KEY0-0000-0000",
            Some(&blocker.join("license.authforge")),
        )
        .expect_err("unwritable");
    assert_eq!(err.code(), "file_write_failed", "{err:?}");
    assert!(err.is_transient());
    assert_eq!(fs::read(&blocker).expect("blocker"), STALE.as_bytes());
    assert_eq!(dir.entries(""), vec!["blocker"]);
    assert_unauthenticated("unwritable", &client);
}

#[test]
fn new_codes_are_definitive() {
    for code in [
        "offline_activation_disabled",
        "offline_activation_requires_perpetual",
        "offline_activation_requires_seats",
        "offline_activation_limit_reached",
        "offline_file_rejected",
    ] {
        assert!(DEFINITIVE_ERROR_CODES.contains(&code), "{code}");
        let err = map_server_error(code);
        assert_eq!(err.code(), code);
        assert!(err.is_fatal(), "{code}");
    }
    let rejected = AuthForgeError::Other("offline_file_rejected: hwid_mismatch".into());
    assert_eq!(rejected.code(), "offline_file_rejected");
    assert!(rejected.is_fatal());
    let missing = AuthForgeError::Other("unexpected_response: success without a file".into());
    assert_eq!(missing.code(), "unexpected_response");
    assert!(missing.is_transient());
}
