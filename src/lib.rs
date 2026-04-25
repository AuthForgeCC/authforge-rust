use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ureq::{Agent, Error as UreqError};

const DEFAULT_API_BASE_URL: &str = "https://auth.authforge.cc";
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Thread-safe hook for logging or metrics when the SDK surfaces a failure string.
pub type FailureCallback = dyn Fn(&str) + Send + Sync;

#[derive(Debug, Clone)]
pub enum HeartbeatMode {
    Local,
    Server
}

pub struct AuthForgeConfig {
    pub app_id: String,
    pub app_secret: String,
    pub public_key: String,
    pub heartbeat_mode: HeartbeatMode,
    pub heartbeat_interval: u64,
    pub api_base_url: String,
    pub on_failure: Option<Box<FailureCallback>>,
    pub request_timeout: u64,
    /// Requested session token lifetime (seconds) forwarded to `/auth/validate`.
    /// `None` means "use the server default" (24h today). Server clamps to
    /// `[3600, 604800]`; out-of-range values are silently clamped.
    pub session_ttl_seconds: Option<u64>,
    pub hwid_override: Option<String>
}

impl Default for AuthForgeConfig {
    fn default() -> Self {
        Self {
            app_id: String::new(),
            app_secret: String::new(),
            public_key: String::new(),
            heartbeat_mode: HeartbeatMode::Local,
            heartbeat_interval: 900,
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            on_failure: None,
            request_timeout: 15,
            session_ttl_seconds: None,
            hwid_override: None
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub session_token: String,
    pub expires_in: u64,
    pub app_variables: Option<HashMap<String, Value>>,
    pub license_variables: Option<HashMap<String, Value>>,
    pub request_id: String
}

#[derive(Debug, Clone)]
pub enum AuthForgeError {
    InvalidApp,
    InvalidKey,
    Expired,
    Revoked,
    HwidMismatch,
    NoCredits,
    AppBurnCapReached,
    Blocked,
    RateLimited,
    ReplayDetected,
    AppDisabled,
    SessionExpired,
    RevokeRequiresSession,
    BadRequest,
    SystemError,
    SignatureMismatch,
    NetworkError(String),
    Other(String)
}

#[derive(Clone)]
struct RuntimeConfig {
    app_id: String,
    app_secret: String,
    public_key: String,
    heartbeat_mode: HeartbeatMode,
    heartbeat_interval: u64,
    api_base_url: String,
    request_timeout: u64,
    on_failure: Option<Arc<FailureCallback>>,
    session_ttl_seconds: Option<u64>
}

#[derive(Debug, Clone)]
struct SessionState {
    authenticated: bool,
    license_key: Option<String>,
    session_token: Option<String>,
    expires_in: Option<u64>,
    session_data: Option<Value>,
    app_variables: Option<HashMap<String, Value>>,
    license_variables: Option<HashMap<String, Value>>
}

impl SessionState {
    fn clear(&mut self) {
        self.authenticated = false;
        self.license_key = None;
        self.session_token = None;
        self.expires_in = None;
        self.session_data = None;
        self.app_variables = None;
        self.license_variables = None;
    }
}

#[derive(Clone, Copy)]
enum SigningContext {
    Validate,
    Heartbeat
}

struct ClientInner {
    cfg: RuntimeConfig,
    hwid: String,
    state: Arc<Mutex<SessionState>>,
    stop_signal: Arc<AtomicBool>,
    heartbeat_handle: Mutex<Option<JoinHandle<()>>>
}

pub struct AuthForgeClient {
    inner: Arc<ClientInner>
}

#[derive(Deserialize)]
struct SignedResponse {
    status: Value,
    payload: Option<String>,
    signature: Option<String>,
    error: Option<String>
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SignedPayload {
    session_token: String,
    expires_in: u64,
    nonce: String,
    request_id: Option<String>,
    app_variables: Option<HashMap<String, Value>>,
    license_variables: Option<HashMap<String, Value>>,
    #[serde(flatten)]
    other: HashMap<String, Value>
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateRequest<'a> {
    app_id: &'a str,
    app_secret: &'a str,
    license_key: &'a str,
    hwid: &'a str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatRequest<'a> {
    app_id: &'a str,
    session_token: &'a str,
    nonce: &'a str,
    hwid: &'a str
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfBanPreSessionRequest<'a> {
    app_id: &'a str,
    app_secret: &'a str,
    license_key: &'a str,
    hwid: &'a str,
    nonce: &'a str,
    revoke_license: bool,
    blacklist_hwid: bool,
    blacklist_ip: bool
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfBanPostSessionRequest<'a> {
    app_id: &'a str,
    session_token: &'a str,
    hwid: &'a str,
    revoke_license: bool,
    blacklist_hwid: bool,
    blacklist_ip: bool
}

impl AuthForgeClient {
    pub fn new(config: AuthForgeConfig) -> Self {
        let on_failure = config.on_failure.map(Arc::<FailureCallback>::from);
        let runtime_cfg = RuntimeConfig {
            app_id: config.app_id,
            app_secret: config.app_secret,
            public_key: config.public_key,
            heartbeat_mode: config.heartbeat_mode,
            heartbeat_interval: if config.heartbeat_interval == 0 {
                900
            } else {
                config.heartbeat_interval
            },
            api_base_url: if config.api_base_url.trim().is_empty() {
                DEFAULT_API_BASE_URL.to_string()
            } else {
                config.api_base_url.trim_end_matches('/').to_string()
            },
            request_timeout: if config.request_timeout == 0 {
                15
            } else {
                config.request_timeout
            },
            on_failure,
            session_ttl_seconds: config.session_ttl_seconds
        };

        let inner = ClientInner {
            cfg: runtime_cfg,
            hwid: resolve_hwid(config.hwid_override),
            state: Arc::new(Mutex::new(SessionState {
                authenticated: false,
                license_key: None,
                session_token: None,
                expires_in: None,
                session_data: None,
                app_variables: None,
                license_variables: None
            })),
            stop_signal: Arc::new(AtomicBool::new(false)),
            heartbeat_handle: Mutex::new(None)
        };

        Self {
            inner: Arc::new(inner)
        }
    }

    pub fn login(&self, license_key: &str) -> Result<LoginResult, AuthForgeError> {
        if self.inner.cfg.app_id.trim().is_empty()
            || self.inner.cfg.app_secret.trim().is_empty()
            || self.inner.cfg.public_key.trim().is_empty()
        {
            return Err(AuthForgeError::InvalidApp);
        }
        if license_key.trim().is_empty() {
            return Err(AuthForgeError::InvalidKey);
        }

        let result = self.validate_once(license_key)?;
        self.start_heartbeat_thread();
        Ok(result)
    }

    /// Same `/auth/validate` request and signature verification as [`Self::login`], without
    /// updating session state or starting the heartbeat thread.
    ///
    /// On transport failure after retries, returns [`AuthForgeError::NetworkError`] without
    /// invoking `on_failure` (unlike [`Self::login`], which uses the network-failure hook).
    pub fn validate_license(&self, license_key: &str) -> Result<LoginResult, AuthForgeError> {
        if self.inner.cfg.app_id.trim().is_empty()
            || self.inner.cfg.app_secret.trim().is_empty()
            || self.inner.cfg.public_key.trim().is_empty()
        {
            return Err(AuthForgeError::InvalidApp);
        }
        if license_key.trim().is_empty() {
            return Err(AuthForgeError::InvalidKey);
        }

        let (result, _) = self.validate_payload_only(license_key, false)?;
        Ok(result)
    }

    pub fn self_ban(
        &self,
        license_key: Option<&str>,
        session_token: Option<&str>,
        revoke_license: bool,
        blacklist_hwid: bool,
        blacklist_ip: bool
    ) -> Result<(), AuthForgeError> {
        let (current_session, current_license) = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            (state.session_token.clone(), state.license_key.clone())
        };

        let resolved_session = session_token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or(current_session);
        if let Some(session) = resolved_session {
            let request = SelfBanPostSessionRequest {
                app_id: &self.inner.cfg.app_id,
                session_token: &session,
                hwid: &self.inner.hwid,
                revoke_license,
                blacklist_hwid,
                blacklist_ip
            };
            let (response, _) = self.post_json("/auth/selfban", &request, true)?;
            if !is_success_status(&response.status) {
                let code = response.error.unwrap_or_else(|| "unknown_error".to_string());
                return Err(map_server_error(&code));
            }
            return Ok(());
        }

        let resolved_license = license_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or(current_license)
            .ok_or_else(|| AuthForgeError::Other("missing_license_key".to_string()))?;
        let nonce = generate_nonce();
        let request = SelfBanPreSessionRequest {
            app_id: &self.inner.cfg.app_id,
            app_secret: &self.inner.cfg.app_secret,
            license_key: &resolved_license,
            hwid: &self.inner.hwid,
            nonce: &nonce,
            // Pre-session self-ban cannot revoke licenses.
            revoke_license: false,
            blacklist_hwid,
            blacklist_ip
        };
        let (response, _) = self.post_json("/auth/selfban", &request, true)?;
        if !is_success_status(&response.status) {
            let code = response.error.unwrap_or_else(|| "unknown_error".to_string());
            return Err(map_server_error(&code));
        }
        Ok(())
    }

    pub fn logout(&self) {
        self.stop_heartbeat_thread();
        let mut state = self
            .inner
            .state
            .lock()
            .expect("authforge state mutex poisoned in logout");
        state.clear();
    }

    pub fn is_authenticated(&self) -> bool {
        self.inner
            .state
            .lock()
            .map(|state| state.authenticated)
            .unwrap_or(false)
    }

    pub fn get_session_data(&self) -> Option<Value> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.session_data.clone())
    }

    pub fn get_app_variables(&self) -> Option<HashMap<String, Value>> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.app_variables.clone())
    }

    pub fn get_license_variables(&self) -> Option<HashMap<String, Value>> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.license_variables.clone())
    }

    fn validate_payload_only(
        &self,
        license_key: &str,
        invoke_on_network_failure: bool
    ) -> Result<(LoginResult, SignedPayload), AuthForgeError> {
        let nonce = generate_nonce();
        let request = ValidateRequest {
            app_id: &self.inner.cfg.app_id,
            app_secret: &self.inner.cfg.app_secret,
            license_key,
            hwid: &self.inner.hwid,
            nonce: &nonce,
            ttl_seconds: self.inner.cfg.session_ttl_seconds
        };

        let (response, used_nonce) =
            self.post_json("/auth/validate", &request, invoke_on_network_failure)?;
        let payload = self.verify_signed_response(
            response,
            used_nonce.as_deref().unwrap_or(&nonce),
            SigningContext::Validate
        )?;
        let request_id = payload.request_id.clone().unwrap_or_default();

        let result = LoginResult {
            session_token: payload.session_token.clone(),
            expires_in: payload.expires_in,
            app_variables: payload.app_variables.clone(),
            license_variables: payload.license_variables.clone(),
            request_id
        };
        Ok((result, payload))
    }

    fn validate_once(&self, license_key: &str) -> Result<LoginResult, AuthForgeError> {
        let (result, payload) = self.validate_payload_only(license_key, true)?;

        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
        state.authenticated = true;
        state.license_key = Some(license_key.to_string());
        state.session_token = Some(payload.session_token.clone());
        state.expires_in = Some(payload.expires_in);
        state.app_variables = payload.app_variables.clone();
        state.license_variables = payload.license_variables.clone();
        state.session_data = Some(serde_json::to_value(&payload).unwrap_or(Value::Null));

        Ok(result)
    }

    fn server_heartbeat_with_retry(&self) -> Result<(), AuthForgeError> {
        let session_token = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            state
                .session_token
                .clone()
                .ok_or_else(|| AuthForgeError::Other("missing_session_token".to_string()))?
        };

        let nonce = generate_nonce();
        let request = HeartbeatRequest {
            app_id: &self.inner.cfg.app_id,
            session_token: &session_token,
            nonce: &nonce,
            hwid: &self.inner.hwid
        };

        let (response, used_nonce) = self.post_json("/auth/heartbeat", &request, true)?;
        let payload = self.verify_signed_response(
            response,
            used_nonce.as_deref().unwrap_or(&nonce),
            SigningContext::Heartbeat
        )?;
        let session_data = serde_json::to_value(&payload).unwrap_or(Value::Null);
        let session_token = payload.session_token;
        let expires_in = payload.expires_in;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
        state.authenticated = true;
        state.session_token = Some(session_token);
        state.expires_in = Some(expires_in);
        state.session_data = Some(session_data);
        Ok(())
    }

    fn local_heartbeat_check(&self) -> Result<(), AuthForgeError> {
        let (authenticated, expires_in) = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            (state.authenticated, state.expires_in)
        };

        if !authenticated {
            return Err(AuthForgeError::Expired);
        }

        let expires = expires_in.ok_or(AuthForgeError::Expired)?;
        let now = epoch_now();
        if now >= expires {
            return Err(AuthForgeError::Expired);
        }

        Ok(())
    }

    fn post_json<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        invoke_on_network_failure: bool
    ) -> Result<(SignedResponse, Option<String>), AuthForgeError> {
        let agent = build_agent(self.inner.cfg.request_timeout);
        let url = format!("{}{}", self.inner.cfg.api_base_url, path);
        let base_value = serde_json::to_value(body)
            .map_err(|err| AuthForgeError::Other(format!("serialize_request_failed: {err}")))?;

        let mut rate_attempt = 0;
        let mut network_retried = false;
        loop {
            let mut request_value = base_value.clone();
            let used_nonce = if rate_attempt > 0 {
                refresh_nonce(&mut request_value)
            } else {
                extract_nonce(&request_value)
            };

            let response = agent.post(&url).send_json(request_value);
            match response {
                Ok(resp) => {
                    let status_code = resp.status();
                    let parsed = parse_signed_response(resp.into_string().unwrap_or_default())?;
                    let is_rate_limited = status_code == 429
                        || response_error_code(&parsed).as_deref() == Some("rate_limited");
                    if is_rate_limited && rate_attempt < 2 {
                        thread::sleep(Duration::from_secs(if rate_attempt == 0 { 2 } else { 5 }));
                        rate_attempt += 1;
                        continue;
                    }
                    return Ok((parsed, used_nonce));
                }
                Err(UreqError::Status(status_code, response)) => {
                    let body_text = response.into_string().unwrap_or_default();
                    let parsed = parse_signed_response(body_text)?;
                    let is_rate_limited = status_code == 429
                        || response_error_code(&parsed).as_deref() == Some("rate_limited");
                    if is_rate_limited && rate_attempt < 2 {
                        thread::sleep(Duration::from_secs(if rate_attempt == 0 { 2 } else { 5 }));
                        rate_attempt += 1;
                        continue;
                    }
                    return Ok((parsed, used_nonce));
                }
                Err(UreqError::Transport(err)) => {
                    if !network_retried {
                        network_retried = true;
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                    if invoke_on_network_failure {
                        if let Some(callback) = &self.inner.cfg.on_failure {
                            callback("network_error");
                        }
                    }
                    return Err(AuthForgeError::NetworkError(err.to_string()));
                }
            }
        }
    }

    fn verify_signed_response(
        &self,
        response: SignedResponse,
        expected_nonce: &str,
        context: SigningContext
    ) -> Result<SignedPayload, AuthForgeError> {
        if !is_success_status(&response.status) {
            let server_error = response.error.unwrap_or_else(|| "unknown_error".to_string());
            return Err(map_server_error(&server_error));
        }

        let payload_b64 = response
            .payload
            .ok_or_else(|| AuthForgeError::Other("missing_payload".to_string()))?;
        let signature = response
            .signature
            .ok_or_else(|| AuthForgeError::Other("missing_signature".to_string()))?;

        _ = context;
        if !verify_payload_signature_ed25519(
            &payload_b64,
            &signature,
            &self.inner.cfg.public_key,
        )? {
            return Err(AuthForgeError::SignatureMismatch);
        }

        let payload_bytes = decode_base64_any(&payload_b64)?;
        let payload: SignedPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|err| AuthForgeError::Other(format!("invalid_payload_json: {err}")))?;

        if payload.nonce != expected_nonce {
            return Err(AuthForgeError::ReplayDetected);
        }

        Ok(payload)
    }

    fn start_heartbeat_thread(&self) {
        self.stop_heartbeat_thread();
        self.inner.stop_signal.store(false, Ordering::SeqCst);

        let client = self.clone();
        let interval = self.inner.cfg.heartbeat_interval;
        let handle = thread::spawn(move || {
            while !client.inner.stop_signal.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(interval));
                if client.inner.stop_signal.load(Ordering::SeqCst) {
                    break;
                }

                let heartbeat_result = match client.inner.cfg.heartbeat_mode {
                    HeartbeatMode::Server => client.server_heartbeat_with_retry(),
                    HeartbeatMode::Local => client.local_heartbeat_check()
                };

                if let Err(err) = heartbeat_result {
                    {
                        let mut state = client
                            .inner
                            .state
                            .lock()
                            .expect("authforge state mutex poisoned in heartbeat");
                        state.authenticated = false;
                    }
                    if let Some(callback) = &client.inner.cfg.on_failure {
                        let message = format!("{err:?}");
                        callback(&message);
                    }
                    break;
                }
            }
        });

        let mut lock = self
            .inner
            .heartbeat_handle
            .lock()
            .expect("authforge heartbeat mutex poisoned in start_heartbeat_thread");
        *lock = Some(handle);
    }

    fn stop_heartbeat_thread(&self) {
        self.inner.stop_signal.store(true, Ordering::SeqCst);
        if let Ok(mut handle_lock) = self.inner.heartbeat_handle.lock() {
            if let Some(handle) = handle_lock.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Clone for AuthForgeClient {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner)
        }
    }
}

impl Drop for AuthForgeClient {
    fn drop(&mut self) {
        self.stop_heartbeat_thread();
    }
}

#[cfg(test)]
mod validate_license_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn validate_license_success_and_error_leave_session_inactive() {
        let raw = include_str!("../test_vectors.json");
        let vectors: Value = serde_json::from_str(raw).expect("vectors");
        let cases = vectors["cases"].as_array().expect("cases");
        let success = cases
            .iter()
            .find(|c| c["id"] == "validate_success")
            .expect("validate_success");
        let public_key = vectors["publicKey"].as_str().unwrap();

        let run_server = |body: String| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = mpsc::channel::<()>();
            thread::spawn(move || {
                let _ = tx.send(());
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            rx.recv_timeout(std::time::Duration::from_secs(2))
                .expect("server thread started");
            addr
        };

        let ok_body = serde_json::json!({
            "status": "ok",
            "payload": success["payload"],
            "signature": success["signature"],
            "keyId": "signing-key-1",
        })
        .to_string();
        let addr_ok = run_server(ok_body);
        std::env::set_var("AUTHFORGE_SDK_TEST_NONCE", "nonce-validate-001");
        let client_ok = AuthForgeClient::new(AuthForgeConfig {
            app_id: "app".into(),
            app_secret: "secret".into(),
            public_key: public_key.into(),
            heartbeat_mode: HeartbeatMode::Local,
            api_base_url: format!("http://{}", addr_ok),
            ..Default::default()
        });
        let result = client_ok.validate_license("key").expect("validate");
        assert_eq!(result.session_token, "session.validate.token");
        assert!(!client_ok.is_authenticated());
        std::env::remove_var("AUTHFORGE_SDK_TEST_NONCE");

        let err_body = r#"{"status":"invalid_key","error":"invalid_key"}"#.to_string();
        let addr_err = run_server(err_body);
        let client_err = AuthForgeClient::new(AuthForgeConfig {
            app_id: "app".into(),
            app_secret: "secret".into(),
            public_key: "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=".into(),
            heartbeat_mode: HeartbeatMode::Local,
            api_base_url: format!("http://{}", addr_err),
            ..Default::default()
        });
        let err = client_err.validate_license("bad").unwrap_err();
        assert!(matches!(err, AuthForgeError::InvalidKey), "{err:?}");
        assert!(!client_err.is_authenticated());
    }
}

pub fn verify_payload_signature_ed25519(
    payload_base64: &str,
    signature_base64: &str,
    public_key_base64: &str,
) -> Result<bool, AuthForgeError> {
    let public_key_bytes = decode_base64_any(public_key_base64)
        .map_err(|err| AuthForgeError::Other(format!("public_key_base64_decode_failed: {err:?}")))?;
    if public_key_bytes.len() != 32 {
        return Err(AuthForgeError::Other("invalid_public_key_length".to_string()));
    }
    let key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthForgeError::Other("invalid_public_key_bytes".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|err| AuthForgeError::Other(format!("invalid_public_key: {err}")))?;

    let signature_bytes = decode_base64_any(signature_base64)
        .map_err(|err| AuthForgeError::Other(format!("signature_base64_decode_failed: {err:?}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| AuthForgeError::Other(format!("invalid_signature_bytes: {err}")))?;

    Ok(verifying_key
        .verify(payload_base64.as_bytes(), &signature)
        .is_ok())
}

fn parse_signed_response(body: String) -> Result<SignedResponse, AuthForgeError> {
    serde_json::from_str::<SignedResponse>(&body)
        .map_err(|err| AuthForgeError::NetworkError(format!("invalid_json_response: {err}")))
}

fn map_server_error(error: &str) -> AuthForgeError {
    match error {
        "invalid_app" => AuthForgeError::InvalidApp,
        "app_disabled" => AuthForgeError::AppDisabled,
        "invalid_key" => AuthForgeError::InvalidKey,
        "expired" => AuthForgeError::Expired,
        "session_expired" => AuthForgeError::SessionExpired,
        "revoked" => AuthForgeError::Revoked,
        "hwid_mismatch" => AuthForgeError::HwidMismatch,
        "no_credits" => AuthForgeError::NoCredits,
        "app_burn_cap_reached" => AuthForgeError::AppBurnCapReached,
        "blocked" => AuthForgeError::Blocked,
        "rate_limited" => AuthForgeError::RateLimited,
        "replay_detected" => AuthForgeError::ReplayDetected,
        "revoke_requires_session" => AuthForgeError::RevokeRequiresSession,
        "bad_request" => AuthForgeError::BadRequest,
        "system_error" => AuthForgeError::SystemError,
        _ => AuthForgeError::Other(error.to_string())
    }
}

fn is_success_status(status: &Value) -> bool {
    match status {
        Value::Bool(value) => *value,
        Value::String(value) => {
            let text = value.trim().to_ascii_lowercase();
            text == "ok" || text == "success" || text == "valid" || text == "true" || text == "1"
        }
        Value::Number(value) => value.as_i64() == Some(1),
        _ => false
    }
}

fn decode_base64_any(value: &str) -> Result<Vec<u8>, AuthForgeError> {
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|err| AuthForgeError::Other(format!("payload_base64_decode_failed: {err}")))
}

fn generate_hwid() -> String {
    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    let os = std::env::consts::OS.to_string();
    let mac = mac_address::get_mac_address()
        .ok()
        .and_then(|value| value)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown-mac".to_string());

    let material = format!("{host}|{os}|{mac}");
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    hex_lower(&hasher.finalize())
}

fn resolve_hwid(hwid_override: Option<String>) -> String {
    if let Some(value) = hwid_override {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    generate_hwid()
}

fn build_agent(timeout_secs: u64) -> Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
}

fn generate_nonce() -> String {
    #[cfg(test)]
    if let Ok(v) = std::env::var("AUTHFORGE_SDK_TEST_NONCE") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = epoch_now();
    let seed = format!(
        "{}:{}:{}:{}",
        now,
        counter,
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    );
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hex_lower(&hasher.finalize())[..32].to_string()
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn extract_nonce(value: &Value) -> Option<String> {
    value
        .get("nonce")
        .and_then(Value::as_str)
        .map(|nonce| nonce.to_string())
}

fn refresh_nonce(value: &mut Value) -> Option<String> {
    let next_nonce = generate_nonce();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("nonce".to_string(), Value::String(next_nonce.clone()));
        return Some(next_nonce);
    }
    None
}

fn response_error_code(response: &SignedResponse) -> Option<String> {
    if let Some(error) = &response.error {
        let lower = error.trim().to_ascii_lowercase();
        if !lower.is_empty() {
            return Some(lower);
        }
    }

    if let Value::String(status) = &response.status {
        let lower = status.trim().to_ascii_lowercase();
        if !lower.is_empty() {
            return Some(lower);
        }
    }

    None
}
