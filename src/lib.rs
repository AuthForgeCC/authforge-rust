use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ureq::{Agent, Error as UreqError};

mod offline;

pub use offline::{
    format_activation_request, parse_iso8601_ms, parse_license_file, verify_license_file,
    ActivationRequestOptions, OfflineHwidPolicy, OfflineLicense, OfflineLicenseError,
    ParsedLicenseFile, VerifyLicenseFileOptions, OFFLINE_LICENSE_FILE_VERSION
};

const DEFAULT_API_BASE_URL: &str = "https://auth.authforge.cc";
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Thread-safe hook for logging or metrics when the SDK surfaces a failure string.
pub type FailureCallback = dyn Fn(&str) + Send + Sync;

/// Receives background check failures as the typed error; see
/// [`AuthForgeConfig::on_heartbeat_failure`].
pub type HeartbeatFailureCallback = dyn Fn(&AuthForgeError) + Send + Sync;

#[derive(Debug, Clone)]
#[deprecated(note = "use online_heartbeat: true for online check-ins; the default is the grace period behavior")]
pub enum HeartbeatMode {
    Local,
    Server
}

pub struct AuthForgeConfig {
    pub app_id: String,
    /// Application secret. Required for online APIs (`login`, `validate_license`,
    /// `self_ban`). Leave empty for offline-only clients (`login_from_file`);
    /// air-gapped builds should not ship the secret.
    pub app_secret: String,
    /// Trusted Ed25519 public key in base64. Use `public_keys` instead for
    /// rotation set support; `public_key` remains for the single-key
    /// historical contract and is merged into the trust list at construction.
    pub public_key: String,
    /// Optional rotation set. When non-empty its entries are merged ahead of
    /// `public_key` so the SDK trusts both the previous and the current
    /// server-side key during a cutover. A signature that matches *any*
    /// entry verifies successfully.
    pub public_keys: Vec<String>,
    /// Deprecated policy selector kept for compatibility. Prefer
    /// [`Self::online_heartbeat`]. `HeartbeatMode::Server` still maps to
    /// online check-ins at construction; `HeartbeatMode::Local` matches the
    /// default grace period behavior.
    #[deprecated(note = "use online_heartbeat: true for online check-ins; the default is the grace period behavior")]
    #[allow(deprecated)]
    pub heartbeat_mode: HeartbeatMode,
    /// Opt into online check-ins: periodic `POST /auth/heartbeat` calls for
    /// fast revocation and concurrent-use detection. When `false` (the
    /// default), the client runs through the grace period instead: it keeps
    /// running on the signed session without contacting AuthForge and fails
    /// once the session TTL expires.
    pub online_heartbeat: bool,
    pub heartbeat_interval: u64,
    pub api_base_url: String,
    pub on_failure: Option<Box<FailureCallback>>,
    /// When set, receives background check failures instead of `on_failure`,
    /// as the [`AuthForgeError`] itself: use [`AuthForgeError::code`] and
    /// [`AuthForgeError::is_transient`]. Fatal failures have already cleared
    /// the session when it runs; transient ones keep checking in. It runs on
    /// the heartbeat thread with no SDK lock held, so it may call
    /// [`AuthForgeClient::logout`], [`AuthForgeClient::is_authenticated`] or
    /// drop the client.
    pub on_heartbeat_failure: Option<Box<HeartbeatFailureCallback>>,
    pub request_timeout: u64,
    /// HTTP timeout in seconds for `/auth/heartbeat` only. Use a value smaller
    /// than [`Self::request_timeout`] so a stuck heartbeat does not block
    /// [`AuthForgeClient::logout`] for as long as activation/validate. `None`
    /// or `0` resolves to **8** seconds at runtime.
    pub heartbeat_request_timeout: Option<u64>,
    /// Requested grace period duration (seconds), forwarded to `/auth/validate`
    /// as the session token lifetime. This controls how long the app keeps
    /// running on the signed session without contacting AuthForge. `None`
    /// means "use the server default" (24h today). Server clamps to
    /// `[3600, 604800]` (1h to 7d); out-of-range values are silently clamped.
    pub session_ttl_seconds: Option<u64>,
    pub hwid_override: Option<String>
}

impl Default for AuthForgeConfig {
    #[allow(deprecated)]
    fn default() -> Self {
        Self {
            app_id: String::new(),
            app_secret: String::new(),
            public_key: String::new(),
            public_keys: Vec::new(),
            heartbeat_mode: HeartbeatMode::Local,
            online_heartbeat: false,
            heartbeat_interval: 900,
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            on_failure: None,
            on_heartbeat_failure: None,
            request_timeout: 15,
            heartbeat_request_timeout: None,
            session_ttl_seconds: None,
            hwid_override: None
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub session_token: String,
    pub expires_in: u64,
    pub session_expires_at: Option<String>,
    pub license_expires_at: Option<String>,
    pub max_hwid_slots: Option<u64>,
    pub hwid_count: Option<u64>,
    pub license_label: Option<String>,
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

impl AuthForgeError {
    /// Machine-readable code: the server's error code (`"revoked"`,
    /// `"hwid_mismatch"`, ...; `malformed_request` and unknown codes arrive
    /// as `Other(code)`) or an SDK code (`"network_error"`, `"timeout"`,
    /// `"http_error_502"`, `"unexpected_response"`, ...).
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidApp => "invalid_app",
            Self::InvalidKey => "invalid_key",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::HwidMismatch => "hwid_mismatch",
            Self::NoCredits => "no_credits",
            Self::AppBurnCapReached => "app_burn_cap_reached",
            Self::Blocked => "blocked",
            Self::RateLimited => "rate_limited",
            Self::ReplayDetected => "replay_detected",
            Self::AppDisabled => "app_disabled",
            Self::SessionExpired => "session_expired",
            Self::RevokeRequiresSession => "revoke_requires_session",
            Self::BadRequest => "bad_request",
            Self::SystemError => "system_error",
            Self::SignatureMismatch => "signature_mismatch",
            Self::NetworkError(detail) => {
                if detail.starts_with("timeout") {
                    "timeout"
                } else if detail.starts_with("invalid_json_response") {
                    "invalid_json_response"
                } else {
                    "network_error"
                }
            }
            Self::Other(detail) => detail.split(':').next().unwrap_or_default().trim()
        }
    }

    /// `true` unless the code is in [`DEFINITIVE_ERROR_CODES`]: network
    /// errors, timeouts, `rate_limited`, `system_error`, `no_credits`,
    /// unparseable or unexpected responses, every `http_error_N` and any
    /// code this SDK version doesn't know.
    pub fn is_transient(&self) -> bool {
        is_transient_error_code(self.code())
    }

    /// `true` when AuthForge definitively rejected the session or license:
    /// the code is in [`DEFINITIVE_ERROR_CODES`].
    pub fn is_fatal(&self) -> bool {
        !self.is_transient()
    }
}

impl fmt::Display for AuthForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkError(detail) | Self::Other(detail) if !detail.starts_with(self.code()) => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::NetworkError(detail) | Self::Other(detail) => f.write_str(detail),
            _ => f.write_str(self.code())
        }
    }
}

impl std::error::Error for AuthForgeError {}

/// Codes that definitively end the session. Every other code, including
/// codes this SDK version doesn't know, is transient.
pub const DEFINITIVE_ERROR_CODES: &[&str] = &[
    "revoked",
    "expired",
    "hwid_mismatch",
    "blocked",
    "session_expired",
    "malformed_request",
    "app_disabled",
    "invalid_app",
    "signature_mismatch"
];

/// Classifies an [`AuthForgeError::code`] value: `false` for the codes in
/// [`DEFINITIVE_ERROR_CODES`], `true` for everything else.
pub fn is_transient_error_code(code: &str) -> bool {
    !DEFINITIVE_ERROR_CODES.contains(&code)
}

#[derive(Clone)]
struct RuntimeConfig {
    app_id: String,
    app_secret: String,
    /// Canonical trust list — never empty after construction.
    public_keys: Vec<String>,
    /// Effective policy: `true` runs online check-ins (`/auth/heartbeat`),
    /// `false` runs the grace period check (no network).
    online_heartbeat: bool,
    heartbeat_interval: u64,
    api_base_url: String,
    request_timeout: u64,
    heartbeat_request_timeout: u64,
    on_failure: Option<Arc<FailureCallback>>,
    on_heartbeat_failure: Option<Arc<HeartbeatFailureCallback>>,
    session_ttl_seconds: Option<u64>
}

/// How the client authenticated: a server session from [`AuthForgeClient::login`]
/// or a locally verified `.authforge` file from [`AuthForgeClient::login_from_file`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Online,
    Offline
}

#[derive(Debug, Clone)]
struct SessionState {
    authenticated: bool,
    /// Drives `is_authenticated`, `self_ban` and the heartbeat guard so an
    /// offline file session can never be mistaken for a server session.
    session_kind: Option<SessionKind>,
    license_key: Option<String>,
    session_token: Option<String>,
    expires_in: Option<u64>,
    session_data: Option<Value>,
    app_variables: Option<HashMap<String, Value>>,
    license_variables: Option<HashMap<String, Value>>,
    /// Set when the client authenticated via `login_from_file`.
    offline_license: Option<OfflineLicense>,
    /// Bumped by `logout` and `login` (and kept by `clear`) so a heartbeat
    /// still in flight for an earlier session never writes to the current one.
    generation: u64
}

impl SessionState {
    fn clear(&mut self) {
        self.authenticated = false;
        self.session_kind = None;
        self.license_key = None;
        self.session_token = None;
        self.expires_in = None;
        self.session_data = None;
        self.app_variables = None;
        self.license_variables = None;
        self.offline_license = None;
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
    /// Wakes the heartbeat thread from a timed wait (logout, drop, restart).
    heartbeat_wake: Mutex<()>,
    heartbeat_wake_cvar: Condvar,
    heartbeat_handle: Mutex<Option<JoinHandle<()>>>,
    sleep: fn(Duration)
}

impl ClientInner {
    /// Wait until `deadline`, [`Self::stop_signal`] becomes true, or [`Self::wake_heartbeat_waiters`].
    /// Returns `true` if the worker should exit (stop requested).
    fn wait_until_heartbeat_deadline(&self, deadline: Instant) -> bool {
        while !self.stop_signal.load(Ordering::SeqCst) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let timeout = deadline.duration_since(now);
            let guard = self
                .heartbeat_wake
                .lock()
                .expect("authforge heartbeat wake mutex poisoned");
            let (guard, _wait) = self
                .heartbeat_wake_cvar
                .wait_timeout(guard, timeout)
                .expect("authforge heartbeat condvar poisoned");
            drop(guard);
        }
        true
    }

    fn wake_heartbeat_waiters(&self) {
        self.heartbeat_wake_cvar.notify_all();
    }
}

pub struct AuthForgeClient {
    inner: Arc<ClientInner>,
    /// Set on the heartbeat thread's own handle so dropping it when the
    /// thread exits doesn't stop (and join) the worker it belongs to.
    worker: bool
}

#[derive(Deserialize)]
struct SignedResponse {
    #[serde(default)]
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
    session_expires_at: Option<String>,
    license_expires_at: Option<Value>,
    max_hwid_slots: Option<u64>,
    hwid_count: Option<u64>,
    license_label: Option<String>,
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

fn license_expires_from_payload(value: &Option<Value>) -> Option<String> {
    match value {
        None => None,
        Some(Value::Null) => Some(String::new()),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None
    }
}

impl AuthForgeClient {
    pub fn new(config: AuthForgeConfig) -> Self {
        let on_failure = config.on_failure.map(Arc::<FailureCallback>::from);
        let on_heartbeat_failure = config
            .on_heartbeat_failure
            .map(Arc::<HeartbeatFailureCallback>::from);
        let public_keys = collect_public_keys(&config.public_keys, &config.public_key);
        // Effective policy: the deprecated HeartbeatMode::Server shim still
        // opts into online check-ins.
        #[allow(deprecated)]
        let online_heartbeat =
            config.online_heartbeat || matches!(config.heartbeat_mode, HeartbeatMode::Server);
        let runtime_cfg = RuntimeConfig {
            app_id: config.app_id,
            app_secret: config.app_secret,
            public_keys,
            online_heartbeat,
            heartbeat_interval: if config.heartbeat_interval == 0 {
                900
            } else if config.heartbeat_interval < 10 {
                10
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
            heartbeat_request_timeout: match config.heartbeat_request_timeout {
                None | Some(0) => 8,
                Some(secs) => secs
            },
            on_failure,
            on_heartbeat_failure,
            session_ttl_seconds: config.session_ttl_seconds
        };

        let inner = ClientInner {
            cfg: runtime_cfg,
            hwid: resolve_hwid(config.hwid_override),
            state: Arc::new(Mutex::new(SessionState {
                authenticated: false,
                session_kind: None,
                license_key: None,
                session_token: None,
                expires_in: None,
                session_data: None,
                app_variables: None,
                license_variables: None,
                offline_license: None,
                generation: 0
            })),
            stop_signal: Arc::new(AtomicBool::new(false)),
            heartbeat_wake: Mutex::new(()),
            heartbeat_wake_cvar: Condvar::new(),
            heartbeat_handle: Mutex::new(None),
            sleep: thread::sleep
        };

        Self {
            inner: Arc::new(inner),
            worker: false
        }
    }

    pub fn login(&self, license_key: &str) -> Result<LoginResult, AuthForgeError> {
        if self.inner.cfg.app_id.trim().is_empty()
            || self.inner.cfg.app_secret.trim().is_empty()
            || self.inner.cfg.public_keys.is_empty()
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
            || self.inner.cfg.public_keys.is_empty()
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
        let (current_session, current_license, current_kind) = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            (
                state.session_token.clone(),
                state.license_key.clone(),
                state.session_kind
            )
        };

        let explicit_session = session_token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let explicit_license = license_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        // An offline session has no server session and must never phone home
        // on its own. Callers who pass an explicit license key / session token
        // are asking about a *different* credential and get the normal paths.
        if current_kind == Some(SessionKind::Offline)
            && explicit_session.is_none()
            && explicit_license.is_none()
        {
            return Err(AuthForgeError::Other("offline_session".to_string()));
        }

        let resolved_session = explicit_session.or(current_session);
        if let Some(session) = resolved_session {
            let request = SelfBanPostSessionRequest {
                app_id: &self.inner.cfg.app_id,
                session_token: &session,
                hwid: &self.inner.hwid,
                revoke_license,
                blacklist_hwid,
                blacklist_ip
            };
            let (response, _) = self.post_json(
                "/auth/selfban",
                &request,
                true,
                self.inner.cfg.request_timeout
            )?;
            if !is_success_status(&response.status) {
                let code = response.error.unwrap_or_else(|| "unknown_error".to_string());
                return Err(map_server_error(&code));
            }
            return Ok(());
        }

        let resolved_license = explicit_license
            .or(current_license)
            .ok_or_else(|| AuthForgeError::Other("missing_license_key".to_string()))?;
        if self.inner.cfg.app_secret.trim().is_empty() {
            return Err(AuthForgeError::InvalidApp);
        }
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
        let (response, _) = self.post_json(
            "/auth/selfban",
            &request,
            true,
            self.inner.cfg.request_timeout
        )?;
        if !is_success_status(&response.status) {
            let code = response.error.unwrap_or_else(|| "unknown_error".to_string());
            return Err(map_server_error(&code));
        }
        Ok(())
    }

    pub fn logout(&self) {
        self.inner.stop_signal.store(true, Ordering::SeqCst);
        {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("authforge state mutex poisoned in logout");
            state.generation += 1;
            state.clear();
        }
        self.inner.wake_heartbeat_waiters();
        self.detach_heartbeat_worker_if_running();
    }

    /// `true` for an online session ([`Self::login`]) or an offline one
    /// ([`Self::login_from_file`]).
    pub fn is_authenticated(&self) -> bool {
        self.inner
            .state
            .lock()
            .map(|state| {
                state.authenticated
                    && match state.session_kind {
                        Some(SessionKind::Online) => state.session_token.is_some(),
                        Some(SessionKind::Offline) => true,
                        None => false
                    }
            })
            .unwrap_or(false)
    }

    /// How the client authenticated: [`SessionKind::Online`] after
    /// [`Self::login`], [`SessionKind::Offline`] after [`Self::login_from_file`],
    /// `None` when logged out. [`Self::self_ban`] without an explicit license
    /// key / session token fails with `Other("offline_session")` on an offline
    /// session and never contacts the server.
    pub fn get_session_kind(&self) -> Option<SessionKind> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.session_kind)
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

    /// The HWID this client sends to AuthForge (or `hwid_override`).
    ///
    /// Customers on air-gapped machines report this value to the operator so
    /// an offline `.authforge` file can be bound to it.
    pub fn hwid(&self) -> &str {
        &self.inner.hwid
    }

    /// Build an activation request (`.authforge-request`) for this machine.
    /// No network, no session, no app secret. `machine_name` is omitted
    /// unless `opts.include_machine_name` is true.
    pub fn create_activation_request(&self, opts: ActivationRequestOptions) -> String {
        let created_at = opts.created_at.unwrap_or_else(offline::now_iso_ms);
        let machine_name = if opts.include_machine_name {
            opts.machine_name.or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        } else {
            None
        };
        let os = if opts.omit_os {
            None
        } else {
            Some(opts.os.unwrap_or_else(offline::default_os_label))
        };
        let sdk = if opts.omit_sdk {
            None
        } else {
            Some(opts.sdk.unwrap_or_else(|| offline::sdk_tag().to_string()))
        };
        let license_key = match opts.license_key {
            Some(key) => {
                if key.is_empty() {
                    None
                } else {
                    Some(key)
                }
            }
            None => self
                .inner
                .state
                .lock()
                .ok()
                .and_then(|state| state.license_key.clone())
        };
        format_activation_request(
            &self.inner.cfg.app_id,
            &self.inner.hwid,
            &created_at,
            machine_name.as_deref(),
            os.as_deref(),
            sdk.as_deref(),
            license_key.as_deref()
        )
    }

    /// Authorize from a cloud-minted offline license file (`.authforge`) with
    /// NO network access. Accepts a filesystem path or the armored text.
    ///
    /// On success the client is authenticated ([`Self::is_authenticated`],
    /// [`Self::get_session_data`], [`Self::get_app_variables`],
    /// [`Self::get_license_variables`] work) and [`Self::get_offline_license`]
    /// describes the file. No grace-period thread and no online check-ins are
    /// started - the file's own `expires_at` is the only clock. Online
    /// [`Self::login`] is untouched.
    ///
    /// Failures are returned as [`OfflineLicenseError`] and echoed to
    /// `on_failure` as `offline_login_failed: <code>`.
    pub fn login_from_file(&self, path_or_text: &str) -> Result<OfflineLicense, OfflineLicenseError> {
        let text = read_license_file_input(path_or_text).inspect_err(|err| {
            self.notify_failure(&format!("offline_login_failed: {err}"));
        })?;
        let lic = self.verify_license_file_text(&text, None).inspect_err(|err| {
            self.notify_failure(&format!("offline_login_failed: {}", err.code()));
        })?;
        self.apply_offline_license(&lic);
        Ok(lic)
    }

    /// Verify a `.authforge` file (filesystem path or armored text) with this
    /// client's app id, public key(s) and HWID, without touching session state.
    pub fn verify_license_file(&self, path_or_text: &str) -> Result<OfflineLicense, OfflineLicenseError> {
        let text = read_license_file_input(path_or_text)?;
        self.verify_license_file_text(&text, None)
    }

    /// The offline file the client authenticated with, or `None`.
    pub fn get_offline_license(&self) -> Option<OfflineLicense> {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.offline_license.clone())
    }

    fn verify_license_file_text(
        &self,
        text: &str,
        now_epoch_ms: Option<i64>
    ) -> Result<OfflineLicense, OfflineLicenseError> {
        verify_license_file(
            text,
            &VerifyLicenseFileOptions {
                app_id: self.inner.cfg.app_id.clone(),
                public_keys: self.inner.cfg.public_keys.clone(),
                hwid: Some(self.inner.hwid.clone()),
                now_epoch_ms
            }
        )
    }

    fn apply_offline_license(&self, lic: &OfflineLicense) {
        // Stop any online session first so the two modes never overlap.
        self.logout();
        let expires_in = lic
            .expires_at
            .as_deref()
            .and_then(parse_iso8601_ms)
            .map(|ms| (ms / 1000).max(0) as u64);
        let mut state = self
            .inner
            .state
            .lock()
            .expect("authforge state mutex poisoned in login_from_file");
        state.authenticated = true;
        state.license_key = Some(lic.license_key.clone());
        // Offline files carry no server session token. The explicit session
        // kind (not a token sentinel) is what makes is_authenticated true and
        // keeps self_ban/heartbeats from ever contacting the server.
        state.session_token = None;
        state.session_kind = Some(SessionKind::Offline);
        state.expires_in = expires_in;
        state.session_data = Some(lic.payload.clone());
        state.app_variables = lic.app_variables.clone();
        state.license_variables = lic.license_variables.clone();
        state.offline_license = Some(lic.clone());
    }

    fn notify_failure(&self, message: &str) {
        if let Some(callback) = &self.inner.cfg.on_failure {
            callback(message);
        }
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

        let (response, used_nonce) = self.post_json(
            "/auth/validate",
            &request,
            invoke_on_network_failure,
            self.inner.cfg.request_timeout
        )?;
        let payload = self.verify_signed_response(
            response,
            used_nonce.as_deref().unwrap_or(&nonce),
            SigningContext::Validate
        )?;
        let request_id = payload.request_id.clone().unwrap_or_default();

        let result = LoginResult {
            session_token: payload.session_token.clone(),
            expires_in: payload.expires_in,
            session_expires_at: payload.session_expires_at.clone(),
            license_expires_at: license_expires_from_payload(&payload.license_expires_at),
            max_hwid_slots: payload.max_hwid_slots,
            hwid_count: payload.hwid_count,
            license_label: payload.license_label.clone(),
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
        state.generation += 1;
        state.authenticated = true;
        state.session_kind = Some(SessionKind::Online);
        state.license_key = Some(license_key.to_string());
        state.session_token = Some(payload.session_token.clone());
        state.expires_in = Some(payload.expires_in);
        state.app_variables = payload.app_variables.clone();
        state.license_variables = payload.license_variables.clone();
        state.session_data = Some(serde_json::to_value(&payload).unwrap_or(Value::Null));

        Ok(result)
    }

    /// One online check-in for the session `generation` identifies. Returns
    /// `Ok(())` without touching state once that session was replaced.
    fn server_heartbeat_with_retry(&self, generation: u64) -> Result<(), AuthForgeError> {
        let session_token = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            if state.generation != generation {
                return Ok(());
            }
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

        // Network failures surface once, through the heartbeat failure callback.
        let (response, used_nonce) = self.post_json(
            "/auth/heartbeat",
            &request,
            false,
            self.inner.cfg.heartbeat_request_timeout
        )?;
        if self.is_stale_heartbeat(generation) {
            return Ok(());
        }
        if !is_success_status(&response.status) {
            return Err(heartbeat_failure_error(&response));
        }
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
        if state.generation != generation || self.inner.stop_signal.load(Ordering::SeqCst) {
            return Ok(());
        }
        state.authenticated = true;
        state.session_token = Some(session_token);
        state.expires_in = Some(expires_in);
        state.session_data = Some(session_data);
        Ok(())
    }

    /// Grace period check: no network. Confirms the session is still
    /// authenticated and the stored expiry has not passed, failing with
    /// `SessionExpired` once the grace period (the session TTL) runs out.
    fn grace_period_check(&self) -> Result<(), AuthForgeError> {
        let (authenticated, expires_in) = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| AuthForgeError::Other("state_lock_failed".to_string()))?;
            (state.authenticated, state.expires_in)
        };

        if !authenticated {
            return Err(AuthForgeError::SessionExpired);
        }

        let expires = expires_in.ok_or(AuthForgeError::SessionExpired)?;
        let now = epoch_now();
        if now >= expires {
            return Err(AuthForgeError::SessionExpired);
        }

        Ok(())
    }

    fn post_json<T: Serialize>(
        &self,
        path: &str,
        body: &T,
        invoke_on_network_failure: bool,
        timeout_secs: u64
    ) -> Result<(SignedResponse, Option<String>), AuthForgeError> {
        let agent = build_agent(timeout_secs);
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
            let (status_code, parsed) = match response {
                Ok(resp) => {
                    let status_code = resp.status();
                    (status_code, parse_signed_response(resp.into_string().unwrap_or_default())?)
                }
                Err(UreqError::Status(status_code, response)) => {
                    let body_text = response.into_string().unwrap_or_default();
                    let parsed = parse_signed_response(body_text)
                        .ok()
                        .filter(|parsed| !parsed.status.is_null() || parsed.error.is_some())
                        .ok_or_else(|| AuthForgeError::Other(format!("http_error_{status_code}")))?;
                    (status_code, parsed)
                }
                Err(UreqError::Transport(err)) => {
                    if !network_retried {
                        network_retried = true;
                        (self.inner.sleep)(Duration::from_secs(2));
                        continue;
                    }
                    if invoke_on_network_failure {
                        if let Some(callback) = &self.inner.cfg.on_failure {
                            callback("network_error");
                        }
                    }
                    let detail = if is_timeout(&err) {
                        format!("timeout: {err}")
                    } else {
                        err.to_string()
                    };
                    return Err(AuthForgeError::NetworkError(detail));
                }
            };
            // no_credits / app_burn_cap_reached / demo_quota_exceeded also use
            // HTTP 429 but are not worth retrying; only retry a genuine rate limit.
            let has_error_code = parsed.error.as_deref().is_some_and(|code| !code.trim().is_empty());
            let is_rate_limited = response_error_code(&parsed).as_deref() == Some("rate_limited")
                || (status_code == 429 && !has_error_code);
            if is_rate_limited && rate_attempt < 2 {
                (self.inner.sleep)(Duration::from_secs(if rate_attempt == 0 { 2 } else { 5 }));
                rate_attempt += 1;
                continue;
            }
            return Ok((parsed, used_nonce));
        }
    }

    fn verify_signed_response(
        &self,
        response: SignedResponse,
        expected_nonce: &str,
        context: SigningContext
    ) -> Result<SignedPayload, AuthForgeError> {
        if !is_success_status(&response.status) {
            let server_error = response
                .error
                .map(|code| code.trim().to_ascii_lowercase())
                .filter(|code| !code.is_empty())
                .unwrap_or_else(|| "unknown_error".to_string());
            return Err(map_server_error(&server_error));
        }

        let payload_b64 = response
            .payload
            .ok_or_else(|| AuthForgeError::Other("missing_payload".to_string()))?;
        let signature = response
            .signature
            .ok_or_else(|| AuthForgeError::Other("missing_signature".to_string()))?;

        _ = context;
        if !verify_payload_signature_ed25519_any(
            &payload_b64,
            &signature,
            &self.inner.cfg.public_keys,
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
        // Offline sessions have no grace period and no online check-ins: the
        // file's own expires_at is the only clock. Never start a thread for them.
        let offline = self
            .inner
            .state
            .lock()
            .map(|state| state.session_kind == Some(SessionKind::Offline))
            .unwrap_or(false);
        if offline {
            return;
        }
        self.stop_heartbeat_thread();
        self.inner.stop_signal.store(false, Ordering::SeqCst);

        let client = AuthForgeClient {
            inner: Arc::clone(&self.inner),
            worker: true
        };
        let interval = self.inner.cfg.heartbeat_interval;
        // Held across spawn so the worker can't check whether it is still
        // the registered worker before its handle is stored.
        let mut lock = self
            .inner
            .heartbeat_handle
            .lock()
            .expect("authforge heartbeat mutex poisoned in start_heartbeat_thread");
        let handle = thread::spawn(move || {
            let inner = Arc::clone(&client.inner);
            let mut deadline = Instant::now() + Duration::from_secs(interval);

            while !inner.stop_signal.load(Ordering::SeqCst) {
                if inner.wait_until_heartbeat_deadline(deadline) {
                    break;
                }
                if inner.stop_signal.load(Ordering::SeqCst) {
                    break;
                }
                if !client.heartbeat_tick() || !client.is_current_heartbeat_worker() {
                    break;
                }
                deadline = Instant::now() + Duration::from_secs(interval);
            }
        });
        *lock = Some(handle);
    }

    /// Runs one background check and reports whether checks should continue.
    /// Transient failures keep the session and check in again next interval.
    /// Definitive failures clear the session first (as [`Self::logout`]
    /// does), so neither the grace period nor [`Self::is_authenticated`]
    /// keeps the app running on it.
    fn heartbeat_tick(&self) -> bool {
        let generation = self.session_generation();
        // Online check-ins call /auth/heartbeat; otherwise run the grace
        // period check against the stored session expiry.
        let result = if self.inner.cfg.online_heartbeat {
            self.server_heartbeat_with_retry(generation)
        } else {
            self.grace_period_check()
        };
        let err = match result {
            Ok(()) => return true,
            Err(err) => err
        };
        if self.is_stale_heartbeat(generation) {
            return false;
        }

        // A transient failure can't extend the session past its signed TTL.
        let failure = if err.is_transient() && self.local_session_expired() {
            AuthForgeError::SessionExpired
        } else {
            err
        };
        let fatal = failure.is_fatal();
        if fatal && !self.end_session(generation) {
            return false;
        }
        if let Some(callback) = &self.inner.cfg.on_heartbeat_failure {
            callback(&failure);
        } else if let Some(callback) = &self.inner.cfg.on_failure {
            callback(&failure.to_string());
        }
        !fatal
    }

    fn session_generation(&self) -> u64 {
        self.inner
            .state
            .lock()
            .map(|state| state.generation)
            .unwrap_or_default()
    }

    /// `true` once `logout` or a new `login` replaced the session a check
    /// started for.
    fn is_stale_heartbeat(&self, generation: u64) -> bool {
        self.inner.stop_signal.load(Ordering::SeqCst) || self.session_generation() != generation
    }

    /// Clears the session and stops check-ins like [`Self::logout`], unless
    /// the session `generation` identifies was already replaced. The worker
    /// keeps its join handle; `logout`, `login` and drop reclaim it.
    fn end_session(&self, generation: u64) -> bool {
        {
            let Ok(mut state) = self.inner.state.lock() else {
                return false;
            };
            if state.generation != generation {
                return false;
            }
            state.generation += 1;
            state.clear();
            self.inner.stop_signal.store(true, Ordering::SeqCst);
        }
        self.inner.wake_heartbeat_waiters();
        true
    }

    fn local_session_expired(&self) -> bool {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| state.expires_in)
            .is_some_and(|expires| epoch_now() >= expires)
    }

    /// `false` once `logout` or a new `login` replaced this worker.
    fn is_current_heartbeat_worker(&self) -> bool {
        !self.inner.stop_signal.load(Ordering::SeqCst)
            && self
                .inner
                .heartbeat_handle
                .lock()
                .map(|slot| {
                    slot.as_ref()
                        .is_some_and(|handle| handle.thread().id() == thread::current().id())
                })
                .unwrap_or(false)
    }

    /// Removes the join handle quickly; caller must [`JoinHandle::join`] or drop
    /// (detach) without holding [`ClientInner::heartbeat_handle`].
    fn take_heartbeat_worker(&self) -> Option<JoinHandle<()>> {
        self.inner
            .heartbeat_handle
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
    }

    fn join_heartbeat_worker_if_running(&self) {
        if let Some(handle) = self.take_heartbeat_worker() {
            // Failure callbacks run on the worker, which can't join itself.
            if handle.thread().id() != thread::current().id() {
                let _ = handle.join();
            }
        }
    }

    /// Drops the join handle without blocking on the worker (typically stuck in
    /// HTTP). The worker still observes [`ClientInner::stop_signal`] and skips
    /// session writes after a late heartbeat response.
    fn detach_heartbeat_worker_if_running(&self) {
        if let Some(handle) = self.take_heartbeat_worker() {
            drop(handle);
        }
    }

    fn stop_heartbeat_thread(&self) {
        self.inner.stop_signal.store(true, Ordering::SeqCst);
        self.inner.wake_heartbeat_waiters();
        self.join_heartbeat_worker_if_running();
    }
}

impl Clone for AuthForgeClient {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            worker: false
        }
    }
}

impl Drop for AuthForgeClient {
    fn drop(&mut self) {
        if !self.worker {
            self.stop_heartbeat_thread();
        }
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
            api_base_url: format!("http://{}", addr_ok),
            ..Default::default()
        });
        let result = client_ok.validate_license("key").expect("validate");
        assert_eq!(result.session_token, "session.validate.token");
        assert!(!client_ok.is_authenticated());
        std::env::remove_var("AUTHFORGE_SDK_TEST_NONCE");

        // Rotation set: bogus key first, real key second. validate_license
        // must succeed because the *second* key in the trust list matches
        // the server's signature — exercising the multi-key fallback path.
        let ok_body_rotation = serde_json::json!({
            "status": "ok",
            "payload": success["payload"],
            "signature": success["signature"],
            "keyId": "signing-key-1",
        })
        .to_string();
        let addr_rotation = run_server(ok_body_rotation);
        std::env::set_var("AUTHFORGE_SDK_TEST_NONCE", "nonce-validate-001");
        let client_rotation = AuthForgeClient::new(AuthForgeConfig {
            app_id: "app".into(),
            app_secret: "secret".into(),
            public_keys: vec![
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                public_key.into(),
            ],
            api_base_url: format!("http://{}", addr_rotation),
            ..Default::default()
        });
        let rotation_result = client_rotation
            .validate_license("key")
            .expect("validate with rotation set");
        assert_eq!(rotation_result.session_token, "session.validate.token");
        std::env::remove_var("AUTHFORGE_SDK_TEST_NONCE");

        let err_body = r#"{"status":"invalid_key","error":"invalid_key"}"#.to_string();
        let addr_err = run_server(err_body);
        let client_err = AuthForgeClient::new(AuthForgeConfig {
            app_id: "app".into(),
            app_secret: "secret".into(),
            public_key: "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=".into(),
            api_base_url: format!("http://{}", addr_err),
            ..Default::default()
        });
        let err = client_err.validate_license("bad").unwrap_err();
        assert!(matches!(err, AuthForgeError::InvalidKey), "{err:?}");
        assert!(!client_err.is_authenticated());
    }

    #[test]
    fn default_config_uses_grace_period() {
        let config = AuthForgeConfig::default();
        assert!(!config.online_heartbeat);
        let client = AuthForgeClient::new(config);
        assert!(!client.inner.cfg.online_heartbeat);
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_server_mode_maps_to_online_check_ins() {
        let client = AuthForgeClient::new(AuthForgeConfig {
            heartbeat_mode: HeartbeatMode::Server,
            ..Default::default()
        });
        assert!(client.inner.cfg.online_heartbeat);
    }

    #[test]
    fn online_heartbeat_flag_enables_online_check_ins() {
        let client = AuthForgeClient::new(AuthForgeConfig {
            online_heartbeat: true,
            ..Default::default()
        });
        assert!(client.inner.cfg.online_heartbeat);
    }
}

#[cfg(test)]
mod heartbeat_tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    const HEARTBEAT_NONCE: &str = "nonce-heartbeat-001";
    const SEED_TOKEN: &str = "seed.session.token";
    const WAIT: Duration = Duration::from_secs(10);

    thread_local! {
        static SLEEPS: RefCell<Vec<Duration>> = const { RefCell::new(Vec::new()) };
    }

    fn record_sleep(duration: Duration) {
        SLEEPS.with(|sleeps| sleeps.borrow_mut().push(duration));
    }

    fn take_sleeps() -> Vec<Duration> {
        SLEEPS.with(|sleeps| std::mem::take(&mut *sleeps.borrow_mut()))
    }

    fn use_heartbeat_nonce() {
        TEST_NONCE.with(|nonce| *nonce.borrow_mut() = Some(HEARTBEAT_NONCE.to_string()));
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../test_vectors.json")).expect("vectors")
    }

    fn signed_body(id: &str) -> String {
        let vectors = vectors();
        let case = vectors["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|case| case["id"] == id)
            .expect("vector case")
            .clone();
        serde_json::json!({
            "status": "ok",
            "payload": case["payload"],
            "signature": case["signature"]
        })
        .to_string()
    }

    enum Reply {
        Respond(u16, String),
        Hang(Duration),
        Gated {
            reached: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            status: u16,
            body: String
        }
    }

    fn raw(status: u16, body: &str) -> Reply {
        Reply::Respond(status, body.to_string())
    }

    fn failed(status: u16, code: &str) -> Reply {
        Reply::Respond(status, format!(r#"{{"status":"failed","error":"{code}"}}"#))
    }

    /// Serves one scripted reply per connection, then closes the port.
    struct MockServer {
        url: String,
        requests: Arc<AtomicUsize>
    }

    impl MockServer {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("addr"));
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&requests);
            thread::spawn(move || {
                for reply in replies {
                    let Ok((mut stream, _)) = listener.accept() else {
                        return;
                    };
                    read_request(&mut stream);
                    counter.fetch_add(1, Ordering::SeqCst);
                    match reply {
                        Reply::Respond(status, body) => write_response(&mut stream, status, &body),
                        Reply::Hang(duration) => {
                            thread::spawn(move || {
                                thread::sleep(duration);
                                drop(stream);
                            });
                        }
                        Reply::Gated {
                            reached,
                            release,
                            status,
                            body
                        } => {
                            let _ = reached.send(());
                            let _ = release.recv_timeout(WAIT);
                            write_response(&mut stream, status, &body);
                        }
                    }
                }
            });
            Self { url, requests }
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    fn read_request(stream: &mut TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= end + 4 + length {
                    return;
                }
            }
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(read) => data.extend_from_slice(&buf[..read])
            }
        }
    }

    fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
        let response = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    }

    fn closed_port_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", listener.local_addr().expect("addr"))
    }

    fn seed_session(client: &AuthForgeClient, token: &str, expires_in: u64) {
        let mut state = client.inner.state.lock().expect("state");
        state.generation += 1;
        state.authenticated = true;
        state.session_kind = Some(SessionKind::Online);
        state.license_key = Some("key".to_string());
        state.session_token = Some(token.to_string());
        state.expires_in = Some(expires_in);
    }

    fn session_token(client: &AuthForgeClient) -> Option<String> {
        client.inner.state.lock().expect("state").session_token.clone()
    }

    fn client_with(url: &str, configure: impl FnOnce(&mut AuthForgeConfig)) -> AuthForgeClient {
        let mut config = AuthForgeConfig {
            app_id: "app".into(),
            app_secret: "secret".into(),
            public_key: vectors()["publicKey"].as_str().expect("key").into(),
            online_heartbeat: true,
            api_base_url: url.into(),
            heartbeat_request_timeout: Some(5),
            ..Default::default()
        };
        configure(&mut config);
        let mut client = AuthForgeClient::new(config);
        Arc::get_mut(&mut client.inner).expect("unique client").sleep = record_sleep;
        seed_session(&client, SEED_TOKEN, epoch_now() + 3600);
        client
    }

    struct Harness {
        client: AuthForgeClient,
        server: MockServer,
        failures: Arc<Mutex<Vec<AuthForgeError>>>
    }

    impl Harness {
        fn new(replies: Vec<Reply>) -> Self {
            Self::with(replies, |_| {})
        }

        fn with(replies: Vec<Reply>, configure: impl FnOnce(&mut AuthForgeConfig)) -> Self {
            let server = MockServer::start(replies);
            let failures = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&failures);
            let client = client_with(&server.url, |config| {
                config.on_heartbeat_failure = Some(Box::new(move |err: &AuthForgeError| {
                    recorded.lock().expect("failures").push(err.clone());
                }));
                configure(config);
            });
            Self {
                client,
                server,
                failures
            }
        }

        fn tick(&self) -> bool {
            use_heartbeat_nonce();
            take_sleeps();
            self.client.heartbeat_tick()
        }

        fn only_failure(&self) -> AuthForgeError {
            let failures = self.failures.lock().expect("failures");
            assert_eq!(failures.len(), 1, "{failures:?}");
            failures[0].clone()
        }

        fn assert_fatal(&self, keep_checking: bool, code: &str, requests: usize) {
            let failure = self.only_failure();
            assert!(!keep_checking, "{code}: tick should stop check-ins");
            assert_eq!(failure.code(), code, "{failure:?}");
            assert!(failure.is_fatal(), "{failure:?}");
            assert!(!self.client.is_authenticated(), "{code}");
            assert_eq!(session_token(&self.client), None, "{code}");
            assert!(self.client.inner.stop_signal.load(Ordering::SeqCst), "{code}");
            assert_eq!(self.server.requests(), requests, "{code}");
        }

        fn assert_transient(&self, keep_checking: bool, code: &str, requests: usize) {
            let failure = self.only_failure();
            assert!(keep_checking, "{code}: tick should keep checking in");
            assert_eq!(failure.code(), code, "{failure:?}");
            assert!(failure.is_transient(), "{failure:?}");
            assert!(self.client.is_authenticated(), "{code}");
            assert_eq!(session_token(&self.client).as_deref(), Some(SEED_TOKEN), "{code}");
            assert_eq!(self.server.requests(), requests, "{code}");
        }
    }

    #[test]
    fn definitive_codes_clear_the_session_without_retrying() {
        let cases = [
            ("revoked", 410),
            ("expired", 410),
            ("hwid_mismatch", 403),
            ("blocked", 403),
            ("app_disabled", 403),
            ("session_expired", 401),
            ("invalid_app", 401),
            ("malformed_request", 400)
        ];
        for (code, status) in cases {
            for status in [status, 200] {
                let harness = Harness::new(vec![failed(status, code)]);
                let keep_checking = harness.tick();
                harness.assert_fatal(keep_checking, code, 1);
                assert!(take_sleeps().is_empty(), "{code} {status}");
            }
        }
    }

    #[test]
    fn verdict_status_and_code_are_normalized() {
        let harness = Harness::new(vec![raw(200, r#"{"status":" FAILED ","error":" Revoked "}"#)]);
        let keep_checking = harness.tick();
        harness.assert_fatal(keep_checking, "revoked", 1);
    }

    #[test]
    fn malformed_request_keeps_its_code() {
        let err = map_server_error("malformed_request");
        assert!(matches!(&err, AuthForgeError::Other(code) if code == "malformed_request"));
        assert_eq!(err.code(), "malformed_request");
        assert_eq!(err.to_string(), "malformed_request");
        assert!(err.is_fatal());
        assert!(matches!(map_server_error("bad_request"), AuthForgeError::BadRequest));
    }

    #[test]
    fn tampered_signature_is_definitive() {
        let harness = Harness::new(vec![raw(200, &signed_body("tampered_payload"))]);
        let keep_checking = harness.tick();
        harness.assert_fatal(keep_checking, "signature_mismatch", 1);
    }

    #[test]
    fn rate_limited_retries_then_stays_transient() {
        let harness = Harness::new(vec![
            failed(429, "rate_limited"),
            failed(429, "rate_limited"),
            failed(429, "rate_limited")
        ]);
        let keep_checking = harness.tick();
        harness.assert_transient(keep_checking, "rate_limited", 3);
        assert_eq!(take_sleeps(), vec![Duration::from_secs(2), Duration::from_secs(5)]);
    }

    #[test]
    fn transient_codes_keep_the_session() {
        let cases = [
            ("system_error", 500),
            ("server_error", 500),
            ("no_credits", 429),
            ("demo_quota_exceeded", 429),
            ("app_burn_cap_reached", 429),
            ("bad_request", 400),
            ("invalid_key", 401),
            ("brand_new_code", 403)
        ];
        for (code, status) in cases {
            let harness = Harness::new(vec![failed(status, code)]);
            let keep_checking = harness.tick();
            harness.assert_transient(keep_checking, code, 1);
            assert!(take_sleeps().is_empty(), "{code}");
        }
    }

    #[test]
    fn unparseable_bodies_are_transient() {
        let cases = [
            (403, "Forbidden", "http_error_403"),
            (500, "<html>Internal Server Error</html>", "http_error_500"),
            (502, "Bad Gateway", "http_error_502"),
            (503, "", "http_error_503"),
            (403, r#""revoked""#, "http_error_403"),
            (200, "", "invalid_json_response"),
            (200, "not json", "invalid_json_response"),
            (200, r#"["failed","revoked"]"#, "invalid_json_response"),
            (200, "null", "invalid_json_response")
        ];
        for (status, body, code) in cases {
            let harness = Harness::new(vec![raw(status, body)]);
            let keep_checking = harness.tick();
            harness.assert_transient(keep_checking, code, 1);
        }
    }

    #[test]
    fn malformed_failure_bodies_are_unexpected_responses() {
        let cases = [
            (403, r#"{"error":"revoked"}"#),
            (200, r#"{"error":"revoked"}"#),
            (403, r#"{"status":"revoked"}"#),
            (200, r#"{"status":"revoked"}"#),
            (200, r#"{"status":"failed"}"#),
            (410, r#"{"status":"failed","error":"  "}"#),
            (200, r#"{"status":false,"error":"revoked"}"#)
        ];
        for (status, body) in cases {
            let harness = Harness::new(vec![raw(status, body)]);
            let keep_checking = harness.tick();
            harness.assert_transient(keep_checking, "unexpected_response", 1);
        }
        let harness = Harness::new(vec![raw(403, r#"{"status":"revoked"}"#)]);
        harness.tick();
        assert_eq!(
            harness.only_failure().to_string(),
            r#"unexpected_response: status="revoked", error=null"#
        );
    }

    #[test]
    fn network_error_is_transient_and_reported_once() {
        let failures = Arc::new(Mutex::new(Vec::new()));
        let messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&failures);
        let legacy = Arc::clone(&messages);
        let client = client_with(&closed_port_url(), |config| {
            config.heartbeat_request_timeout = Some(15);
            config.on_heartbeat_failure = Some(Box::new(move |err: &AuthForgeError| {
                recorded.lock().expect("failures").push(err.clone());
            }));
            config.on_failure = Some(Box::new(move |message: &str| {
                legacy.lock().expect("messages").push(message.to_string());
            }));
        });
        take_sleeps();
        assert!(client.heartbeat_tick());
        let failures = failures.lock().expect("failures");
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].code(), "network_error", "{:?}", failures[0]);
        assert!(failures[0].is_transient());
        assert!(messages.lock().expect("messages").is_empty());
        assert!(client.is_authenticated());
        assert_eq!(take_sleeps(), vec![Duration::from_secs(2)]);
    }

    #[test]
    fn timeout_is_transient_and_reported_once() {
        let harness = Harness::with(
            vec![Reply::Hang(Duration::from_secs(4)), Reply::Hang(Duration::from_secs(4))],
            |config| config.heartbeat_request_timeout = Some(1)
        );
        let keep_checking = harness.tick();
        harness.assert_transient(keep_checking, "timeout", 2);
        let failure = harness.only_failure();
        assert!(matches!(&failure, AuthForgeError::NetworkError(detail) if detail.starts_with("timeout: ")));
        assert_eq!(take_sleeps(), vec![Duration::from_secs(2)]);
    }

    #[test]
    fn transient_failure_after_ttl_becomes_session_expired() {
        let harness = Harness::new(vec![failed(500, "system_error")]);
        seed_session(&harness.client, SEED_TOKEN, epoch_now() - 1);
        let keep_checking = harness.tick();
        harness.assert_fatal(keep_checking, "session_expired", 1);
        assert!(matches!(harness.only_failure(), AuthForgeError::SessionExpired));
    }

    #[test]
    fn success_after_transient_failure_refreshes_the_session() {
        let harness = Harness::new(vec![
            failed(500, "system_error"),
            raw(200, &signed_body("heartbeat_success"))
        ]);
        assert!(harness.tick());
        assert!(harness.tick());
        assert_eq!(harness.only_failure().code(), "system_error");
        assert!(harness.client.is_authenticated());
        assert_eq!(session_token(&harness.client).as_deref(), Some("session.heartbeat.token"));
        assert_eq!(
            harness.client.inner.state.lock().expect("state").expires_in,
            Some(1_900_000_300)
        );
        assert_eq!(harness.server.requests(), 2);
    }

    #[test]
    fn grace_period_expiry_is_session_expired() {
        let harness = Harness::with(Vec::new(), |config| config.online_heartbeat = false);
        assert!(harness.tick());
        assert!(harness.failures.lock().expect("failures").is_empty());

        seed_session(&harness.client, SEED_TOKEN, epoch_now() - 1);
        let keep_checking = harness.tick();
        harness.assert_fatal(keep_checking, "session_expired", 0);
        assert!(matches!(harness.only_failure(), AuthForgeError::SessionExpired));

        let harness = Harness::with(Vec::new(), |config| config.online_heartbeat = false);
        harness.client.inner.state.lock().expect("state").authenticated = false;
        let keep_checking = harness.tick();
        harness.assert_fatal(keep_checking, "session_expired", 0);
    }

    #[test]
    fn legacy_on_failure_receives_the_display_form() {
        let server = MockServer::start(vec![failed(410, "revoked")]);
        let messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let legacy = Arc::clone(&messages);
        let client = client_with(&server.url, |config| {
            config.on_failure = Some(Box::new(move |message: &str| {
                legacy.lock().expect("messages").push(message.to_string());
            }));
        });
        use_heartbeat_nonce();
        assert!(!client.heartbeat_tick());
        assert_eq!(*messages.lock().expect("messages"), vec!["revoked".to_string()]);
        assert!(!client.is_authenticated());
    }

    #[test]
    fn error_code_classification() {
        for code in DEFINITIVE_ERROR_CODES {
            assert!(!is_transient_error_code(code), "{code}");
        }
        for code in [
            "network_error",
            "timeout",
            "rate_limited",
            "system_error",
            "server_error",
            "invalid_json_response",
            "unexpected_response",
            "http_error_400",
            "http_error_403",
            "http_error_404",
            "http_error_500",
            "http_error_502",
            "no_credits",
            "demo_quota_exceeded",
            "app_burn_cap_reached",
            "bad_request",
            "invalid_key",
            "replay_detected",
            "revoke_requires_session",
            "missing_session_token",
            "state_lock_failed",
            "missing_payload",
            "brand_new_code",
            ""
        ] {
            assert!(is_transient_error_code(code), "{code}");
        }
        assert!(AuthForgeError::Revoked.is_fatal());
        assert!(AuthForgeError::SessionExpired.is_fatal());
        assert!(AuthForgeError::SignatureMismatch.is_fatal());
        assert!(AuthForgeError::NoCredits.is_transient());
        assert!(AuthForgeError::ReplayDetected.is_transient());
        assert!(AuthForgeError::Other("brand_new_code".into()).is_transient());
        let timeout = AuthForgeError::NetworkError("timeout: read timed out".into());
        assert_eq!(timeout.code(), "timeout");
        assert_eq!(timeout.to_string(), "timeout: read timed out");
        let network = AuthForgeError::NetworkError("connection refused".into());
        assert_eq!(network.code(), "network_error");
        assert_eq!(network.to_string(), "network_error: connection refused");
        assert_eq!(AuthForgeError::HwidMismatch.to_string(), "hwid_mismatch");
    }

    #[test]
    fn callback_can_logout_and_query_the_client() {
        for (reply, fatal) in [(failed(500, "system_error"), false), (failed(403, "revoked"), true)] {
            let server = MockServer::start(vec![reply]);
            let slot = Arc::new(Mutex::new(None::<AuthForgeClient>));
            let (seen_tx, seen_rx) = mpsc::channel::<(bool, bool)>();
            let seen_tx = Mutex::new(seen_tx);
            let callback_slot = Arc::clone(&slot);
            let client = client_with(&server.url, |config| {
                config.on_heartbeat_failure = Some(Box::new(move |_err: &AuthForgeError| {
                    let guard = callback_slot.lock().expect("slot");
                    let client = guard.as_ref().expect("client");
                    let before = client.is_authenticated();
                    client.logout();
                    let after = client.is_authenticated();
                    let _ = seen_tx.lock().expect("sender").send((before, after));
                }));
            });
            let ticker = client.clone();
            *slot.lock().expect("slot") = Some(client);

            let (done_tx, done_rx) = mpsc::channel();
            thread::spawn(move || {
                use_heartbeat_nonce();
                let _ = done_tx.send(ticker.heartbeat_tick());
            });
            let keep_checking = done_rx.recv_timeout(WAIT).expect("tick finished without deadlock");
            let (before, after) = seen_rx.recv_timeout(WAIT).expect("callback ran");
            assert_eq!(keep_checking, !fatal);
            assert_eq!(before, !fatal);
            assert!(!after);
            slot.lock().expect("slot").take();
        }
    }

    struct DropSignal(Mutex<mpsc::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Ok(sender) = self.0.lock() {
                let _ = sender.send(());
            }
        }
    }

    #[test]
    fn callback_can_drop_the_last_client_on_the_worker() {
        for (online, reply) in [(false, None), (true, Some(failed(500, "system_error")))] {
            let server = MockServer::start(reply.into_iter().collect());
            let slot = Arc::new(Mutex::new(None::<AuthForgeClient>));
            let (called_tx, called_rx) = mpsc::channel::<()>();
            let called_tx = Mutex::new(called_tx);
            let (dropped_tx, dropped_rx) = mpsc::channel::<()>();
            let dropped = DropSignal(Mutex::new(dropped_tx));
            let callback_slot = Arc::clone(&slot);
            let mut client = client_with(&server.url, |config| {
                config.online_heartbeat = online;
                config.on_heartbeat_failure = Some(Box::new(move |_err: &AuthForgeError| {
                    let _ = &dropped;
                    let client = callback_slot.lock().expect("slot").take();
                    drop(client);
                    let _ = called_tx.lock().expect("sender").send(());
                }));
            });
            Arc::get_mut(&mut client.inner)
                .expect("unique client")
                .cfg
                .heartbeat_interval = 0;
            if !online {
                seed_session(&client, SEED_TOKEN, epoch_now() - 1);
            }

            let mut guard = slot.lock().expect("slot");
            guard.insert(client).start_heartbeat_thread();
            drop(guard);

            called_rx.recv_timeout(WAIT).expect("callback dropped the client");
            dropped_rx.recv_timeout(WAIT).expect("worker exited and released the client");
            assert!(slot.lock().expect("slot").is_none());
        }
    }

    #[test]
    fn late_heartbeat_response_cannot_restore_a_replaced_session() {
        for body in [signed_body("heartbeat_success"), r#"{"status":"failed","error":"revoked"}"#.to_string()] {
            for relogin in [false, true] {
                let (reached_tx, reached_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let harness = Harness::new(vec![Reply::Gated {
                    reached: reached_tx,
                    release: release_rx,
                    status: 200,
                    body: body.clone()
                }]);
                let ticker = harness.client.clone();
                let tick = thread::spawn(move || {
                    use_heartbeat_nonce();
                    ticker.heartbeat_tick()
                });
                reached_rx.recv_timeout(WAIT).expect("heartbeat in flight");
                harness.client.logout();
                if relogin {
                    seed_session(&harness.client, "replacement.session.token", epoch_now() + 3600);
                    harness.client.inner.stop_signal.store(false, Ordering::SeqCst);
                }
                release_tx.send(()).expect("release");
                tick.join().expect("tick thread");

                assert!(harness.failures.lock().expect("failures").is_empty());
                if relogin {
                    assert!(harness.client.is_authenticated());
                    assert_eq!(
                        session_token(&harness.client).as_deref(),
                        Some("replacement.session.token")
                    );
                } else {
                    assert!(!harness.client.is_authenticated());
                    assert_eq!(session_token(&harness.client), None);
                }
            }
        }
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

/// Multi-key variant: returns `Ok(true)` if the signature matches *any* key
/// in `public_keys`. Used internally so the SDK keeps verifying during a
/// server-side rotation; entries that are malformed are skipped rather than
/// causing the whole call to fail.
pub fn verify_payload_signature_ed25519_any(
    payload_base64: &str,
    signature_base64: &str,
    public_keys: &[String],
) -> Result<bool, AuthForgeError> {
    if public_keys.is_empty() {
        return Ok(false);
    }
    let signature_bytes = decode_base64_any(signature_base64)
        .map_err(|err| AuthForgeError::Other(format!("signature_base64_decode_failed: {err:?}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| AuthForgeError::Other(format!("invalid_signature_bytes: {err}")))?;

    let payload_bytes = payload_base64.as_bytes();
    for key_b64 in public_keys {
        let public_key_bytes = match decode_base64_any(key_b64) {
            Ok(bytes) => bytes,
            Err(_) => continue
        };
        if public_key_bytes.len() != 32 {
            continue;
        }
        let key_array: [u8; 32] = match public_key_bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => continue
        };
        let verifying_key = match VerifyingKey::from_bytes(&key_array) {
            Ok(vk) => vk,
            Err(_) => continue
        };
        if verifying_key.verify(payload_bytes, &signature).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Build the canonical trust list from the two public-key fields, in order
/// of preference. Trims, splits comma-separated `public_key` strings, and
/// deduplicates while preserving order.
fn collect_public_keys(rotation_set: &[String], primary: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |raw: &str| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        if !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    };
    for key in rotation_set {
        push(key);
    }
    if primary.contains(',') {
        for segment in primary.split(',') {
            push(segment);
        }
    } else {
        push(primary);
    }
    out
}

fn is_timeout(err: &ureq::Transport) -> bool {
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    err.to_string().to_ascii_lowercase().contains("timed out")
}

fn parse_signed_response(body: String) -> Result<SignedResponse, AuthForgeError> {
    let value = serde_json::from_str::<Value>(&body)
        .map_err(|err| AuthForgeError::NetworkError(format!("invalid_json_response: {err}")))?;
    if !value.is_object() {
        return Err(AuthForgeError::NetworkError(
            "invalid_json_response: expected a JSON object".to_string()
        ));
    }
    serde_json::from_value::<SignedResponse>(value)
        .map_err(|err| AuthForgeError::NetworkError(format!("invalid_json_response: {err}")))
}

/// A failed check-in is an AuthForge verdict only when the body carries
/// `"status": "failed"` and a non-empty `error`; any other failure body is
/// the transient `unexpected_response`.
fn heartbeat_failure_error(response: &SignedResponse) -> AuthForgeError {
    let failed = response
        .status
        .as_str()
        .is_some_and(|status| status.trim().eq_ignore_ascii_case("failed"));
    match response.error.as_deref().map(str::trim) {
        Some(code) if failed && !code.is_empty() => map_server_error(&code.to_ascii_lowercase()),
        _ => AuthForgeError::Other(format!(
            "unexpected_response: status={}, error={}",
            response.status,
            Value::from(response.error.clone())
        ))
    }
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

fn read_license_file_input(path_or_text: &str) -> Result<String, OfflineLicenseError> {
    if path_or_text.trim().is_empty() {
        return Err(OfflineLicenseError::ReadError(
            "license file must be a path or the armored text".to_string()
        ));
    }
    if offline::contains_armor(path_or_text) {
        return Ok(path_or_text.to_string());
    }
    std::fs::read_to_string(path_or_text).map_err(|err| OfflineLicenseError::ReadError(err.to_string()))
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

#[cfg(test)]
thread_local! {
    static TEST_NONCE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn generate_nonce() -> String {
    #[cfg(test)]
    if let Some(v) = TEST_NONCE.with(|nonce| nonce.borrow().clone()) {
        return v;
    }
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
