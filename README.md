# AuthForge Rust SDK

Official Rust SDK for [AuthForge](https://authforge.cc) - license validation, HWID binding, signed payload verification, and background heartbeats.

## Installation

The crate is published on [crates.io/crates/authforge](https://crates.io/crates/authforge) as **`authforge`**.

From your project root:

```bash
cargo add authforge
```

Or declare a semver range in `Cargo.toml` (for example `1.0` picks up `1.0.x` patches):

```toml
[dependencies]
authforge = "1.0"
```

### Git dependency (unreleased changes)

To track the GitHub repo instead of a crates.io release:

```toml
[dependencies]
authforge = { git = "https://github.com/AuthForgeCC/authforge-rust" }
```

Optional: pin a branch or revision with `branch = "main"` or `rev = "…"`.

### Path dependency (vendored / local checkout)

Clone or submodule this repo and point at the crate directory:

```toml
[dependencies]
authforge = { path = "../authforge-rust" }
```

Adjust the path to match your layout (for example `vendor/authforge-rust`).

## Quick start

```rust
use authforge::{AuthForgeClient, AuthForgeConfig, HeartbeatMode};

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "your-app-id".into(),
        app_secret: "your-app-secret".into(),
        public_key: "your-public-key".into(),
        heartbeat_mode: HeartbeatMode::Server,
        on_failure: Some(Box::new(|err| {
            eprintln!("Auth failed: {}", err);
            std::process::exit(1);
        })),
        ..Default::default()
    });

    match client.login("XXXX-XXXX-XXXX-XXXX") {
        Ok(result) => println!("Authenticated! Expires: {}", result.expires_in),
        Err(e) => eprintln!("Login failed: {:?}", e),
    }
}
```

## Config options

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `app_id` | `String` | required | Application ID from the dashboard |
| `app_secret` | `String` | required | Application secret from the dashboard |
| `public_key` | `String` | required | App Ed25519 public key (base64) from dashboard |
| `heartbeat_mode` | `HeartbeatMode` | `Local` | `Local` or `Server` heartbeat strategy |
| `heartbeat_interval` | `u64` | `900` | Heartbeat interval in seconds (any value ≥ 1; default 15 min) |
| `api_base_url` | `String` | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Option<Box<dyn Fn(&str)+Send+Sync>>` | `None` | Callback invoked when auth fails |
| `request_timeout` | `u64` | `15` | Request timeout in seconds |
| `session_ttl_seconds` | `Option<u64>` | `None` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |
| `hwid_override` | `Option<String>` | `None` | Optional custom hardware/subject identifier. When set to `Some(non-empty)`, the SDK uses it instead of generated device fingerprint data. |

### Identity-based binding example (Telegram/Discord)

```rust
let client = AuthForgeClient::new(AuthForgeConfig {
    app_id: "YOUR_APP_ID".into(),
    app_secret: "YOUR_APP_SECRET".into(),
    public_key: "YOUR_PUBLIC_KEY".into(),
    heartbeat_mode: HeartbeatMode::Server,
    hwid_override: Some(format!("tg:{telegram_user_id}")), // or format!("discord:{discord_user_id}")
    ..Default::default()
});
```

## Billing

- **1 `login()` call = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats on the same license = 1 credit** (billed every 10th successful heartbeat).

A desktop app running 6h/day at a 15-minute interval burns ~3–4 credits/day. A server app running 24/7 at a 1-minute interval burns ~145 credits/day — pick the interval based on how fast you need revocations to propagate (they always land on the **next** heartbeat).

## Methods

- `login(&self, license_key: &str) -> Result<LoginResult, AuthForgeError>`
- `self_ban(&self, license_key: Option<&str>, session_token: Option<&str>, revoke_license: bool, blacklist_hwid: bool, blacklist_ip: bool) -> Result<(), AuthForgeError>`
- `logout(&self)`
- `is_authenticated(&self) -> bool`
- `get_session_data(&self) -> Option<serde_json::Value>`
- `get_app_variables(&self) -> Option<std::collections::HashMap<String, serde_json::Value>>`
- `get_license_variables(&self) -> Option<std::collections::HashMap<String, serde_json::Value>>`

## Heartbeat modes

- `HeartbeatMode::Server`: sends `/auth/heartbeat` requests on each interval and verifies signatures.
- `HeartbeatMode::Local`: performs local signature + expiry checks without heartbeat network calls, and fails with `SessionExpired` when the session timestamp is reached.

## Error handling

Errors are returned as `AuthForgeError`, including:

- `InvalidApp`
- `InvalidKey`
- `Expired`
- `Revoked`
- `HwidMismatch`
- `NoCredits`
- `Blocked`
- `RateLimited`
- `ReplayDetected`
- `AppDisabled`
- `SessionExpired`
- `RevokeRequiresSession`
- `BadRequest`
- `SignatureMismatch`
- `NetworkError(String)`
- `Other(String)`

Retry behavior is handled inside the internal HTTP request layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network transport failure: retry once after 2s
- retries regenerate a fresh nonce when request payload includes `nonce`

## Self-ban (tamper response)

Use `self_ban(...)` when anti-tamper checks trigger:

```rust
// Post-session (authenticated): revoke + HWID/IP blacklist.
client.self_ban(None, None, true, true, true)?;

// Pre-session: provide a license key; SDK forces revoke off client-side.
client.self_ban(Some("AF-XXXX-XXXX-XXXX"), None, true, true, true)?;

// Explicit flags:
client.self_ban(None, None, false, true, true)?;
```

`self_ban(...)` chooses request mode automatically:
- Uses post-session mode when a session token is available (`session_token` arg or current SDK session).
- Falls back to pre-session mode with `license_key` + nonce + app secret.
- In pre-session mode, revoke is always disabled client-side to avoid unsafe key revocations.

## License

MIT
