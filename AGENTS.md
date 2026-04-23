# AuthForge SDK — AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Billing model (so you can pick sensible intervals)

- **1 `login()` = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats = 1 credit** (billed on every 10th successful heartbeat per license).
- Any `heartbeat_interval` is safe — from `1` (server apps) to `900` (15 min, desktop apps). Revocations always take effect on the **next** heartbeat regardless of interval.

## Installation

The crate is **`authforge`** on [crates.io](https://crates.io/crates/authforge). Prefer `cargo add authforge` or a semver dependency in `Cargo.toml`. For git or path dependencies, see the repository README.

## Minimal working integration

```rust
use authforge::{AuthForgeClient, AuthForgeConfig, HeartbeatMode};
use std::process;

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "YOUR_APP_ID".into(),
        app_secret: "YOUR_APP_SECRET".into(),
        heartbeat_mode: HeartbeatMode::Server,
        on_failure: Some(Box::new(|msg: &str| {
            eprintln!("AuthForge: {msg}");
            process::exit(1);
        })),
        ..Default::default()
    });

    let license_key = "XXXX-XXXX-XXXX-XXXX";
    match client.login(license_key) {
        Ok(result) => {
            eprintln!("Authenticated; expires_in={}", result.expires_in);
        }
        Err(e) => {
            eprintln!("Login failed: {e:?}");
            process::exit(1);
        }
    }

    // --- Your application code starts here ---
    run_app();
    // --- Your application code ends here ---

    client.logout();
}

fn run_app() {
    println!("Running with a valid license.");
}
```

## Constructor parameters (`AuthForgeConfig`)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app_id` | `String` | yes | empty | Application ID |
| `app_secret` | `String` | yes | empty | Application secret |
| `heartbeat_mode` | `HeartbeatMode` | yes | `Local` | `HeartbeatMode::Server` or `HeartbeatMode::Local` |
| `heartbeat_interval` | `u64` | no | `900` | Seconds between heartbeats (any value ≥ 1; `0` coerced to `900`) |
| `api_base_url` | `String` | no | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Option<Box<dyn Fn(&str) + Send + Sync>>` | no | `None` | Invoked on heartbeat/auth failure with a diagnostic string |
| `request_timeout` | `u64` | no | `15` | HTTP timeout seconds (`0` → `15`) |
| `session_ttl_seconds` | `Option<u64>` | no | `None` (server default: 86400) | Requested session token lifetime. Server clamps to `[3600, 604800]`; preserved across heartbeat refreshes. |
| `hwid_override` | `Option<String>` | no | `None` | Optional custom HWID/subject string. When set to `Some(non-empty)` (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login(&self, license_key: &str)` | `Result<LoginResult, AuthForgeError>` | Validates license and starts heartbeat |
| `logout(&self)` | `()` | Stops heartbeat and clears state |
| `is_authenticated(&self)` | `bool` | Whether authenticated |
| `get_session_data(&self)` | `Option<serde_json::Value>` | Session payload |
| `get_app_variables(&self)` | `Option<HashMap<String, Value>>` | App variables |
| `get_license_variables(&self)` | `Option<HashMap<String, Value>>` | License variables |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, session_expired, app_disabled, bad_request

(Maps to `AuthForgeError` variants and `AuthForgeError::Other(String)` for unknown strings.)

Notes:
- `rate_limited` and `replay_detected` can only be returned from `/auth/validate`. Heartbeats are not IP rate-limited and do not enforce nonce replay.

## Common patterns

### Reading license variables (feature gating)

```rust
if let Some(vars) = client.get_license_variables() {
    let _tier = vars.get("tier");
}
```

### Graceful shutdown

```rust
client.logout();
```

### Custom error handling

Handle `AuthForgeError` from `login`; heartbeat failures invoke `on_failure` with a `Debug` string of the error.

## Do NOT

- Do not hardcode the app secret as a plain string literal in source — use environment variables or encrypted config
- Do not omit `on_failure` if you need controlled shutdown — heartbeats run in a background thread and failures are reported through this callback
- Do not call `login` on every app action — call once at startup; heartbeats handle the rest
- Do not use `HeartbeatMode::Local` unless the app has no internet after initial auth
