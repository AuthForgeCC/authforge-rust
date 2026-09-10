# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates online: it sends a license key + hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the **grace period**: it keeps running on the signed session with no further network calls until the session TTL expires (server default 24h, clamped 1h to 7d). Optionally, enable **online check-ins** (`online_heartbeat: true`) to send periodic `POST /auth/heartbeat` requests for fast revocation and concurrent-use detection. When the grace period expires or a check-in fails, `on_failure` is invoked and you handle it (typically exit the app).

## Billing model (so you can pick sensible intervals)

- **1 `login()` or `validate_license()` = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins = 1 credit** (billed on every 10th successful check-in per license). The grace period costs nothing after activation.
- Keep `heartbeat_interval` at `>= 10` seconds (`900` / 15 min is the common desktop default). `/auth/heartbeat` is limited to 6 requests/minute per license key, and revocations take effect on the **next** check-in.

## Installation

The crate is **`authforge`** on [crates.io](https://crates.io/crates/authforge). Prefer `cargo add authforge` or a semver dependency in `Cargo.toml`. For git or path dependencies, see the repository README.

## Minimal working integration

Activate online once at startup; the default grace period handles the rest with no network calls:

```rust
use authforge::{AuthForgeClient, AuthForgeConfig};
use std::process;

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "YOUR_APP_ID".into(),
        app_secret: "YOUR_APP_SECRET".into(),
        public_key: "YOUR_PUBLIC_KEY".into(), // required: base64 Ed25519 key from the dashboard
        on_failure: Some(Box::new(|msg: &str| {
            eprintln!("AuthForge: {msg}");
            process::exit(1);
        })),
        ..Default::default()
    });

    let license_key = "XXXX-XXXX-XXXX-XXXX";
    match client.login(license_key) {
        Ok(result) => {
            eprintln!("Activated; grace period seconds remaining={}", result.expires_in);
        }
        Err(e) => {
            eprintln!("Activation failed: {e:?}");
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

To enable online check-ins, add `online_heartbeat: true` (and optionally set `heartbeat_interval`).

## Constructor parameters (`AuthForgeConfig`)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app_id` | `String` | yes | empty | Application ID |
| `app_secret` | `String` | yes | empty | Application secret |
| `public_key` | `String` | yes* | empty | Base64 Ed25519 public key from the dashboard. Accepts a comma-separated trust list. *Required unless `public_keys` is set; with neither, `login` returns `InvalidApp` |
| `public_keys` | `Vec<String>` | no | empty | Rotation set; merged ahead of `public_key`. The SDK trusts a signature matching **any** entry |
| `online_heartbeat` | `bool` | no | `false` | `true` enables online check-ins (periodic `/auth/heartbeat`). `false` (default) runs through the grace period with no network after activation |
| `heartbeat_mode` | `HeartbeatMode` | no | `Local` | **Deprecated**: see [Migrating from HeartbeatMode](#migrating-from-heartbeatmode) |
| `heartbeat_interval` | `u64` | no | `900` | Seconds between online check-ins or grace period checks (minimum `10`; `0` coerced to `900`) |
| `api_base_url` | `String` | no | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Option<Box<dyn Fn(&str) + Send + Sync>>` | no | `None` | Invoked on background check failure (and `login` network failure after retry); **not** invoked for `validate_license` network errors |
| `request_timeout` | `u64` | no | `15` | HTTP timeout seconds (`0` coerced to `15`) |
| `session_ttl_seconds` | `Option<u64>` | no | `None` (server default: 86400) | Requested grace period duration in seconds. Server clamps to `[3600, 604800]` (1h to 7d); preserved across check-in refreshes. |
| `hwid_override` | `Option<String>` | no | `None` | Optional custom HWID/subject string. When set to `Some(non-empty)` (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from HeartbeatMode

`heartbeat_mode` and the `HeartbeatMode` enum are `#[deprecated]`. The old field still works, but new code should use `online_heartbeat`:

- `HeartbeatMode::Local` maps to the default (the grace period): remove the field entirely.
- `HeartbeatMode::Server` maps to `online_heartbeat: true`.
- If both are set, either `online_heartbeat: true` or `HeartbeatMode::Server` enables online check-ins.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login(&self, license_key: &str)` | `Result<LoginResult, AuthForgeError>` | Activates online and starts the background check thread |
| `validate_license(&self, license_key: &str)` | `Result<LoginResult, AuthForgeError>` | Same validate + signatures; no session/background thread; no `on_failure` on transport failure |
| `logout(&self)` | `()` | Stops background checks and clears state |
| `is_authenticated(&self)` | `bool` | Whether authenticated |
| `get_session_data(&self)` | `Option<serde_json::Value>` | Session payload |
| `get_app_variables(&self)` | `Option<HashMap<String, Value>>` | App variables |
| `get_license_variables(&self)` | `Option<HashMap<String, Value>>` | License variables |

## Error codes the server can return

Full set: invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error

(Maps to `AuthForgeError` variants; `bad_request`/`malformed_request` both map to `BadRequest`, and unknown strings map to `AuthForgeError::Other(String)`.)

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).

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

Handle `AuthForgeError` from `login` or `validate_license`; background check failures (grace period expiry or a failed online check-in) invoke `on_failure` with a `Debug` string of the error. `validate_license` transport failures return `Err(NetworkError)` without calling `on_failure`.

## Do NOT

- Do not hardcode the app secret as a plain string literal in source; use environment variables or encrypted config
- Do not omit `on_failure` if you need controlled shutdown; checks run in a background thread and failures are reported through this callback
- Do not call `login` on every app action; call once at startup, the grace period (or online check-ins) handles the rest
- Do not enable `online_heartbeat` unless you need fast revocation or concurrent-use detection; the default grace period is cheaper and works without a persistent connection
