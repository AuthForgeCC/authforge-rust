# AuthForge Rust SDK

Official Rust SDK for [AuthForge](https://authforge.cc): online license activation, Ed25519 signed sessions with a grace period, HWID binding, and optional online check-ins.

## How it works

1. **Activate**: `login()` calls `POST /auth/validate` online. The server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL.
2. **Grace period** (the default): the app keeps running on the signed session without contacting AuthForge. The grace period equals the session TTL: the server default is 24h, and requested values are clamped to 1h to 7d. When it expires, the SDK marks the session unauthenticated and invokes `on_failure`.
3. **Online check-ins** (opt-in): set `online_heartbeat: true` to send periodic `POST /auth/heartbeat` requests instead. This gives you fast revocation and concurrent-use detection at the cost of network traffic and heartbeat credits.

## Features

Everything in this list ships in `src/lib.rs` today:

- **Online activation** via `POST /auth/validate`, returning a signed `LoginResult`.
- **Ed25519 signature verification** on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected. `verify_payload_signature_ed25519[_any]` is exported for standalone use.
- **Key rotation**: configure `public_key` (single key or comma-separated string) and/or `public_keys` (rotation set). The SDK trusts a signature that matches **any** configured key, so you can roll the server-side signing key without breaking deployed clients.
- **Nonce anti-replay**: a fresh nonce is sent on every request and the echoed nonce in the signed payload is checked; a mismatch returns `ReplayDetected`.
- **HWID fingerprinting**: deterministic device hash from hostname + OS + MAC, with graceful fallback.
- **`hwid_override`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `max_hwid_slots`; `hwid_count` / `max_hwid_slots` are surfaced on `LoginResult`. A shared (unlimited-seat) key skips per-device binding.
- **Grace period by default, opt-in online check-ins** (see [Grace period and online check-ins](#grace-period-and-online-check-ins)).
- **Self-ban** (`self_ban(...)`) for anti-tamper response, both pre-session and post-session.
- **Grace period duration control** (`session_ttl_seconds`) with server-side clamping to `[3600, 604800]` (1h to 7d).
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per retry.
- **Returns `Result` instead of exiting**: unlike the Python/Node/C#/C++ SDKs, the Rust SDK never exits the process; `login`/`validate_license` return `Result` and background failures are reported through `on_failure`.

## Installation

The crate is published on [crates.io/crates/authforge](https://crates.io/crates/authforge) as **`authforge`**.

From your project root:

```bash
cargo add authforge
```

Or declare a semver range in `Cargo.toml` (for example `1.1` picks up `1.1.x` patches):

```toml
[dependencies]
authforge = "1.1"
```

### Git dependency (unreleased changes)

To track the GitHub repo instead of a crates.io release:

```toml
[dependencies]
authforge = { git = "https://github.com/AuthForgeCC/authforge-rust" }
```

Optional: pin a branch or revision with `branch = "main"` or `rev = "..."`.

### Path dependency (vendored / local checkout)

Clone or submodule this repo and point at the crate directory:

```toml
[dependencies]
authforge = { path = "../authforge-rust" }
```

Adjust the path to match your layout (for example `vendor/authforge-rust`).

## Quick start

Activate online once at startup; the app then runs through the grace period with no further network calls:

```rust
use authforge::{AuthForgeClient, AuthForgeConfig};

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "your-app-id".into(),
        app_secret: "your-app-secret".into(),
        public_key: "your-public-key".into(),
        on_failure: Some(Box::new(|err| {
            eprintln!("Auth failed: {}", err);
            std::process::exit(1);
        })),
        ..Default::default()
    });

    match client.login("XXXX-XXXX-XXXX-XXXX") {
        Ok(result) => println!("Activated! Grace period seconds remaining: {}", result.expires_in),
        Err(e) => eprintln!("Activation failed: {:?}", e),
    }
}
```

To enable online check-ins instead, add `online_heartbeat: true` (and optionally tune `heartbeat_interval`).

## Config options

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `app_id` | `String` | required | Application ID from the dashboard |
| `app_secret` | `String` | required | Application secret from the dashboard |
| `public_key` | `String` | required* | App Ed25519 public key (base64) from dashboard. Accepts a comma-separated trust list. *Required unless `public_keys` is set. |
| `public_keys` | `Vec<String>` | optional | Rotation set of trusted keys. Merged ahead of `public_key`; the SDK trusts a signature matching **any** entry (see [Key rotation](#key-rotation)). |
| `online_heartbeat` | `bool` | `false` | `true` enables online check-ins (periodic `/auth/heartbeat`). `false` (default) runs through the grace period with no network calls after activation. |
| `heartbeat_mode` | `HeartbeatMode` | `Local` | **Deprecated**: see [Migrating from HeartbeatMode](#migrating-from-heartbeatmode). |
| `heartbeat_interval` | `u64` | `900` | Seconds between online check-ins or grace period checks (minimum `10`; default 15 min) |
| `api_base_url` | `String` | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Option<Box<dyn Fn(&str)+Send+Sync>>` | `None` | Callback invoked when auth fails |
| `request_timeout` | `u64` | `15` | Request timeout in seconds |
| `session_ttl_seconds` | `Option<u64>` | `None` (server default: 86400) | Requested grace period duration in seconds. Server clamps to `[3600, 604800]` (1h to 7d); preserved across check-in refreshes. |
| `hwid_override` | `Option<String>` | `None` | Optional custom hardware/subject identifier. When set to `Some(non-empty)`, the SDK uses it instead of generated device fingerprint data. |

### Identity-based binding example (Telegram/Discord)

```rust
let client = AuthForgeClient::new(AuthForgeConfig {
    app_id: "YOUR_APP_ID".into(),
    app_secret: "YOUR_APP_SECRET".into(),
    public_key: "YOUR_PUBLIC_KEY".into(),
    online_heartbeat: true,
    hwid_override: Some(format!("tg:{telegram_user_id}")), // or format!("discord:{discord_user_id}")
    ..Default::default()
});
```

### Key rotation

To rotate the server-side signing key without a flag-day, configure both the
**new** and **previous** keys; the SDK accepts a signature matching any entry:

```rust
let client = AuthForgeClient::new(AuthForgeConfig {
    app_id: "YOUR_APP_ID".into(),
    app_secret: "YOUR_APP_SECRET".into(),
    public_keys: vec!["NEW_PUBLIC_KEY".into(), "PREVIOUS_PUBLIC_KEY".into()],
    ..Default::default()
});
```

A comma-separated `public_key` (`"NEW,PREVIOUS"`) works too, for env-var convenience.

## Grace period and online check-ins

- **Grace period** (the default, no config needed): after a successful online activation, the app keeps running on the Ed25519-signed session without contacting AuthForge. On each `heartbeat_interval` the SDK confirms the session is still authenticated and that the stored expiry has not passed, failing with `Expired` once it has. (The signature was already verified at activation; the check is expiry-only and does not re-verify the cached signature.) The grace period equals the session TTL: server default 24h, clamped to 1h to 7d via `session_ttl_seconds`.
- **Online check-ins** (`online_heartbeat: true`): the SDK sends `/auth/heartbeat` on each interval, verifies the signature + nonce, and refreshes the stored session. Use this when you need fast revocation or concurrent-use detection; revocations take effect on the **next** check-in rather than at the end of the grace period.

Either way, the grace period is session continuation after one successful online activation, not persistent offline licensing. The app must reach AuthForge again once the signed session expires.

## Migrating from HeartbeatMode

`AuthForgeConfig.heartbeat_mode` and the `HeartbeatMode` enum are deprecated. The old field still works but emits deprecation warnings. If both fields are set, either one enables online check-ins: `HeartbeatMode::Server` is not overridden by `online_heartbeat: false`.

- `heartbeat_mode: HeartbeatMode::Local` maps to the default behavior (the grace period). Just remove the field:

```rust
// Before
AuthForgeConfig { heartbeat_mode: HeartbeatMode::Local, ..Default::default() }
// After
AuthForgeConfig { ..Default::default() }
```

- `heartbeat_mode: HeartbeatMode::Server` maps to online check-ins:

```rust
// Before
AuthForgeConfig { heartbeat_mode: HeartbeatMode::Server, ..Default::default() }
// After
AuthForgeConfig { online_heartbeat: true, ..Default::default() }
```

If both are set, `online_heartbeat: true` or `HeartbeatMode::Server` (either one) enables online check-ins.

## Billing

- **1 `login()` or `validate_license()` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same license = 1 credit** (billed every 10th successful check-in). The grace period makes no network calls and costs nothing after activation.

With online check-ins, a desktop app running 6h/day at a 15-minute interval burns roughly 3 to 4 credits/day. `/auth/heartbeat` is limited to 6 requests/minute per license key, so keep intervals at 10 seconds or higher and choose cadence based on revocation speed needs (revocations always land on the **next** check-in).

## Methods

- `login(&self, license_key: &str) -> Result<LoginResult, AuthForgeError>`
- `validate_license(&self, license_key: &str) -> Result<LoginResult, AuthForgeError>`: same `/auth/validate` + verification as `login`, without storing session or starting the background thread; **`on_failure` is not called** for network errors on this path
- `self_ban(&self, license_key: Option<&str>, session_token: Option<&str>, revoke_license: bool, blacklist_hwid: bool, blacklist_ip: bool) -> Result<(), AuthForgeError>`
- `logout(&self)`
- `is_authenticated(&self) -> bool`
- `get_session_data(&self) -> Option<serde_json::Value>`
- `get_app_variables(&self) -> Option<std::collections::HashMap<String, serde_json::Value>>`
- `get_license_variables(&self) -> Option<std::collections::HashMap<String, serde_json::Value>>`

## Error handling

Errors are returned as `AuthForgeError`, including:

- `InvalidApp`
- `InvalidKey`
- `Expired`
- `Revoked`
- `HwidMismatch`
- `NoCredits`
- `AppBurnCapReached`
- `Blocked`
- `RateLimited`
- `ReplayDetected`
- `AppDisabled`
- `SessionExpired`
- `RevokeRequiresSession`
- `BadRequest` (covers both `bad_request` and `malformed_request`)
- `SystemError`
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
