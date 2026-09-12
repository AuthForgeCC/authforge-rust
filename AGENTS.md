# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates online: it sends a license key + hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID binding, and credits, then returns an Ed25519-signed session with a TTL. By default the app then runs through the **grace period**: it keeps running on the signed session with no further network calls until the session TTL expires (server default 24h, clamped 1h to 7d). Optionally, enable **online check-ins** (`online_heartbeat: true`) to send periodic `POST /auth/heartbeat` requests for fast revocation and concurrent-use detection. When the grace period expires or a check-in fails, `on_failure` is invoked and you handle it (typically exit the app).

There is also a **separate** mode for machines that can never reach the internet: **offline license files (`.authforge`)**. The operator mints a signed file in the AuthForge cloud; `login_from_file` verifies it locally with the app public key and the machine HWID, with zero network calls. Do not ship the App Secret in those builds (leave `app_secret` empty). Only use it when the user explicitly asks for air-gapped / offline-file licensing. The default integration is always online `login` + grace period. To collect the HWID for a bound file, write an **activation request** (`.authforge-request`) with `create_activation_request`. It is not a license, is not signed, and does not mint anything. Prefer it over printing the raw HWID.

## Billing model (so you can pick sensible intervals)

- **1 `login()` or `validate_license()` = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins = 1 credit** (billed on every 10th successful check-in per license). The grace period costs nothing after activation.
- **1 offline file mint = 1 credit** (charged to the operator when the file is minted). `login_from_file` / `verify_license_file` cost nothing.
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
| `app_secret` | `String` | for online APIs | empty | Application secret. Required for `login` / `validate_license` / `self_ban`. Leave empty for `login_from_file` only; do not ship it in air-gapped binaries. |
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
| `login_from_file(&self, path_or_text: &str)` | `Result<OfflineLicense, OfflineLicenseError>` | Offline mode: verifies a `.authforge` file locally (no network), authenticates the client, never starts the background thread. Errors echoed to `on_failure` as `offline_login_failed: <code>` |
| `verify_license_file(&self, path_or_text: &str)` | `Result<OfflineLicense, OfflineLicenseError>` | Same offline checks without changing client state |
| `get_offline_license(&self)` | `Option<OfflineLicense>` | `jti`, `expires_at`, `hwid_policy`, … of the offline file in use |
| `get_session_kind(&self)` | `Option<SessionKind>` | `Some(Online)`, `Some(Offline)`, or `None` when logged out |
| `hwid(&self)` | `&str` | HWID this client sends; the customer reports it so the operator can mint a bound file |
| `create_activation_request(&self, opts)` | `String` | Unsigned `.authforge-request` for this machine. No network, no secret, callable before `login`. Hostname omitted unless `include_machine_name` |
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

### Offline license file (air-gapped machine, only when asked)

```rust
// Step 1 (customer machine): print the HWID so the operator can bind the file to it.
println!("{}", client.hwid());

// Step 2 (operator): mint the .authforge file in the dashboard or via
// POST /v1/licenses/{licenseKey}/offline-files and deliver it out-of-band.

// Step 3 (customer machine): authorize with the file. No network, no check-ins.
let lic = client.login_from_file("license.authforge").unwrap_or_else(|err| {
    // OfflineLicenseError::{BadArmor, BadSignature, UnsupportedVersion, MalformedPayload,
    //                       WrongApp, Expired, HwidMismatch, ReadError(_)}; err.code() gives the string
    eprintln!("offline license rejected: {err}");
    std::process::exit(1);
});
let _ = lic.expires_at; // None = lifetime file
```

Offline file error variants (in check order): `BadArmor`, `BadSignature`, `UnsupportedVersion`, `MalformedPayload`, `WrongApp`, `Expired`, `HwidMismatch`; `ReadError(String)` when a path cannot be read.

### Custom error handling

Handle `AuthForgeError` from `login` or `validate_license`; background check failures (grace period expiry or a failed online check-in) invoke `on_failure` with a `Debug` string of the error. `validate_license` transport failures return `Err(NetworkError)` without calling `on_failure`.

## Do NOT

- Do not hardcode the app secret as a plain string literal in source; use environment variables or encrypted config
- Do not embed the App Secret in air-gapped / `login_from_file` builds; leave `app_secret` empty (`Default` already does); verification only needs app id + public key
- Do not omit `on_failure` if you need controlled shutdown; checks run in a background thread and failures are reported through this callback
- Do not call `login` on every app action; call once at startup, the grace period (or online check-ins) handles the rest
- Do not enable `online_heartbeat` unless you need fast revocation or concurrent-use detection; the default grace period is cheaper and works without a persistent connection
- Do not treat the grace period as persistent offline licensing; it is session continuation after one successful online activation, and revocations are only picked up at the next online validate or check-in
- Do not reach for `login_from_file` unless the user explicitly needs air-gapped / offline-file licensing; the default is online `login` + grace period
- Do not expect an online revoke to disable an offline file that is already on a customer machine; the file stays valid until its own `expires_at`; prefer short expiries and HWID-bound files
- Do not mint or accept `hwid.mode: "any"` files casually; anyone who copies an unbound file has a working license
- Do not call `login_from_file` with another app's public key or app id; the file is rejected with `BadSignature` / `WrongApp` by design
- Do not try to build `.authforge` files client-side; only the AuthForge cloud holds the signing key; there is no BYO issuer
- Do not call `self_ban` or any other online method after `login_from_file`; an offline session has no server session (`get_session_kind()` is `Some(SessionKind::Offline)`), so `self_ban` returns `Err(AuthForgeError::Other("offline_session"))` without contacting the server and online check-ins never start; machines that can reach AuthForge should use online `login`
- Do not bind an offline file to an HWID reported by a different SDK or language; HWID fingerprints are not portable across SDKs, so collect the HWID from the exact SDK build that will load the file (or use the HWID override with an identifier you control)
