# AuthForge Rust SDK

Official Rust SDK for [AuthForge](https://authforge.cc) - license validation, HWID binding, signed payload verification, and background heartbeats.

## Installation

### crates.io (when published)

```toml
[dependencies]
authforge = "0.1"
```

### Git dependency

```toml
[dependencies]
authforge = { git = "https://github.com/AuthForgeCC/authforge-rust" }
```

## Quick start

```rust
use authforge::{AuthForgeClient, AuthForgeConfig, HeartbeatMode};

fn main() {
    let client = AuthForgeClient::new(AuthForgeConfig {
        app_id: "your-app-id".into(),
        app_secret: "your-app-secret".into(),
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
| `heartbeat_mode` | `HeartbeatMode` | `Local` | `Local` or `Server` heartbeat strategy |
| `heartbeat_interval` | `u64` | `900` | Heartbeat interval in seconds |
| `api_base_url` | `String` | `https://auth.authforge.cc` | API base URL |
| `on_failure` | `Option<Box<dyn Fn(&str)+Send+Sync>>` | `None` | Callback invoked when auth fails |
| `request_timeout` | `u64` | `15` | Request timeout in seconds |

## Methods

- `login(&self, license_key: &str) -> Result<LoginResult, AuthForgeError>`
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
- `BadRequest`
- `ChecksumRequired`
- `ChecksumMismatch`
- `SignatureMismatch`
- `NetworkError(String)`
- `Other(String)`

Retry behavior is handled inside the internal HTTP request layer:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network transport failure: retry once after 2s
- retries regenerate a fresh nonce when request payload includes `nonce`

## License

MIT
