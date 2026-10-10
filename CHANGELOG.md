# Changelog

## 1.5.0

### Features

- **Self-serve offline activation**: `AuthForgeClient::activate_offline(&self, license_key: &str, path: Option<&Path>) -> Result<(), AuthForgeError>` calls `POST /auth/offline/activate` once and turns a license key into a lifetime, HWID-bound `.authforge` file. The SDK verifies the file with the configured public key(s), app id and local HWID before writing it, writes it atomically to `path` (temp file + rename, parent directories created), and starts an offline session exactly as `login_from_file` does (no background thread). Needs the app secret, unlike air-gapped files. A new machine costs the app owner 2 credits; the same machine re-activating gets the identical file back for free. Refunds and revokes cannot reach files already issued.
- Fails fast without a request: `InvalidKey` for an empty key, then `InvalidApp` when the app secret, app id or public key is missing. Uses the same HWID, nonce generator and retry policy as `login()`. Errors are only returned, never sent to `on_failure`; on error nothing is written to `path` and the session state is unchanged.
- New definitive codes in `DEFINITIVE_ERROR_CODES`: the server's `offline_activation_disabled`, `offline_activation_requires_perpetual`, `offline_activation_requires_seats`, `offline_activation_limit_reached`, and the SDK's `offline_file_rejected` (the returned file failed local verification; the verifier's reason is in the message, e.g. `offline_file_rejected: bad_signature`). They arrive as `AuthForgeError::Other(code)`, as `AuthForgeError` is still exhaustive (see `NEXT_MAJOR.md`). A success response without a file is the transient `unexpected_response`; a failed write to `path` is the transient `file_write_failed`.
- Conformance tests against the shared `self_serve_activation_vectors.json`.

## 1.4.1

### Fixes

- **Transient failures are no longer silent without a callback.** With neither `on_heartbeat_failure` nor `on_failure` set, a transient background check failure now writes one line to stderr, `AuthForge: background check failed (<code>); retrying next interval`, and checks in again on the next interval as before. Definitive failures, including the TTL-promoted `Expired`, still clear the session and stop background checks without output; the Rust SDK still never exits the process.

### Docs

- The README and `AGENTS.md` examples no longer call `std::process::exit(1)` from the failure callback. The callback sends on an `mpsc` channel that the main thread receives from, so it can save work and exit; exiting from the callback is kept as a last resort after saving.

## 1.4.0

### Behavior changes for callers

- **Typed errors**: `AuthForgeError` gains `code()`, `is_transient()` and `is_fatal()`, implements `Display` and `std::error::Error`, and the crate exports `is_transient_error_code(code)` and `DEFINITIVE_ERROR_CODES`.
- **`on_heartbeat_failure`**: new `AuthForgeConfig` field that receives background check failures as `&AuthForgeError`. When set, it replaces `on_failure` for background checks.
- **Classification**: only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and `signature_mismatch` are definitive. Everything else is transient, including unknown codes, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_N` and unparseable responses.
- **Transient failures keep checking in**: previously the background thread stopped on any failure and set `authenticated = false`. Now the session is kept and the next check runs at the next interval. A transient failure after the session TTL has passed is reported as `Expired` (definitive).
- **Definitive failures clear the session** (as `logout()` does) before the callback runs, so `is_authenticated()` is already `false` inside it.
- **Grace period expiry** still reports `Expired`, unchanged from 1.3.x. The other SDKs report local expiry as `session_expired`. Rust keeps `Expired` so that 1.4 doesn't break `match` arms; the switch to `SessionExpired` is deferred to the next major (see `NEXT_MAJOR.md`).
- **Legacy `on_failure`** still receives the `Debug` form of background check failures (`"Revoked"`, `"NetworkError(\"...\")"`), unchanged from 1.3.x. Use `on_heartbeat_failure` for the typed error. Switching to the `Display` form is deferred to the next major (see `NEXT_MAJOR.md`).
- **`unexpected_response`**: a failed check-in counts as a server verdict only if its body is a JSON object with `"status": "failed"` and a non-empty `error`. Any other failure body is reported as the transient `Other("unexpected_response: status=..., error=...")`.
- **Rate-limit retry**: only `rate_limited`, or a 429 without an error code, is retried (after 2s, then 5s). A 429 carrying `no_credits`, `demo_quota_exceeded` or `app_burn_cap_reached` is no longer retried.
- **Check-in network failures** are reported once, through the background failure callback; they no longer also fire `on_failure("network_error")`. Timeouts are reported as `NetworkError("timeout: ...")` (`code()` is `"timeout"`).
- **Session replacement**: a check-in still in flight when `logout()` or a new `login()` runs no longer writes its result to the new session.

### Known differences from 1.3.x

- **`malformed_request`** is now `Other("malformed_request")` instead of `BadRequest`, so `matches!(err, AuthForgeError::BadRequest)` no longer catches it. `BadRequest` also carries the server's `bad_request`, which is transient, so it can't also stand for the definitive `malformed_request`. A dedicated variant is planned for the next major (see `NEXT_MAJOR.md`).
