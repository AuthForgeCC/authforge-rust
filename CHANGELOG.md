# Changelog

## 1.4.0

### Behavior changes for callers

- **Typed errors**: `AuthForgeError` gains `code()`, `is_transient()` and `is_fatal()`, implements `Display` and `std::error::Error`, and the crate exports `is_transient_error_code(code)` and `DEFINITIVE_ERROR_CODES`.
- **`on_heartbeat_failure`**: new `AuthForgeConfig` field that receives background check failures as `&AuthForgeError`. When set, it replaces `on_failure` for background checks.
- **Classification**: only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and `signature_mismatch` are definitive. Everything else is transient, including unknown codes, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_N` and unparseable responses.
- **Transient failures keep checking in**: previously the background thread stopped on any failure and set `authenticated = false`. Now the session is kept and the next check runs at the next interval. A transient failure after the session TTL has passed is reported as `SessionExpired` (definitive).
- **Definitive failures clear the session** (as `logout()` does) before the callback runs, so `is_authenticated()` is already `false` inside it.
- **Grace period expiry** now reports `SessionExpired` instead of `Expired`.
- **`malformed_request`** now surfaces as `Other("malformed_request")` instead of `BadRequest`, so `code()` keeps the server's name.
- **Legacy `on_failure`** now receives the `Display` form (`"revoked"`, `"network_error: ..."`) instead of the `Debug` form (`"Revoked"`).
- **`unexpected_response`**: a failed check-in counts as a server verdict only if its body is a JSON object with `"status": "failed"` and a non-empty `error`. Any other failure body is reported as the transient `Other("unexpected_response: status=..., error=...")`.
- **Rate-limit retry**: only `rate_limited`, or a 429 without an error code, is retried (after 2s, then 5s). A 429 carrying `no_credits`, `demo_quota_exceeded` or `app_burn_cap_reached` is no longer retried.
- **Check-in network failures** are reported once, through the background failure callback; they no longer also fire `on_failure("network_error")`. Timeouts are reported as `NetworkError("timeout: ...")` (`code()` is `"timeout"`).
- **Session replacement**: a check-in still in flight when `logout()` or a new `login()` runs no longer writes its result to the new session.
