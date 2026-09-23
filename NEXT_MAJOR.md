# Next major release

Breaking changes deferred to the next major version. The SDKs version in lockstep on major.minor, so these ship in the same release as the other SDKs' deferred changes. When one lands, move it to `CHANGELOG.md` and delete it here.

## Report local session expiry as `SessionExpired`

- **Now (1.4.x):** when the grace period ends, or a transient check-in failure happens after the session TTL has passed, the background failure is `AuthForgeError::Expired` (`code()` is `"expired"`). The other SDKs report both as `session_expired`.
- **Planned:** report `AuthForgeError::SessionExpired`, so `Expired` only means the server's license-expired verdict.
- **Why deferred:** callers that match `AuthForgeError::Expired` to detect the end of the grace period would silently stop matching.
- **Touches:** `grace_period_check` and the TTL promotion in `heartbeat_tick` (`src/lib.rs`), the tests `grace_period_expiry_is_expired` and `transient_failure_after_ttl_becomes_expired`, `README.md`, `AGENTS.md`, and in AuthForgeDocs `sdk/rust.mdx` plus the "Rust reports `expired`" notes in `sdk/overview.mdx`, `sdk/best-practices.mdx`, `api/errors.mdx` and both `llms-full.txt` copies.

## Mark `AuthForgeError` `#[non_exhaustive]`

- **Now (1.4.x):** the enum is exhaustive, so callers can `match` it without a wildcard arm, and adding a variant is a breaking change. New server codes arrive as `Other(String)`.
- **Planned:** add `#[non_exhaustive]` so later minor releases can give new server codes their own variants.
- **Why deferred:** every exhaustive `match` on `AuthForgeError` in downstream code needs a `_ =>` arm to compile.
- **Touches:** the `AuthForgeError` definition in `src/lib.rs`, `README.md` (error handling section), AuthForgeDocs `sdk/rust.mdx` (error enum reference).

## Give `malformed_request` its own variant

- **Now (1.4.x):** `malformed_request` is `Other("malformed_request")` (definitive, `code()` is `"malformed_request"`). In 1.3.x it was `BadRequest`, which also carries the server's `bad_request`. `bad_request` is transient and `malformed_request` is definitive, so one unit variant can't hold both.
- **Planned:** add `AuthForgeError::MalformedRequest` (definitive, `code()` `"malformed_request"`) and map `malformed_request` to it. `BadRequest` stays `bad_request` only.
- **Why deferred:** adding a variant to the exhaustive enum breaks downstream exhaustive `match`es. Land it together with `#[non_exhaustive]`.
- **Touches:** `AuthForgeError`, `code()`, `map_server_error` and the `malformed_request_keeps_its_code` test in `src/lib.rs`, the error lists in `README.md` / `AGENTS.md`, the "Known differences from 1.3.x" note in `CHANGELOG.md`, AuthForgeDocs `sdk/rust.mdx`.

## Legacy `on_failure` receives the `Display` form

- **Now (1.4.x):** without `on_heartbeat_failure`, background check failures reach `on_failure` as the error's `Debug` string (`"Revoked"`, `"NetworkError(\"...\")"`), as in 1.3.x.
- **Planned:** pass the `Display` form (`"revoked"`, `"network_error: ..."`), which is the stable machine-readable code the other SDKs use.
- **Why deferred:** callers comparing the string (`msg == "Revoked"`) would stop matching.
- **Touches:** the `on_failure` call in `heartbeat_tick` and the `legacy_on_failure_receives_the_debug_form` test in `src/lib.rs`, the `on_failure` rows in `README.md` / `AGENTS.md`, AuthForgeDocs `sdk/rust.mdx` and the Rust row in `sdk/best-practices.mdx`, both `llms-full.txt` copies.
