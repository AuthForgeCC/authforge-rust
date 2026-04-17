use authforge::{derive_heartbeat_signing_key, derive_signing_key, sign_payload};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVectors {
    validate: VectorBlock,
    heartbeat: VectorBlock
}

#[derive(Deserialize)]
struct VectorBlock {
    inputs: VectorInputs,
    outputs: VectorOutputs
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct VectorInputs {
    #[serde(default)]
    app_secret: Option<String>,
    #[serde(default)]
    sig_key: Option<String>,
    nonce: String,
    payload: String
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorOutputs {
    derived_key_hex: String,
    signature_hex: String
}

fn load_vectors() -> TestVectors {
    let raw = include_str!("../test_vectors.json");
    serde_json::from_str(raw).expect("valid vector json")
}

#[test]
fn validate_vectors_match_rust_crypto_outputs() {
    let vectors = load_vectors();
    let v = &vectors.validate;
    let app_secret = v.inputs.app_secret.as_deref().expect("validate.inputs.appSecret");

    let key = derive_signing_key(app_secret, &v.inputs.nonce);
    assert_eq!(to_hex(&key), v.outputs.derived_key_hex);

    let signature = sign_payload(&v.inputs.payload, &key).expect("hmac signature");
    assert_eq!(signature, v.outputs.signature_hex);
}

#[test]
fn heartbeat_vectors_match_rust_crypto_outputs() {
    let vectors = load_vectors();
    let h = &vectors.heartbeat;
    let sig_key = h.inputs.sig_key.as_deref().expect("heartbeat.inputs.sigKey");

    let key = derive_heartbeat_signing_key(sig_key, &h.inputs.nonce);
    assert_eq!(to_hex(&key), h.outputs.derived_key_hex);

    let signature = sign_payload(&h.inputs.payload, &key).expect("hmac signature");
    assert_eq!(signature, h.outputs.signature_hex);
}

#[test]
fn validate_and_heartbeat_keys_differ() {
    let vectors = load_vectors();
    assert_ne!(
        vectors.validate.outputs.derived_key_hex,
        vectors.heartbeat.outputs.derived_key_hex
    );
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
