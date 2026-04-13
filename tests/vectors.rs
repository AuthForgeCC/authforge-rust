use authforge::{derive_signing_key, sign_payload};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVectors {
    inputs: VectorInputs,
    outputs: VectorOutputs
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorInputs {
    app_secret: String,
    nonce: String,
    payload: String
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorOutputs {
    derived_key_hex: String,
    signature_hex: String
}

#[test]
fn python_vector_matches_rust_crypto_outputs() {
    let vectors = include_str!("../../AuthForge-PythonSDK/test_vectors.json");
    let parsed: TestVectors = serde_json::from_str(vectors).expect("valid vector json");

    let key = derive_signing_key(&parsed.inputs.app_secret, &parsed.inputs.nonce);
    let key_hex = to_hex(&key);
    assert_eq!(key_hex, parsed.outputs.derived_key_hex);

    let signature = sign_payload(&parsed.inputs.payload, &key).expect("hmac signature");
    assert_eq!(signature, parsed.outputs.signature_hex);
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
