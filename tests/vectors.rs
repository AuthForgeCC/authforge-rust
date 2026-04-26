use authforge::{verify_payload_signature_ed25519, verify_payload_signature_ed25519_any};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVectors {
    algorithm: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    cases: Vec<TestVectorCase>,
}

#[derive(Deserialize)]
struct TestVectorCase {
    id: String,
    payload: String,
    signature: String,
    #[serde(rename = "shouldVerify")]
    should_verify: bool,
}

fn load_vectors() -> TestVectors {
    let raw = include_str!("../test_vectors.json");
    serde_json::from_str(raw).expect("valid vector json")
}

#[test]
fn vectors_use_ed25519() {
    let vectors = load_vectors();
    assert_eq!(vectors.algorithm, "ed25519");
}

#[test]
fn vector_cases_match_expected_verification_result() {
    let vectors = load_vectors();
    for vector in vectors.cases {
        let verified = verify_payload_signature_ed25519(
            &vector.payload,
            &vector.signature,
            &vectors.public_key,
        )
        .expect("verification should run");
        assert_eq!(
            verified, vector.should_verify,
            "vector case '{}' verification mismatch",
            vector.id
        );
    }
}

// During a server-side rotation a deployment can be configured with the
// previous and current keys; verification has to walk the full list.
#[test]
fn multi_key_accepts_any_match() {
    let vectors = load_vectors();
    let trust_list: Vec<String> = vec![
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        vectors.public_key.clone(),
    ];
    for vector in vectors.cases.iter().filter(|v| v.should_verify) {
        let verified =
            verify_payload_signature_ed25519_any(&vector.payload, &vector.signature, &trust_list)
                .expect("verification should run");
        assert!(verified, "multi-key verify rejected vector '{}'", vector.id);
    }
}
