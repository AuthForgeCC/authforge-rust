use authforge::verify_payload_signature_ed25519;
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
