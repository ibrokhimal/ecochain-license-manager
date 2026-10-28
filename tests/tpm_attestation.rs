mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ecochain_license::attestation;

#[test]
fn verifies_pinned_ak_nv_name_and_fresh_nonce() {
    let f = support::TpmFixture::new();
    let proof = f.proof(1, b"fresh-nonce");
    assert_eq!(
        attestation::verify_nv(&f.trust, &proof, b"fresh-nonce", true)
            .unwrap()
            .counter,
        1
    );
    assert!(attestation::verify_nv(&f.trust, &proof, b"another-nonce", true).is_err());
    let mut other = f.trust.clone();
    other.nv_name_hex = format!("000b{}", "cd".repeat(32));
    assert!(attestation::verify_nv(&other, &proof, b"fresh-nonce", true).is_err());
    assert!(attestation::verify_nv(&f.trust, &proof, b"fresh-nonce", false).is_err());
}

#[test]
fn malformed_signed_tpm_data_does_not_panic_or_pass() {
    let f = support::TpmFixture::new();
    let proof = f.proof(1, b"nonce");
    let raw = STANDARD.decode(&proof.attestation_b64).unwrap();
    for len in 0..raw.len() {
        assert!(
            attestation::verify_nv(&f.trust, &f.sign_proof(&raw[..len]), b"nonce", true).is_err()
        );
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(attestation::verify_nv(&f.trust, &f.sign_proof(&extra), b"nonce", true).is_err());
    let mut bad_type = raw.clone();
    bad_type[5] = 0x18;
    assert!(attestation::verify_nv(&f.trust, &f.sign_proof(&bad_type), b"nonce", true).is_err());
    let mut forged = proof;
    forged.signature_b64 = "AAAA".into();
    assert!(attestation::verify_nv(&f.trust, &forged, b"nonce", true).is_err());
}

#[test]
fn key_policy_must_match_counter_and_no_password_bypass() {
    let f = support::TpmFixture::new();
    attestation::validate_trust(&f.trust, true).unwrap();
    let mut wrong = f.trust.clone();
    wrong.activation_counter = 2;
    assert!(attestation::validate_trust(&wrong, true).is_err());
    let mut bypass = f.trust.clone();
    bypass.device_public_tpm_b64 =
        STANDARD.encode(support::public_blob(&f.device, 0x0004_0072, &f.policy));
    assert!(attestation::validate_trust(&bypass, true).is_err());
    let mut unrestricted = f.trust.clone();
    unrestricted.ak_public_tpm_b64 = STANDARD.encode(support::public_blob(&f.ak, 0x0004_0072, &[]));
    assert!(attestation::validate_trust(&unrestricted, true).is_err());
}
