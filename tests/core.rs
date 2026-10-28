use ecochain_license::{
    device::{fingerprint, Device, SoftwareDevice},
    error::Error,
    license::{self, Claims},
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn fixture() -> (SigningKey, SoftwareDevice, Claims) {
    let vendor = SigningKey::generate(&mut OsRng);
    let device = SoftwareDevice::new(
        p256::ecdsa::SigningKey::random(&mut OsRng),
        "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
        "BOARD-A".into(),
    );
    let salt = "ab".repeat(32);
    let claims = Claims {
        schema_version: 1,
        license_id: "lic-1".into(),
        revision: 1,
        organization_id: "org-1".into(),
        product_id: "ecochain".into(),
        issued_at: 1_000,
        not_before: 1_000,
        expiration_date: 10_000,
        allowed_modules: vec!["inventory".into()],
        max_users: 1,
        hardware_profile: "dmi-v1".into(),
        hardware_salt: salt.clone(),
        hardware_hash: device.hardware_hash(&salt).unwrap(),
        server_public_key_pem: device.public_key_pem().unwrap(),
        binding_mode: "development".into(),
    };
    (vendor, device, claims)
}

#[test]
fn valid_license_roundtrip_and_exact_expiration() {
    let (key, device, claims) = fixture();
    let envelope = license::issue(&claims, "vendor-1", &key).unwrap();
    let decoded = license::verify(
        &serde_json::to_vec(&envelope).unwrap(),
        "vendor-1",
        &key.verifying_key(),
    )
    .unwrap();
    assert_eq!(decoded.organization_id, "org-1");
    license::check_binding(&decoded, &device, true, "org-1", "ecochain", 9_999).unwrap();
    assert!(matches!(
        license::check_binding(&decoded, &device, true, "org-1", "ecochain", 10_000),
        Err(Error::LicenseTime)
    ));
}

#[test]
fn payload_and_key_id_tampering_are_rejected() {
    let (key, _, claims) = fixture();
    let mut envelope = license::issue(&claims, "vendor-1", &key).unwrap();
    envelope.payload_b64 = "e30=".into();
    assert!(license::verify(
        &serde_json::to_vec(&envelope).unwrap(),
        "vendor-1",
        &key.verifying_key()
    )
    .is_err());
    let mut envelope = license::issue(&claims, "vendor-1", &key).unwrap();
    envelope.key_id = "attacker".into();
    assert!(license::verify(
        &serde_json::to_vec(&envelope).unwrap(),
        "vendor-1",
        &key.verifying_key()
    )
    .is_err());
}

#[test]
fn copied_license_fails_on_other_hardware_or_key() {
    let (_, _, claims) = fixture();
    let other = SoftwareDevice::new(
        p256::ecdsa::SigningKey::random(&mut OsRng),
        "aaba4679-b41d-46a8-b8af-4fa855843212".into(),
        "BOARD-B".into(),
    );
    assert!(license::check_binding(&claims, &other, true, "org-1", "ecochain", 2_000).is_err());
    let same_hardware = SoftwareDevice::new(
        p256::ecdsa::SigningKey::random(&mut OsRng),
        "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
        "BOARD-A".into(),
    );
    assert!(matches!(
        license::check_binding(&claims, &same_hardware, true, "org-1", "ecochain", 2_000),
        Err(Error::DeviceKeyMismatch)
    ));
}

#[test]
fn production_refuses_software_key_and_wrong_tenant() {
    let (_, device, claims) = fixture();
    assert!(matches!(
        license::check_binding(&claims, &device, false, "org-1", "ecochain", 2_000),
        Err(Error::DevelopmentForbidden)
    ));
    assert!(license::check_binding(&claims, &device, true, "org-2", "ecochain", 2_000).is_err());
}

#[test]
fn fingerprints_normalize_and_reject_missing_hardware() {
    let salt = "ab".repeat(32);
    assert_eq!(
        fingerprint("AABA4679-B41D-46A8-B8AF-4FA855843211", " BOARD-A ", &salt).unwrap(),
        fingerprint("aaba4679-b41d-46a8-b8af-4fa855843211", "board-a", &salt).unwrap()
    );
    assert!(fingerprint("00000000-0000-0000-0000-000000000000", "BOARD-A", &salt).is_err());
    assert!(fingerprint(
        "aaba4679-b41d-46a8-b8af-4fa855843211",
        "To Be Filled By O.E.M.",
        &salt
    )
    .is_err());
}

#[test]
fn issuer_registry_refuses_second_server_and_revision_conflict() {
    let (key, _, mut claims) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("issuer.db");
    ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).unwrap();
    // Exact retry is allowed, a second binding is not.
    ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).unwrap();
    claims.hardware_hash = "cd".repeat(32);
    claims.revision = 2;
    assert!(
        ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).is_err()
    );
    claims.hardware_hash = fixture().2.hardware_hash;
    claims.revision = 1;
    claims.max_users = 2;
    assert!(
        ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).is_err()
    );
}

#[test]
fn enrollment_request_requires_device_proof_and_preserves_binding() {
    let (_, device, _) = fixture();
    let request = ecochain_license::issuer::enroll(&device, "org-1", "ecochain").unwrap();
    let binding = ecochain_license::issuer::verify_activation(&request).unwrap();
    assert_eq!(binding.organization_id, "org-1");
    assert_eq!(
        binding.hardware_hash,
        device.hardware_hash(&binding.hardware_salt).unwrap()
    );
    let mut tampered = request;
    tampered.signature_b64 = "AAAA".into();
    assert!(ecochain_license::issuer::verify_activation(&tampered).is_err());
}

#[test]
fn issuer_binding_fields_cannot_collide_through_delimiters() {
    let (key, _, mut claims) = fixture();
    claims.organization_id = "org".into();
    claims.product_id = "branch:ecochain".into();
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("issuer.db");
    ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).unwrap();
    claims.organization_id = "org:branch".into();
    claims.product_id = "ecochain".into();
    claims.revision = 2;
    assert!(
        ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).is_err()
    );
}

#[test]
fn normal_reissue_cannot_shorten_a_pending_activation_window() {
    let (key, _, mut claims) = fixture();
    claims.not_before = 5000;
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("issuer.db");
    ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).unwrap();
    claims.revision = 2;
    claims.issued_at = 2000;
    claims.not_before = 2000;
    assert!(
        ecochain_license::issuer::issue_registered(&registry, &claims, "vendor-1", &key).is_err()
    );
}
