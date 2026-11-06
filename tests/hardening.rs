//! Regression tests for clock rollback, request budget and device-proof caching.
use ecochain_license::{
    agent::parse_readclock,
    device::{Device, SoftwareDevice},
    engine::{Engine, Principal},
    error::{Error, Result},
    license::{Claims, ClockAnchor},
};
use rand_core::OsRng;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

/// Software key with a controllable TPM clock and a signature counter.
struct TestDevice {
    inner: SoftwareDevice,
    mode: &'static str,
    clock_ms: AtomicU64,
    has_clock: bool,
    signs: AtomicUsize,
}
impl TestDevice {
    fn new(mode: &'static str, clock_ms: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            inner: SoftwareDevice::new(
                p256::ecdsa::SigningKey::random(&mut OsRng),
                "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
                "BOARD-A".into(),
            ),
            mode,
            clock_ms: AtomicU64::new(clock_ms.unwrap_or(0)),
            has_clock: clock_ms.is_some(),
            signs: AtomicUsize::new(0),
        })
    }
}
impl Device for TestDevice {
    fn mode(&self) -> &str {
        self.mode
    }
    fn public_key_pem(&self) -> Result<String> {
        self.inner.public_key_pem()
    }
    fn hardware_hash(&self, salt: &str) -> Result<String> {
        self.inner.hardware_hash(salt)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message)
    }
    fn tpm_clock_ms(&self) -> Result<Option<u64>> {
        Ok(self.has_clock.then(|| self.clock_ms.load(Ordering::SeqCst)))
    }
}

fn claims(device: &TestDevice, anchor: Option<ClockAnchor>) -> Claims {
    let salt = "ab".repeat(32);
    Claims {
        schema_version: 1,
        license_id: "lic-1".into(),
        revision: 1,
        organization_id: "org-1".into(),
        product_id: "ecochain".into(),
        issued_at: 1_000,
        not_before: 1_000,
        expiration_date: 1_000_000,
        allowed_modules: vec!["inventory".into()],
        max_users: 1,
        hardware_profile: "dmi-v1".into(),
        hardware_salt: salt.clone(),
        hardware_hash: device.hardware_hash(&salt).unwrap(),
        server_public_key_pem: device.public_key_pem().unwrap(),
        binding_mode: device.mode.into(),
        tpm_clock_anchor: anchor,
    }
}
fn alice() -> Principal {
    Principal {
        organization: "org-1".into(),
        subject: "alice".into(),
    }
}
fn modules() -> Vec<String> {
    vec!["inventory".into()]
}

#[test]
fn old_request_timestamps_cannot_shorten_rate_limit_window() {
    let dir = tempfile::tempdir().unwrap();
    let device = TestDevice::new("development", None);
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims(&device, None),
        device.clone(),
        true,
        true,
        10_000,
    )
    .unwrap();
    let now = 10_000;
    let old = now - 3_590; // accepted, but would expire after 10 seconds
    let token = engine
        .acquire(&alice(), &format!("{old}:acq"), "desktop", &modules(), now)
        .unwrap();
    let lease: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &token.payload_b64,
        )
        .unwrap(),
    )
    .unwrap();
    let lease_id = lease["lease_id"].as_str().unwrap().to_owned();
    for i in 1..512 {
        engine
            .renew(&alice(), &format!("{old}:r{i}"), &lease_id, "desktop", now)
            .unwrap();
    }
    assert!(matches!(
        engine.renew(&alice(), &format!("{old}:over"), &lease_id, "desktop", now),
        Err(Error::RateLimit)
    ));
    // Before the fix these rows were purged at old+3600 = now+10.
    assert!(matches!(
        engine.renew(
            &alice(),
            &format!("{}:later", now + 20),
            &lease_id,
            "desktop",
            now + 20
        ),
        Err(Error::RateLimit)
    ));
}

#[test]
fn validate_and_status_reuse_cached_device_proof() {
    let dir = tempfile::tempdir().unwrap();
    let device = TestDevice::new("development", None);
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims(&device, None),
        device.clone(),
        true,
        true,
        2_000,
    )
    .unwrap();
    assert_eq!(device.signs.load(Ordering::SeqCst), 1, "startup proof");
    let token = engine
        .acquire(&alice(), "2000:a", "desktop", &modules(), 2_000)
        .unwrap();
    assert_eq!(
        device.signs.load(Ordering::SeqCst),
        2,
        "lease signature only"
    );
    for _ in 0..20 {
        engine
            .validate(&alice(), &token, "inventory", 2_001)
            .unwrap();
        engine.status(&alice(), 2_001).unwrap();
    }
    assert_eq!(device.signs.load(Ordering::SeqCst), 2, "no device calls");
    assert!(matches!(
        engine.validate(&alice(), &token, "billing", 2_001),
        Err(Error::ModuleDenied)
    ));
}

#[test]
fn tpm_clock_floor_survives_state_reset_and_clock_rollback() {
    let dir = tempfile::tempdir().unwrap();
    // 100_000 s of TPM uptime since the anchor counts as at least 85_000 s.
    let device = TestDevice::new("development", Some(100_000_000));
    let anchored = claims(
        &device,
        Some(ClockAnchor {
            unix_time: 1_000,
            clock_ms: 0,
        }),
    );
    let floor = 1_000 + 85_000;
    // Fresh state (as after deleting state.db) with the wall clock set back.
    assert!(matches!(
        Engine::open(
            &dir.path().join("reset.db"),
            anchored.clone(),
            device.clone(),
            true,
            true,
            floor - 301,
        ),
        Err(Error::Clock)
    ));
    let engine = Engine::open(
        &dir.path().join("state.db"),
        anchored,
        device.clone(),
        true,
        true,
        floor,
    )
    .unwrap();
    engine
        .acquire(
            &alice(),
            &format!("{floor}:a"),
            "desktop",
            &modules(),
            floor,
        )
        .unwrap();
}

#[test]
fn tpm_clock_floor_can_expire_license_despite_wall_clock() {
    let dir = tempfile::tempdir().unwrap();
    // Floor is far past the license expiration (1_000_000).
    let device = TestDevice::new("development", Some(2_000_000_000));
    let anchored = claims(
        &device,
        Some(ClockAnchor {
            unix_time: 1_000,
            clock_ms: 0,
        }),
    );
    assert!(Engine::open(
        &dir.path().join("state.db"),
        anchored,
        device,
        true,
        true,
        2_000,
    )
    .is_err());
}

#[test]
fn tpm_binding_requires_clock_when_anchored_and_rejects_backward_clock() {
    let dir = tempfile::tempdir().unwrap();
    let no_clock = TestDevice::new("tpm2", None);
    let anchor = Some(ClockAnchor {
        unix_time: 1_000,
        clock_ms: 0,
    });
    assert!(matches!(
        Engine::open(
            &dir.path().join("a.db"),
            claims(&no_clock, anchor),
            no_clock.clone(),
            false,
            true,
            2_000,
        ),
        Err(Error::Device(_))
    ));
    let backwards = TestDevice::new("tpm2", Some(1_000));
    assert!(matches!(
        Engine::open(
            &dir.path().join("b.db"),
            claims(
                &backwards,
                Some(ClockAnchor {
                    unix_time: 1_000,
                    clock_ms: 10_000_000,
                })
            ),
            backwards.clone(),
            false,
            true,
            2_000,
        ),
        Err(Error::Clock)
    ));
}

#[test]
fn readclock_output_parsing() {
    let output = "time: 9693\nclock_info:\n  clock: 123456\n  reset_count: 0\n  restart_count: 0\n  safe: yes\nfirmware_version: 0x1\n";
    assert_eq!(parse_readclock(output).unwrap(), 123_456);
    assert!(parse_readclock("time: 1\n").is_err());
    assert!(parse_readclock("clock: 1\nclock: 2\n").is_err());
    assert!(parse_readclock("clock: x\n").is_err());
}
