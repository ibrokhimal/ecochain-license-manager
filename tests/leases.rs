use ecochain_license::{
    device::{Device, SoftwareDevice},
    engine::{Engine, Principal},
    error::Error,
    license::Claims,
};
use rand_core::OsRng;
use std::sync::Arc;
use tempfile::TempDir;

fn setup() -> (TempDir, Claims, Arc<dyn Device>) {
    let dir = tempfile::tempdir().unwrap();
    let device: Arc<dyn Device> = Arc::new(SoftwareDevice::new(
        p256::ecdsa::SigningKey::random(&mut OsRng),
        "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
        "BOARD-A".into(),
    ));
    let salt = "ab".repeat(32);
    let claims = Claims {
        schema_version: 1,
        license_id: "lic-1".into(),
        revision: 1,
        organization_id: "org-1".into(),
        product_id: "ecochain".into(),
        issued_at: 1_000,
        not_before: 1_000,
        expiration_date: 20_000,
        allowed_modules: vec!["inventory".into()],
        max_users: 1,
        hardware_profile: "dmi-v1".into(),
        hardware_salt: salt.clone(),
        hardware_hash: device.hardware_hash(&salt).unwrap(),
        server_public_key_pem: device.public_key_pem().unwrap(),
        binding_mode: "development".into(),
    };
    (dir, claims, device)
}
fn user(id: &str) -> Principal {
    Principal {
        organization: "org-1".into(),
        subject: id.into(),
    }
}
fn modules() -> Vec<String> {
    vec!["inventory".into()]
}

#[test]
fn distinct_users_capacity_and_exact_idempotency() {
    let (dir, claims, device) = setup();
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims,
        device,
        true,
        true,
        2_000,
    )
    .unwrap();
    let first = engine
        .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_000)
        .unwrap();
    let retry = engine
        .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_001)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&retry).unwrap()
    );
    engine
        .acquire(&user("alice"), "2000:req-a2", "mobile", &modules(), 2_001)
        .unwrap();
    assert!(matches!(
        engine.acquire(&user("bob"), "2000:req-b", "desktop", &modules(), 2_001),
        Err(Error::Limit)
    ));
    assert!(matches!(
        engine.acquire(&user("alice"), "2000:req-a", "other", &modules(), 2_001),
        Err(Error::RequestConflict)
    ));
    assert!(matches!(
        engine.acquire(&user("bob"), "2000:req-a", "desktop", &modules(), 2_001),
        Err(Error::RequestConflict)
    ));
}

#[test]
fn validate_enforces_owner_module_and_expiry_and_renewal() {
    let (dir, claims, device) = setup();
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims,
        device,
        true,
        true,
        2_000,
    )
    .unwrap();
    let token = engine
        .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_000)
        .unwrap();
    let lease = engine
        .validate(&user("alice"), &token, "inventory", 2_001)
        .unwrap();
    assert_eq!(lease.expires_at, 2_180);
    assert!(engine
        .validate(&user("bob"), &token, "inventory", 2_001)
        .is_err());
    assert!(matches!(
        engine.validate(&user("alice"), &token, "analytics", 2_001),
        Err(Error::ModuleDenied)
    ));
    assert!(engine
        .validate(&user("alice"), &token, "inventory", 2_180)
        .is_err());
    assert!(engine
        .renew(
            &user("bob"),
            "2000:renew-b",
            &lease.lease_id,
            "desktop",
            2_179
        )
        .is_err());
    assert!(engine
        .renew(
            &user("alice"),
            "2000:renew-a",
            &lease.lease_id,
            "desktop",
            2_180
        )
        .is_err());
    engine
        .acquire(&user("bob"), "2000:req-b", "desktop", &modules(), 2_180)
        .unwrap();
}

#[test]
fn restart_preserves_seats_retry_and_clock_floor() {
    let (dir, claims, device) = setup();
    let path = dir.path().join("state.db");
    let first = {
        let engine =
            Engine::open(&path, claims.clone(), device.clone(), true, true, 2_000).unwrap();
        engine
            .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_000)
            .unwrap()
    };
    let engine = Engine::open(&path, claims.clone(), device.clone(), true, false, 2_001).unwrap();
    assert!(matches!(
        engine.acquire(&user("bob"), "2000:req-b", "desktop", &modules(), 2_001),
        Err(Error::Limit)
    ));
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(
            &engine
                .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_002)
                .unwrap()
        )
        .unwrap()
    );
    assert!(matches!(
        Engine::open(&path, claims, device, true, false, 1_000),
        Err(Error::Clock)
    ));
}

#[test]
fn revision_rollback_conflict_and_module_revocation() {
    let (dir, mut claims, device) = setup();
    let path = dir.path().join("state.db");
    let old_token = {
        let engine =
            Engine::open(&path, claims.clone(), device.clone(), true, true, 2_000).unwrap();
        engine
            .acquire(&user("alice"), "2000:req-a", "desktop", &modules(), 2_000)
            .unwrap()
    };
    let old = claims.clone();
    claims.revision = 2;
    let engine = Engine::open(&path, claims.clone(), device.clone(), true, false, 2_001).unwrap();
    assert!(engine
        .validate(&user("alice"), &old_token, "inventory", 2_001)
        .is_err());
    assert!(matches!(
        Engine::open(&path, old, device.clone(), true, false, 2_002),
        Err(Error::Revision)
    ));
    claims.max_users = 2;
    assert!(matches!(
        Engine::open(&path, claims, device, true, false, 2_002),
        Err(Error::Revision)
    ));
}

#[test]
fn final_seat_is_atomic_under_concurrency() {
    let (dir, claims, device) = setup();
    let engine = Arc::new(
        Engine::open(
            &dir.path().join("state.db"),
            claims,
            device,
            true,
            true,
            2_000,
        )
        .unwrap(),
    );
    let barrier = Arc::new(std::sync::Barrier::new(12));
    let handles: Vec<_> = (0..12)
        .map(|i| {
            let e = engine.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                e.acquire(
                    &user(&format!("user-{i}")),
                    &format!("2000:req-{i}"),
                    "desktop",
                    &modules(),
                    2_000,
                )
                .is_ok()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn session_cap_unknown_module_and_expiry_bound() {
    let (dir, mut claims, device) = setup();
    claims.expiration_date = 2_050;
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims,
        device,
        true,
        true,
        2_000,
    )
    .unwrap();
    for i in 0..4 {
        let token = engine
            .acquire(
                &user("alice"),
                &format!("2000:r-{i}"),
                &format!("s-{i}"),
                &modules(),
                2_000,
            )
            .unwrap();
        assert_eq!(
            engine
                .validate(&user("alice"), &token, "inventory", 2_001)
                .unwrap()
                .expires_at,
            2_050
        );
    }
    assert!(matches!(
        engine.acquire(&user("alice"), "2000:r-5", "s-5", &modules(), 2_000),
        Err(Error::SessionLimit)
    ));
    assert!(matches!(
        engine.acquire(
            &user("alice"),
            "2000:r-6",
            "s-6",
            &["unknown".into()],
            2_000
        ),
        Err(Error::ModuleDenied)
    ));
}

#[test]
fn missing_state_is_not_implicitly_reset() {
    let (dir, claims, device) = setup();
    assert!(matches!(
        Engine::open(
            &dir.path().join("absent.db"),
            claims,
            device,
            true,
            false,
            2_000
        ),
        Err(Error::StateMissing)
    ));
}

#[test]
fn revision_upgrade_can_replace_same_session_without_extra_seat() {
    let (dir, mut claims, device) = setup();
    let path = dir.path().join("state.db");
    {
        let engine =
            Engine::open(&path, claims.clone(), device.clone(), true, true, 2_000).unwrap();
        for i in 0..4 {
            engine
                .acquire(
                    &user("alice"),
                    &format!("2000:r-{i}"),
                    &format!("s-{i}"),
                    &modules(),
                    2_000,
                )
                .unwrap();
        }
    }
    claims.revision = 2;
    let engine = Engine::open(&path, claims, device, true, false, 2_001).unwrap();
    let token = engine
        .acquire(&user("alice"), "2000:updated", "s-0", &modules(), 2_001)
        .unwrap();
    assert_eq!(
        engine
            .validate(&user("alice"), &token, "inventory", 2_001)
            .unwrap()
            .revision,
        2
    );
    assert!(matches!(
        engine.acquire(&user("bob"), "2000:bob-new", "s-0", &modules(), 2_001),
        Err(Error::Limit)
    ));
}

#[test]
fn stale_request_cannot_mint_new_lease_after_retention_pruning() {
    let (dir, claims, device) = setup();
    let path = dir.path().join("state.db");
    let engine = Engine::open(&path, claims, device, true, true, 2_000).unwrap();
    engine
        .acquire(
            &user("alice"),
            "2000:original",
            "desktop",
            &modules(),
            2_000,
        )
        .unwrap();
    engine
        .acquire(&user("bob"), "6000:new", "desktop", &modules(), 6_000)
        .unwrap();
    assert!(engine
        .acquire(
            &user("alice"),
            "2000:original",
            "desktop",
            &modules(),
            6_001
        )
        .is_err());
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM leases", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn renewal_budget_is_bounded_but_exact_retry_still_works() {
    let (dir, claims, device) = setup();
    let engine = Engine::open(
        &dir.path().join("state.db"),
        claims,
        device,
        true,
        true,
        2_000,
    )
    .unwrap();
    let first = engine
        .acquire(&user("alice"), "2000:initial", "desktop", &modules(), 2_000)
        .unwrap();
    let id = engine
        .validate(&user("alice"), &first, "inventory", 2_000)
        .unwrap()
        .lease_id;
    let mut last = first;
    for i in 1..512 {
        last = engine
            .renew(
                &user("alice"),
                &format!("2000:renew-{i}"),
                &id,
                "desktop",
                2_000,
            )
            .unwrap();
    }
    assert!(matches!(
        engine.renew(&user("alice"), "2000:over-budget", &id, "desktop", 2_000),
        Err(Error::RateLimit)
    ));
    assert_eq!(
        engine
            .renew(&user("alice"), "2000:renew-511", &id, "desktop", 2_000)
            .unwrap(),
        last
    );
}
