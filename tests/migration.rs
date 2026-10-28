mod support;
use ecochain_license::{
    license,
    migration::{self, Proofs, Terms},
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

#[test]
fn enrollment_then_one_time_migration_waits_without_expanding_rights() {
    let old = support::TpmFixture::new();
    let new = support::TpmFixture::new();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("issuer.db");
    let key = SigningKey::generate(&mut OsRng);
    migration::register_trust(&db, &old.trust, true).unwrap();
    migration::register_trust(&db, &new.trust, true).unwrap();
    let request = old.activation();
    let challenge = migration::create_challenge(
        &db, "enroll", "lic-1", &request, "vendor-1", &key, 1000, true,
    )
    .unwrap();
    let proofs = Proofs {
        target: old.proof(1, &migration::nonce(&challenge, "target").unwrap()),
        old: None,
    };
    let terms = Terms {
        revision: 1,
        max_users: 10,
        modules: vec!["inventory".into()],
        expiration_date: 20000,
    };
    let first = migration::complete(
        &db,
        &challenge,
        &request,
        &proofs,
        Some(&terms),
        "vendor-1",
        &key,
        1001,
        true,
    )
    .unwrap();
    let repeated = migration::complete(
        &db,
        &challenge,
        &request,
        &proofs,
        Some(&terms),
        "vendor-1",
        &key,
        1002,
        true,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    let next = new.activation();
    let migration =
        migration::create_challenge(&db, "migrate", "lic-1", &next, "vendor-1", &key, 1100, true)
            .unwrap();
    let proof = Proofs {
        target: new.proof(1, &migration::nonce(&migration, "target").unwrap()),
        old: Some(old.proof(2, &migration::nonce(&migration, "old").unwrap())),
    };
    let issued = migration::complete(
        &db, &migration, &next, &proof, None, "vendor-1", &key, 1101, true,
    )
    .unwrap();
    let claims = license::verify(
        &serde_json::to_vec(&issued).unwrap(),
        "vendor-1",
        &key.verifying_key(),
    )
    .unwrap();
    assert_eq!(claims.revision, 2);
    assert_eq!(claims.not_before, 1581);
    assert_eq!(claims.max_users, 10);
    assert_eq!(claims.allowed_modules, ["inventory"]);
    assert_eq!(claims.expiration_date, 20000);
    assert_eq!(claims.server_public_key_pem, new.public_pem());
    assert_eq!(claims.binding_mode, "development");
    // Replay cannot switch the target or proof; exact retry only retrieves the same result.
    assert!(migration::complete(
        &db, &migration, &request, &proof, None, "vendor-1", &key, 1102, true
    )
    .is_err());
    assert!(migration::complete(
        &db, &migration, &next, &proof, None, "vendor-1", &key, 1102, false
    )
    .is_err());
    let renewal =
        migration::create_challenge(&db, "enroll", "lic-1", &next, "vendor-1", &key, 1102, true)
            .unwrap();
    let renewed_proofs = Proofs {
        target: new.proof(1, &migration::nonce(&renewal, "target").unwrap()),
        old: None,
    };
    let renewed_terms = Terms {
        revision: 3,
        max_users: 10,
        modules: vec!["inventory".into()],
        expiration_date: 20000,
    };
    let renewed = migration::complete(
        &db,
        &renewal,
        &next,
        &renewed_proofs,
        Some(&renewed_terms),
        "vendor-1",
        &key,
        1103,
        true,
    )
    .unwrap();
    let renewed = license::verify(
        &serde_json::to_vec(&renewed).unwrap(),
        "vendor-1",
        &key.verifying_key(),
    )
    .unwrap();
    assert_eq!(
        renewed.not_before, 1581,
        "renewal must preserve migration wait"
    );
}

#[test]
fn rejects_missing_trust_inactive_counter_expiry_and_stale_migration() {
    let old = support::TpmFixture::new();
    let new = support::TpmFixture::new();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("issuer.db");
    let key = SigningKey::generate(&mut OsRng);
    let request = old.activation();
    assert!(
        migration::create_challenge(&db, "enroll", "lic-1", &request, "v1", &key, 1000, true)
            .is_err()
    );
    migration::register_trust(&db, &old.trust, true).unwrap();
    migration::register_trust(&db, &new.trust, true).unwrap();
    let challenge =
        migration::create_challenge(&db, "enroll", "lic-1", &request, "v1", &key, 1000, true)
            .unwrap();
    let mut proofs = Proofs {
        target: old.proof(2, &migration::nonce(&challenge, "target").unwrap()),
        old: None,
    };
    let terms = Terms {
        revision: 1,
        max_users: 1,
        modules: vec!["inventory".into()],
        expiration_date: 200000,
    };
    assert!(migration::complete(
        &db,
        &challenge,
        &request,
        &proofs,
        Some(&terms),
        "v1",
        &key,
        1001,
        true
    )
    .is_err());
    proofs.target = old.proof(1, &migration::nonce(&challenge, "target").unwrap());
    assert!(migration::complete(
        &db,
        &challenge,
        &request,
        &proofs,
        Some(&terms),
        "v1",
        &key,
        87400,
        true
    )
    .is_err());
    migration::complete(
        &db,
        &challenge,
        &request,
        &proofs,
        Some(&terms),
        "v1",
        &key,
        1001,
        true,
    )
    .unwrap();
    let target = new.activation();
    let a = migration::create_challenge(&db, "migrate", "lic-1", &target, "v1", &key, 1100, true)
        .unwrap();
    let b = migration::create_challenge(&db, "migrate", "lic-1", &target, "v1", &key, 1100, true)
        .unwrap();
    let make_proof = |c| Proofs {
        target: new.proof(1, &migration::nonce(c, "target").unwrap()),
        old: Some(old.proof(1, &migration::nonce(c, "old").unwrap())),
    };
    assert!(migration::complete(
        &db,
        &a,
        &target,
        &make_proof(&a),
        None,
        "v1",
        &key,
        1101,
        true
    )
    .is_err());
    let mut good = make_proof(&a);
    good.old = Some(old.proof(2, &migration::nonce(&a, "old").unwrap()));
    migration::complete(&db, &a, &target, &good, None, "v1", &key, 1101, true).unwrap();
    let mut stale = make_proof(&b);
    stale.old = Some(old.proof(2, &migration::nonce(&b, "old").unwrap()));
    assert!(migration::complete(&db, &b, &target, &stale, None, "v1", &key, 1102, true).is_err());
}

#[test]
fn competing_migrations_commit_once_and_other_reports_stale_revision() {
    let old = support::TpmFixture::new();
    let target = support::TpmFixture::new();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("issuer.db");
    let key = SigningKey::generate(&mut OsRng);
    migration::register_trust(&db, &old.trust, true).unwrap();
    migration::register_trust(&db, &target.trust, true).unwrap();
    let request = old.activation();
    let enroll =
        migration::create_challenge(&db, "enroll", "race", &request, "v1", &key, 1000, true)
            .unwrap();
    let proofs = Proofs {
        target: old.proof(1, &migration::nonce(&enroll, "target").unwrap()),
        old: None,
    };
    let terms = Terms {
        revision: 1,
        max_users: 2,
        modules: vec!["inventory".into()],
        expiration_date: 20000,
    };
    migration::complete(
        &db,
        &enroll,
        &request,
        &proofs,
        Some(&terms),
        "v1",
        &key,
        1001,
        true,
    )
    .unwrap();
    let request = target.activation();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = vec![];
    for _ in 0..2 {
        let c =
            migration::create_challenge(&db, "migrate", "race", &request, "v1", &key, 1100, true)
                .unwrap();
        let p = Proofs {
            target: target.proof(1, &migration::nonce(&c, "target").unwrap()),
            old: Some(old.proof(2, &migration::nonce(&c, "old").unwrap())),
        };
        let db = db.clone();
        let request = request.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            migration::complete(&db, &c, &request, &p, None, "v1", &key, 1101, true)
        }));
    }
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(ecochain_license::error::Error::Revision)))
            .count(),
        1
    );
}
