use crate::{
    attestation::{self, NvProof, TrustedDevice},
    device::public_key_hash,
    error::{Error, Result},
    issuer::{self, ActivationRequest},
    license::{self, Claims, Envelope},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const CHALLENGE_DOMAIN: &[u8] = b"ECOCHAIN-TPM-CHALLENGE-V1\0";
pub const MIGRATION_WAIT: i64 = 480;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChallenge {
    pub payload_b64: String,
    pub signature_b64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema_version: u32,
    pub id: String,
    pub kind: String,
    pub license_id: String,
    pub old_revision: u64,
    pub old_digest: Option<String>,
    pub old_key_hash: Option<String>,
    pub target_key_hash: String,
    pub activation_digest: String,
    pub target_trust_digest: String,
    pub old_trust_digest: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proofs {
    pub target: NvProof,
    pub old: Option<NvProof>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub revision: u64,
    pub max_users: u32,
    pub modules: Vec<String>,
    pub expiration_date: i64,
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
fn payload(document: &SignedChallenge) -> Result<Vec<u8>> {
    if document.payload_b64.len() > 16_384 || document.signature_b64.len() > 128 {
        return Err(invalid("challenge size"));
    }
    STANDARD
        .decode(&document.payload_b64)
        .map_err(|_| Error::Signature)
}

pub fn register_trust(
    registry: &Path,
    record: &TrustedDevice,
    allow_simulator: bool,
) -> Result<String> {
    let hash = attestation::validate_trust(record, allow_simulator)?;
    let mut db = issuer::open_registry(registry)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT digest FROM trusted_devices WHERE key_hash=?1",
            [&hash],
            |r| r.get(0),
        )
        .optional()?;
    let current = digest(record)?;
    if old.as_ref().is_some_and(|old| old != &current) {
        return Err(invalid(
            "trusted record is immutable; provisioning review required",
        ));
    }
    tx.execute(
        "INSERT OR IGNORE INTO trusted_devices VALUES(?1,?2,?3)",
        params![hash, current, serde_json::to_string(record)?],
    )?;
    tx.commit()?;
    Ok(hash)
}

fn trusted(
    db: &Connection,
    hash: &str,
    expected: Option<&str>,
    allow: bool,
) -> Result<TrustedDevice> {
    let (saved, raw): (String, String) = db
        .query_row(
            "SELECT digest,record FROM trusted_devices WHERE key_hash=?1",
            [hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| invalid("TPM identity is not in vendor trust registry"))?;
    let record: TrustedDevice = serde_json::from_str(&raw)?;
    if expected.is_some_and(|v| v != saved)
        || digest(&record)? != saved
        || attestation::validate_trust(&record, allow)? != hash
    {
        return Err(invalid("trust record mismatch"));
    }
    Ok(record)
}
fn current(db: &Connection, id: &str, key_id: &str, key: &VerifyingKey) -> Result<Option<Claims>> {
    let raw: Option<String> = db
        .query_row(
            "SELECT envelope FROM issued WHERE license_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|raw| license::verify(raw.as_bytes(), key_id, key))
        .transpose()
}

#[allow(clippy::too_many_arguments)]
pub fn create_challenge(
    registry: &Path,
    kind: &str,
    license_id: &str,
    request: &ActivationRequest,
    key_id: &str,
    key: &SigningKey,
    now: i64,
    allow_simulator: bool,
) -> Result<SignedChallenge> {
    if !["enroll", "migrate"].contains(&kind)
        || !license::valid_id(license_id)
        || !(0..253_402_200_000).contains(&now)
    {
        return Err(invalid("challenge parameters"));
    }
    let activation = issuer::verify_activation(request)?;
    let target_hash = public_key_hash(&activation.server_public_key_pem)?;
    let mut db = issuer::open_registry(registry)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let target = trusted(&tx, &target_hash, None, allow_simulator)?;
    attestation::match_activation(&target, &activation, allow_simulator)?;
    let old = current(&tx, license_id, key_id, &key.verifying_key())?;
    let mut old_key_hash = None;
    let mut old_trust_digest = None;
    if let Some(old) = &old {
        if activation.organization_id != old.organization_id
            || activation.product_id != old.product_id
        {
            return Err(Error::Unauthorized);
        }
        if kind == "enroll" {
            if old.hardware_salt != activation.hardware_salt
                || old.hardware_hash != activation.hardware_hash
                || public_key_hash(&old.server_public_key_pem)? != target_hash
            {
                return Err(Error::DeviceKeyMismatch);
            }
        } else {
            let hash = public_key_hash(&old.server_public_key_pem)?;
            if hash == target_hash {
                return Err(invalid("migration target must be another key"));
            }
            let (saved_hash, trust_digest): (String, String) = tx
                .query_row(
                    "SELECT key_hash,trust_digest FROM attested_licenses WHERE license_id=?1",
                    [license_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or_else(|| invalid("old license requires attested enrollment first"))?;
            if saved_hash != hash {
                return Err(Error::DeviceKeyMismatch);
            }
            let record = trusted(&tx, &hash, Some(&trust_digest), allow_simulator)?;
            if record.environment != target.environment {
                return Err(invalid("migration cannot change trust environment"));
            }
            old_key_hash = Some(hash);
            old_trust_digest = Some(trust_digest);
        }
    } else if kind == "migrate" {
        return Err(invalid("no existing license to migrate"));
    }
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let challenge = Challenge {
        schema_version: 1,
        id: uuid::Uuid::new_v4().to_string(),
        kind: kind.into(),
        license_id: license_id.into(),
        old_revision: old.as_ref().map_or(0, |c| c.revision),
        old_digest: old.as_ref().map(license::claims_digest).transpose()?,
        old_key_hash,
        target_key_hash: target_hash,
        activation_digest: digest(request)?,
        target_trust_digest: digest(&target)?,
        old_trust_digest,
        created_at: now,
        expires_at: now + 86_400,
        nonce: hex::encode(random),
    };
    let payload = serde_json::to_vec(&challenge)?;
    let mut message = CHALLENGE_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    let document = SignedChallenge {
        payload_b64: STANDARD.encode(payload),
        signature_b64: STANDARD.encode(key.sign(&message).to_bytes()),
    };
    tx.execute(
        "INSERT INTO challenges(id,document) VALUES(?1,?2)",
        params![challenge.id, serde_json::to_string(&document)?],
    )?;
    tx.commit()?;
    Ok(document)
}

pub fn verify_challenge(document: &SignedChallenge, key: &VerifyingKey) -> Result<Challenge> {
    let payload = payload(document)?;
    let signature = STANDARD
        .decode(&document.signature_b64)
        .map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::Signature)?;
    let mut message = CHALLENGE_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    key.verify_strict(&message, &signature)
        .map_err(|_| Error::Signature)?;
    let c: Challenge = serde_json::from_slice(&payload)?;
    if c.schema_version != 1
        || !["enroll", "migrate"].contains(&c.kind.as_str())
        || c.created_at < 0
        || c.expires_at.checked_sub(c.created_at) != Some(86_400)
        || hex::decode(&c.nonce).map_or(true, |v| v.len() != 32)
    {
        return Err(invalid("invalid challenge"));
    }
    Ok(c)
}

pub fn nonce(challenge: &SignedChallenge, role: &str) -> Result<[u8; 32]> {
    if !["old", "target"].contains(&role) {
        return Err(invalid("unknown proof role"));
    }
    let mut message = b"ECOCHAIN-TPM-NV-PROOF-V1\0".to_vec();
    message.extend_from_slice(role.as_bytes());
    message.push(0);
    message.extend_from_slice(&payload(challenge)?);
    Ok(Sha256::digest(message).into())
}

#[allow(clippy::too_many_arguments)]
pub fn complete(
    registry: &Path,
    document: &SignedChallenge,
    request: &ActivationRequest,
    proofs: &Proofs,
    terms: Option<&Terms>,
    key_id: &str,
    key: &SigningKey,
    now: i64,
    allow_simulator: bool,
) -> Result<Envelope> {
    let c = verify_challenge(document, &key.verifying_key())?;
    let activation = issuer::verify_activation(request)?;
    if digest(request)? != c.activation_digest
        || public_key_hash(&activation.server_public_key_pem)? != c.target_key_hash
    {
        return Err(Error::DeviceKeyMismatch);
    }
    let mut db = issuer::open_registry(registry)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let target = trusted(
        &tx,
        &c.target_key_hash,
        Some(&c.target_trust_digest),
        allow_simulator,
    )?;
    attestation::match_activation(&target, &activation, allow_simulator)?;
    let input_digest = digest(&(document, request, proofs, terms))?;
    let (saved_document, used, result): (String, Option<String>, Option<String>) = tx
        .query_row(
            "SELECT document,used_input,result FROM challenges WHERE id=?1",
            [&c.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| invalid("unknown challenge"))?;
    if saved_document != serde_json::to_string(document)? {
        return Err(Error::Signature);
    }
    if let Some(used) = used {
        if used != input_digest {
            return Err(Error::RequestConflict);
        }
        return Ok(serde_json::from_str(
            &result.ok_or_else(|| invalid("missing completion result"))?,
        )?);
    }
    if now < c.created_at || now >= c.expires_at {
        return Err(invalid("challenge expired or not yet valid"));
    }
    let old = current(&tx, &c.license_id, key_id, &key.verifying_key())?;
    if old.as_ref().map(license::claims_digest).transpose()? != c.old_digest
        || old.as_ref().map_or(0, |v| v.revision) != c.old_revision
    {
        return Err(Error::Revision);
    }
    if attestation::verify_nv(
        &target,
        &proofs.target,
        &nonce(document, "target")?,
        allow_simulator,
    )?
    .counter
        != target.activation_counter
    {
        return Err(invalid("target TPM counter is not active"));
    }
    let mut authorized_rebind = None;
    let claims = if c.kind == "enroll" {
        if proofs.old.is_some() {
            return Err(invalid("unexpected old proof for enrollment"));
        }
        let terms = terms.ok_or_else(|| invalid("enrollment license terms required"))?;
        Claims {
            schema_version: 1,
            license_id: c.license_id.clone(),
            revision: terms.revision,
            organization_id: activation.organization_id,
            product_id: activation.product_id,
            issued_at: now,
            not_before: old
                .as_ref()
                .map_or(now, |previous| now.max(previous.not_before)),
            expiration_date: terms.expiration_date,
            allowed_modules: terms.modules.clone(),
            max_users: terms.max_users,
            hardware_profile: "dmi-v1".into(),
            hardware_salt: activation.hardware_salt,
            hardware_hash: activation.hardware_hash,
            server_public_key_pem: activation.server_public_key_pem,
            binding_mode: activation.binding_mode,
        }
    } else {
        if terms.is_some() {
            return Err(invalid("migration cannot change license terms"));
        }
        let mut old = old.ok_or_else(|| invalid("old license missing"))?;
        let old_hash = c
            .old_key_hash
            .as_deref()
            .ok_or_else(|| invalid("old identity missing"))?;
        if public_key_hash(&old.server_public_key_pem)? != old_hash
            || old.organization_id != activation.organization_id
            || old.product_id != activation.product_id
        {
            return Err(Error::DeviceKeyMismatch);
        }
        let old_trust = trusted(
            &tx,
            old_hash,
            c.old_trust_digest.as_deref(),
            allow_simulator,
        )?;
        if old_trust.environment != target.environment {
            return Err(invalid("trust downgrade"));
        }
        let old_proof = proofs
            .old
            .as_ref()
            .ok_or_else(|| invalid("deactivation proof required"))?;
        if attestation::verify_nv(
            &old_trust,
            old_proof,
            &nonce(document, "old")?,
            allow_simulator,
        )?
        .counter
            <= old_trust.activation_counter
        {
            return Err(invalid("old TPM counter has not advanced"));
        }
        authorized_rebind = c.old_digest.as_deref();
        old.revision = old.revision.checked_add(1).ok_or(Error::Revision)?;
        old.issued_at = now;
        old.not_before = now.checked_add(MIGRATION_WAIT).ok_or(Error::LicenseTime)?;
        old.hardware_salt = activation.hardware_salt;
        old.hardware_hash = activation.hardware_hash;
        old.server_public_key_pem = activation.server_public_key_pem;
        old.binding_mode = activation.binding_mode;
        old
    };
    let envelope = issuer::issue_in_transaction(&tx, &claims, key_id, key, authorized_rebind)?;
    tx.execute("INSERT INTO attested_licenses VALUES(?1,?2,?3) ON CONFLICT(license_id) DO UPDATE SET key_hash=excluded.key_hash,trust_digest=excluded.trust_digest", params![c.license_id,c.target_key_hash,c.target_trust_digest])?;
    tx.execute(
        "UPDATE challenges SET used_input=?1,result=?2 WHERE id=?3",
        params![input_digest, serde_json::to_string(&envelope)?, c.id],
    )?;
    tx.commit()?;
    Ok(envelope)
}
