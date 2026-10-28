use crate::{
    device::public_key_hash,
    error::{Error, Result},
    license::{self, Claims, Envelope},
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
pub const ACTIVATION_DOMAIN: &[u8] = b"ECOCHAIN-ACTIVATION-V1\0";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationClaims {
    pub organization_id: String,
    pub product_id: String,
    pub hardware_salt: String,
    pub hardware_hash: String,
    pub server_public_key_pem: String,
    pub binding_mode: String,
    pub nonce: String,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub payload_b64: String,
    pub signature_b64: String,
}
pub fn enroll(
    device: &dyn crate::device::Device,
    organization: &str,
    product: &str,
) -> Result<ActivationRequest> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use rand_core::{OsRng, RngCore};
    if !license::valid_id(organization) || !license::valid_id(product) {
        return Err(Error::Invalid("invalid organization/product".into()));
    }
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let salt = hex::encode(salt);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let claims = ActivationClaims {
        organization_id: organization.into(),
        product_id: product.into(),
        hardware_salt: salt.clone(),
        hardware_hash: device.hardware_hash(&salt)?,
        server_public_key_pem: device.public_key_pem()?,
        binding_mode: device.mode().into(),
        nonce: hex::encode(nonce),
    };
    let payload = serde_json::to_vec(&claims)?;
    let mut message = ACTIVATION_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    Ok(ActivationRequest {
        payload_b64: STANDARD.encode(payload),
        signature_b64: STANDARD.encode(device.sign(&message)?),
    })
}
pub fn verify_activation(request: &ActivationRequest) -> Result<ActivationClaims> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if request.payload_b64.len() > 16_384 || request.signature_b64.len() > 256 {
        return Err(Error::Invalid("activation size".into()));
    }
    let payload = STANDARD
        .decode(&request.payload_b64)
        .map_err(|_| Error::Signature)?;
    let signature = STANDARD
        .decode(&request.signature_b64)
        .map_err(|_| Error::Signature)?;
    let claims: ActivationClaims = serde_json::from_slice(&payload)?;
    if !license::valid_id(&claims.organization_id)
        || !license::valid_id(&claims.product_id)
        || !["development", "tpm2"].contains(&claims.binding_mode.as_str())
        || [&claims.hardware_salt, &claims.hardware_hash, &claims.nonce]
            .iter()
            .any(|v| hex::decode(v).map_or(true, |b| b.len() != 32))
    {
        return Err(Error::Invalid("activation fields".into()));
    }
    let mut message = ACTIVATION_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    crate::device::verify_device_signature(&claims.server_public_key_pem, &message, &signature)?;
    Ok(claims)
}
pub fn issue_registered(
    registry: &Path,
    claims: &Claims,
    key_id: &str,
    key: &SigningKey,
) -> Result<Envelope> {
    let mut db = open_registry(registry)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let envelope = issue_in_transaction(&tx, claims, key_id, key, None)?;
    tx.commit()?;
    Ok(envelope)
}

pub(crate) fn open_registry(registry: &Path) -> Result<Connection> {
    let db = Connection::open(registry)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS issued (license_id TEXT PRIMARY KEY, binding TEXT NOT NULL, revision INTEGER NOT NULL, digest TEXT NOT NULL, envelope TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trusted_devices (key_hash TEXT PRIMARY KEY, digest TEXT NOT NULL, record TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, document TEXT NOT NULL, used_input TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS attested_licenses (license_id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, trust_digest TEXT NOT NULL);
    ")?;
    Ok(db)
}

pub(crate) fn issue_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    claims: &Claims,
    key_id: &str,
    key: &SigningKey,
    authorized_previous_digest: Option<&str>,
) -> Result<Envelope> {
    let envelope = license::issue(claims, key_id, key)?;
    let digest = license::claims_digest(claims)?;
    let binding = serde_json::to_string(&(
        &claims.organization_id,
        &claims.product_id,
        &claims.binding_mode,
        &claims.hardware_profile,
        &claims.hardware_salt,
        &claims.hardware_hash,
        public_key_hash(&claims.server_public_key_pem)?,
    ))?;
    let old: Option<(String, i64, String, String)> = tx
        .query_row(
            "SELECT binding,revision,digest,envelope FROM issued WHERE license_id=?1",
            [&claims.license_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    if let Some((old_binding, revision, old_digest, old_envelope)) = old {
        let previous = license::verify(old_envelope.as_bytes(), key_id, &key.verifying_key())?;
        if claims.not_before < previous.not_before {
            return Err(Error::LicenseTime);
        }
        if binding != old_binding && authorized_previous_digest != Some(old_digest.as_str()) {
            return Err(Error::DeviceKeyMismatch);
        }
        if (claims.revision as i64) < revision
            || (claims.revision as i64 == revision && digest != old_digest)
        {
            return Err(Error::Revision);
        }
        if claims.revision as i64 == revision {
            return Ok(serde_json::from_str(&old_envelope)?);
        }
    } else if authorized_previous_digest.is_some() {
        return Err(Error::Revision);
    }
    tx.execute("INSERT INTO issued VALUES(?1,?2,?3,?4,?5) ON CONFLICT(license_id) DO UPDATE SET binding=excluded.binding,revision=excluded.revision,digest=excluded.digest,envelope=excluded.envelope",
        params![claims.license_id, binding, claims.revision as i64, digest, serde_json::to_string(&envelope)?])?;
    Ok(envelope)
}
