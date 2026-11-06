use crate::{
    device::{public_key_hash, verify_device_signature, Device},
    error::{Error, Result},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_FILE_BYTES: usize = 64 * 1024;
pub const PROOF_DOMAIN: &[u8] = b"ECOCHAIN-DEVICE-PROOF-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub schema_version: u32,
    pub license_id: String,
    pub revision: u64,
    pub organization_id: String,
    pub product_id: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expiration_date: i64,
    pub allowed_modules: Vec<String>,
    pub max_users: u32,
    pub hardware_profile: String,
    pub hardware_salt: String,
    pub hardware_hash: String,
    pub server_public_key_pem: String,
    pub binding_mode: String,
    /// Vendor-attested TPM Clock reading. Absent in licenses issued before clock
    /// anchoring; omitted on serialization so their digests stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_clock_anchor: Option<ClockAnchor>,
}

/// Pairs a TPM Clock reading (milliseconds of powered-on time, never reset by the
/// owner) with a UTC time that is known to be no later than that reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockAnchor {
    pub unix_time: i64,
    pub clock_ms: u64,
}

/// TPM clocks may run fast. Only this share of elapsed TPM time is trusted as
/// elapsed UTC time, which keeps the derived floor a lower bound.
pub const TPM_CLOCK_MIN_RATE_PERCENT: u64 = 85;
/// Tolerated backward movement of TPM Clock (e.g. lost NV update on power loss).
pub const TPM_CLOCK_BACKWARD_SLACK_MS: u64 = 300_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format_version: u32,
    pub key_id: String,
    pub payload_b64: String,
    pub signature_b64: String,
}

fn message(version: u32, key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = b"ECOCHAIN-LICENSE-V1\0".to_vec();
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    out.extend_from_slice(key_id.as_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn validate_claims(c: &Claims) -> Result<()> {
    if c.schema_version != 1
        || c.license_id.is_empty()
        || c.license_id.len() > 128
        || c.revision == 0
        || c.revision > i64::MAX as u64
        || c.organization_id.is_empty()
        || c.product_id.is_empty()
        || c.max_users == 0
        || c.max_users > 1_000_000
        || c.issued_at < 0
        || c.issued_at > c.not_before
        || c.not_before >= c.expiration_date
        || c.expiration_date > 253_402_300_799
        || c.hardware_profile != "dmi-v1"
        || !["development", "tpm2"].contains(&c.binding_mode.as_str())
        || c.allowed_modules.is_empty()
        || c.allowed_modules.len() > 128
        || c.allowed_modules.iter().any(|s| !valid_id(s))
        || c.allowed_modules
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != c.allowed_modules.len()
        || hex::decode(&c.hardware_salt).map_or(true, |b| b.len() != 32)
        || hex::decode(&c.hardware_hash).map_or(true, |b| b.len() != 32)
        || c.tpm_clock_anchor
            .as_ref()
            .is_some_and(|a| a.unix_time < 0 || a.unix_time > c.issued_at)
    {
        return Err(Error::Invalid("invalid license claims".into()));
    }
    public_key_hash(&c.server_public_key_pem)?;
    Ok(())
}

pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b))
}

pub fn issue(claims: &Claims, key_id: &str, key: &SigningKey) -> Result<Envelope> {
    validate_claims(claims)?;
    if !valid_id(key_id) {
        return Err(Error::Invalid("invalid key id".into()));
    }
    let payload = serde_json::to_vec(claims)?;
    let sig = key.sign(&message(1, key_id, &payload));
    Ok(Envelope {
        format_version: 1,
        key_id: key_id.into(),
        payload_b64: STANDARD.encode(payload),
        signature_b64: STANDARD.encode(sig.to_bytes()),
    })
}

pub fn verify(file: &[u8], key_id: &str, key: &VerifyingKey) -> Result<Claims> {
    if file.is_empty() || file.len() > MAX_FILE_BYTES {
        return Err(Error::Invalid("license file size".into()));
    }
    let env: Envelope = serde_json::from_slice(file)?;
    if env.format_version != 1 || env.key_id != key_id {
        return Err(Error::Signature);
    }
    let payload = STANDARD
        .decode(&env.payload_b64)
        .map_err(|_| Error::Signature)?;
    let signature = STANDARD
        .decode(&env.signature_b64)
        .map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::Signature)?;
    key.verify_strict(
        &message(env.format_version, &env.key_id, &payload),
        &signature,
    )
    .map_err(|_| Error::Signature)?;
    let c: Claims = serde_json::from_slice(&payload)?;
    validate_claims(&c)?;
    Ok(c)
}

pub fn claims_digest(c: &Claims) -> Result<String> {
    // Internal state conflict detection, not signature verification.
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(c)?)))
}

/// Full binding check: cheap claim/time checks plus a fresh device proof.
pub fn check_binding(
    claims: &Claims,
    device: &dyn Device,
    allow_dev: bool,
    organization: &str,
    product: &str,
    now: i64,
) -> Result<()> {
    check_claims(claims, device, allow_dev, organization, product, now)?;
    prove_device(claims, device)
}

/// Local checks that need no device round trip.
pub fn check_claims(
    claims: &Claims,
    device: &dyn Device,
    allow_dev: bool,
    organization: &str,
    product: &str,
    now: i64,
) -> Result<()> {
    validate_claims(claims)?;
    if claims.binding_mode == "development" && !allow_dev {
        return Err(Error::DevelopmentForbidden);
    }
    if claims.organization_id != organization || claims.product_id != product {
        return Err(Error::Unauthorized);
    }
    if now < claims.not_before || now >= claims.expiration_date {
        return Err(Error::LicenseTime);
    }
    if device.mode() != claims.binding_mode {
        return Err(Error::DeviceKeyMismatch);
    }
    Ok(())
}

/// Hardware identity, key identity and a fresh challenge signature.
pub fn prove_device(claims: &Claims, device: &dyn Device) -> Result<()> {
    if device.hardware_hash(&claims.hardware_salt)? != claims.hardware_hash {
        return Err(Error::HardwareMismatch);
    }
    if public_key_hash(&device.public_key_pem()?)?
        != public_key_hash(&claims.server_public_key_pem)?
    {
        return Err(Error::DeviceKeyMismatch);
    }
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let mut proof = PROOF_DOMAIN.to_vec();
    proof.extend_from_slice(&challenge);
    verify_device_signature(&claims.server_public_key_pem, &proof, &device.sign(&proof)?)
}

/// Lower bound for current UTC time derived from the TPM Clock anchor.
///
/// Deleting or restoring the state database cannot move this floor backwards,
/// because TPM Clock only advances while the TPM is powered.
pub fn clock_floor(claims: &Claims, device: &dyn Device) -> Result<Option<i64>> {
    let Some(anchor) = &claims.tpm_clock_anchor else {
        return Ok(None);
    };
    let current = match device.tpm_clock_ms()? {
        Some(value) => value,
        None if claims.binding_mode == "tpm2" => {
            return Err(Error::Device("TPM clock unavailable".into()))
        }
        None => return Ok(None),
    };
    if current.saturating_add(TPM_CLOCK_BACKWARD_SLACK_MS) < anchor.clock_ms {
        return Err(Error::Clock);
    }
    let elapsed = current.saturating_sub(anchor.clock_ms) / 1000 * TPM_CLOCK_MIN_RATE_PERCENT / 100;
    let elapsed = i64::try_from(elapsed).map_err(|_| Error::Clock)?;
    Ok(Some(anchor.unix_time.saturating_add(elapsed)))
}
