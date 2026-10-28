use crate::{
    device::{verify_device_signature, Device},
    error::{Error, Result},
    license::Claims,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

pub const LEASE_DOMAIN: &[u8] = b"ECOCHAIN-LEASE-V1\0";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LeaseToken {
    pub payload_b64: String,
    pub signature_b64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseClaims {
    pub lease_id: String,
    pub license_id: String,
    pub revision: u64,
    pub organization_id: String,
    pub subject: String,
    pub session_id: String,
    pub allowed_modules: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub fn sign_token(claims: &LeaseClaims, device: &dyn Device) -> Result<LeaseToken> {
    let payload = serde_json::to_vec(claims)?;
    let mut message = LEASE_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    Ok(LeaseToken {
        payload_b64: STANDARD.encode(&payload),
        signature_b64: STANDARD.encode(device.sign(&message)?),
    })
}

pub fn verify_token(token: &LeaseToken, license: &Claims, now: i64) -> Result<LeaseClaims> {
    if token.payload_b64.len() > 32_768 || token.signature_b64.len() > 256 {
        return Err(Error::LeaseInvalid);
    }
    let payload = STANDARD
        .decode(&token.payload_b64)
        .map_err(|_| Error::LeaseInvalid)?;
    let signature = STANDARD
        .decode(&token.signature_b64)
        .map_err(|_| Error::LeaseInvalid)?;
    let mut message = LEASE_DOMAIN.to_vec();
    message.extend_from_slice(&payload);
    verify_device_signature(&license.server_public_key_pem, &message, &signature)?;
    let lease: LeaseClaims = serde_json::from_slice(&payload)?;
    if lease.license_id != license.license_id
        || lease.revision != license.revision
        || lease.organization_id != license.organization_id
        || now < license.not_before
        || now >= license.expiration_date
        || now < lease.issued_at
        || now >= lease.expires_at
        || lease.issued_at >= lease.expires_at
        || lease.expires_at - lease.issued_at > 180
        || lease.expires_at > license.expiration_date
        || lease.allowed_modules.is_empty()
        || lease
            .allowed_modules
            .iter()
            .any(|m| !license.allowed_modules.contains(m))
    {
        return Err(Error::LeaseInvalid);
    }
    Ok(lease)
}
