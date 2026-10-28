use crate::error::{Error, Result};
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
};
use sha2::{Digest, Sha256};

pub trait Device: Send + Sync {
    fn mode(&self) -> &str;
    fn public_key_pem(&self) -> Result<String>;
    fn hardware_hash(&self, salt: &str) -> Result<String>;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

pub fn fingerprint(uuid: &str, serial: &str, salt: &str) -> Result<String> {
    let uuid = uuid::Uuid::parse_str(uuid.trim())
        .map_err(|_| Error::Invalid("invalid system UUID".into()))?;
    let serial = serial.trim().to_ascii_lowercase();
    if uuid.is_nil()
        || uuid.as_bytes().iter().all(|v| *v == 255)
        || serial.is_empty()
        || serial.len() > 256
        || serial.chars().all(|c| c == '0')
        || [
            "unknown",
            "none",
            "default string",
            "to be filled by o.e.m.",
            "not specified",
        ]
        .contains(&serial.as_str())
    {
        return Err(Error::Invalid(
            "missing or placeholder hardware identity".into(),
        ));
    }
    let salt = hex::decode(salt).map_err(|_| Error::Invalid("invalid hardware salt".into()))?;
    if salt.len() != 32 {
        return Err(Error::Invalid("salt must be 32 bytes".into()));
    }
    let mut input = b"ECOCHAIN-HARDWARE-V1\0".to_vec();
    for part in [
        b"dmi-v1".as_slice(),
        &salt,
        uuid.hyphenated().to_string().as_bytes(),
        serial.as_bytes(),
    ] {
        input.extend_from_slice(&(part.len() as u32).to_be_bytes());
        input.extend_from_slice(part);
    }
    Ok(hex::encode(Sha256::digest(input)))
}

pub struct SoftwareDevice {
    key: SigningKey,
    uuid: String,
    serial: String,
}
impl SoftwareDevice {
    pub fn new(key: SigningKey, uuid: String, serial: String) -> Self {
        Self { key, uuid, serial }
    }
}
impl Device for SoftwareDevice {
    fn mode(&self) -> &str {
        "development"
    }
    fn public_key_pem(&self) -> Result<String> {
        self.key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Device(e.to_string()))
    }
    fn hardware_hash(&self, salt: &str) -> Result<String> {
        fingerprint(&self.uuid, &self.serial, salt)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

pub fn verify_device_signature(public_pem: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_public_key_pem(public_pem).map_err(|_| Error::Signature)?;
    let signature = Signature::from_der(signature).map_err(|_| Error::Signature)?;
    key.verify(message, &signature)
        .map_err(|_| Error::Signature)
}

pub fn public_key_hash(pem: &str) -> Result<String> {
    let key = VerifyingKey::from_public_key_pem(pem)
        .map_err(|_| Error::Invalid("invalid P-256 public key".into()))?;
    Ok(hex::encode(Sha256::digest(
        key.to_encoded_point(false).as_bytes(),
    )))
}
