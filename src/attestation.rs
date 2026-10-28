use crate::{
    device::{fingerprint, public_key_hash, verify_device_signature},
    error::{Error, Result},
    issuer::ActivationClaims,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::{
    ecdsa::VerifyingKey,
    pkcs8::{EncodePublicKey, LineEnding},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedDevice {
    pub schema_version: u32,
    pub environment: String,
    pub organization_id: String,
    pub product_id: String,
    pub system_uuid: String,
    pub board_serial: String,
    pub ak_public_tpm_b64: String,
    pub ak_qualified_name_hex: String,
    pub device_public_tpm_b64: String,
    pub nv_name_hex: String,
    pub nv_public_tpm_b64: String,
    pub activation_counter: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvProof {
    pub attestation_b64: String,
    pub signature_b64: String,
}
#[derive(Debug)]
pub struct Evidence {
    pub counter: u64,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
}
fn invalid() -> Error {
    Error::Invalid("invalid or unsupported TPM evidence".into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(invalid());
        }
        Ok(Self { bytes, pos: 0 })
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(size).ok_or_else(invalid)?;
        let value = self.bytes.get(self.pos..end).ok_or_else(invalid)?;
        self.pos = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let size = self.u16()? as usize;
        self.take(size)
    }
    fn done(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn b64(value: &str) -> Result<Vec<u8>> {
    if value.len() > 8192 {
        return Err(invalid());
    }
    STANDARD.decode(value).map_err(|_| invalid())
}
fn name(value: &str) -> Result<Vec<u8>> {
    if value.len() != 68 {
        return Err(invalid());
    }
    let bytes = hex::decode(value).map_err(|_| invalid())?;
    if !bytes.starts_with(&[0, 0x0b]) {
        return Err(invalid());
    }
    Ok(bytes)
}

struct PublicArea {
    pem: String,
    attributes: u32,
    policy: Vec<u8>,
}
fn public_area(encoded: &str) -> Result<PublicArea> {
    let bytes = b64(encoded)?;
    let mut outer = Reader::new(&bytes)?;
    let body = outer.sized()?;
    outer.done()?;
    let mut r = Reader::new(body)?;
    if r.u16()? != 0x23 || r.u16()? != 0x0b {
        return Err(invalid());
    }
    let attributes = r.u32()?;
    let policy = r.sized()?.to_vec();
    // Signing keys require symmetric=NULL; only ECDSA/SHA256 or NULL scheme.
    if r.u16()? != 0x10 {
        return Err(invalid());
    }
    match r.u16()? {
        0x10 => {}
        0x18 if r.u16()? == 0x0b => {}
        _ => return Err(invalid()),
    }
    if r.u16()? != 3 || r.u16()? != 0x10 {
        return Err(invalid());
    }
    let x = r.sized()?;
    let y = r.sized()?;
    r.done()?;
    if x.is_empty() || x.len() > 32 || y.is_empty() || y.len() > 32 {
        return Err(invalid());
    }
    let mut point = [0u8; 65];
    point[0] = 4;
    point[33 - x.len()..33].copy_from_slice(x);
    point[65 - y.len()..65].copy_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| invalid())?;
    Ok(PublicArea {
        pem: key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| invalid())?,
        attributes,
        policy,
    })
}

pub fn validate_trust(record: &TrustedDevice, allow_simulator: bool) -> Result<String> {
    if record.schema_version != 1
        || !["physical", "simulator"].contains(&record.environment.as_str())
        || (record.environment == "simulator" && !allow_simulator)
        || !crate::license::valid_id(&record.organization_id)
        || !crate::license::valid_id(&record.product_id)
        || record.activation_counter == 0
    {
        return Err(invalid());
    }
    fingerprint(&record.system_uuid, &record.board_serial, &"00".repeat(32))?;
    let nv = name(&record.nv_name_hex)?;
    if nv != validate_nv_public(&record.nv_public_tpm_b64)? {
        return Err(invalid());
    }
    name(&record.ak_qualified_name_hex)?;
    let ak = public_area(&record.ak_public_tpm_b64)?;
    let device = public_area(&record.device_public_tpm_b64)?;
    const FIXED: u32 = 0x0004_0032; // sign + sensitiveDataOrigin + fixedParent + fixedTPM
    if ak.attributes & (FIXED | 0x10000) != FIXED | 0x10000
        || ak.attributes & 0x20000 != 0
        || device.attributes & FIXED != FIXED
        || device.attributes & (0x30000 | 0x40) != 0
        || device.policy.as_slice() != nv_policy(&nv, record.activation_counter)
    {
        return Err(invalid());
    }
    public_key_hash(&device.pem)
}

fn validate_nv_public(encoded: &str) -> Result<Vec<u8>> {
    let bytes = b64(encoded)?;
    let mut outer = Reader::new(&bytes)?;
    let body = outer.sized()?;
    outer.done()?;
    let mut r = Reader::new(body)?;
    let index = r.u32()?;
    if !(0x0100_0000..0x0200_0000).contains(&index) || r.u16()? != 0x0b {
        return Err(invalid());
    }
    let attrs = r.u32()?;
    if attrs & 0xf0 != 0x10 || attrs & 0x2000_0000 == 0 {
        return Err(invalid());
    }
    let policy = r.sized()?;
    if !policy.is_empty() && policy.len() != 32 {
        return Err(invalid());
    }
    if r.u16()? != 8 {
        return Err(invalid());
    }
    r.done()?;
    let mut name = vec![0, 0x0b];
    name.extend_from_slice(&Sha256::digest(body));
    Ok(name)
}

pub fn device_public_pem(record: &TrustedDevice) -> Result<String> {
    Ok(public_area(&record.device_public_tpm_b64)?.pem)
}

pub fn match_activation(
    record: &TrustedDevice,
    activation: &ActivationClaims,
    allow_simulator: bool,
) -> Result<()> {
    let hash = validate_trust(record, allow_simulator)?;
    let mode = if record.environment == "physical" {
        "tpm2"
    } else {
        "development"
    };
    if activation.organization_id != record.organization_id
        || activation.product_id != record.product_id
        || activation.binding_mode != mode
        || public_key_hash(&activation.server_public_key_pem)? != hash
    {
        return Err(Error::DeviceKeyMismatch);
    }
    if fingerprint(
        &record.system_uuid,
        &record.board_serial,
        &activation.hardware_salt,
    )? != activation.hardware_hash
    {
        return Err(Error::HardwareMismatch);
    }
    Ok(())
}

pub fn verify_nv(
    record: &TrustedDevice,
    proof: &NvProof,
    nonce: &[u8],
    allow_simulator: bool,
) -> Result<Evidence> {
    validate_trust(record, allow_simulator)?;
    if nonce.is_empty() || nonce.len() > 64 || proof.signature_b64.len() > 256 {
        return Err(invalid());
    }
    let bytes = b64(&proof.attestation_b64)?;
    let signature = b64(&proof.signature_b64)?;
    let ak = public_area(&record.ak_public_tpm_b64)?;
    verify_device_signature(&ak.pem, &bytes, &signature)?;
    let mut r = Reader::new(&bytes)?;
    if r.u32()? != 0xff54_4347
        || r.u16()? != 0x8014
        || r.sized()? != name(&record.ak_qualified_name_hex)?
        || r.sized()? != nonce
    {
        return Err(invalid());
    }
    let clock = r.u64()?;
    let reset_count = r.u32()?;
    let restart_count = r.u32()?;
    if r.take(1)? != [1] {
        return Err(invalid());
    }
    r.u64()?; // firmware version is informational; signed original bytes remain intact.
    if r.sized()? != name(&record.nv_name_hex)? || r.u16()? != 0 {
        return Err(invalid());
    }
    let counter = u64::from_be_bytes(r.sized()?.try_into().map_err(|_| invalid())?);
    r.done()?;
    Ok(Evidence {
        counter,
        clock,
        reset_count,
        restart_count,
    })
}

pub fn nv_policy(nv_name: &[u8], counter: u64) -> [u8; 32] {
    let mut arguments = counter.to_be_bytes().to_vec();
    arguments.extend_from_slice(&[0u8; 4]); // offset=0, TPM_EO_EQ=0
    let mut input = vec![0u8; 32];
    input.extend_from_slice(&0x0000_0149u32.to_be_bytes());
    input.extend_from_slice(&Sha256::digest(arguments));
    input.extend_from_slice(nv_name);
    Sha256::digest(input).into()
}
