#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ecochain_license::{
    attestation::{self, NvProof, TrustedDevice},
    device::SoftwareDevice,
    issuer::ActivationRequest,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::{EncodePublicKey, LineEnding},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

pub fn sized(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
pub fn public_blob(key: &SigningKey, attrs: u32, policy: &[u8]) -> Vec<u8> {
    let mut body = vec![];
    body.extend_from_slice(&0x23u16.to_be_bytes());
    body.extend_from_slice(&0x0bu16.to_be_bytes());
    body.extend_from_slice(&attrs.to_be_bytes());
    sized(policy, &mut body);
    for n in [0x10u16, 0x18, 0x0b, 0x03, 0x10] {
        body.extend_from_slice(&n.to_be_bytes());
    }
    let point = key.verifying_key().to_encoded_point(false);
    sized(point.x().unwrap(), &mut body);
    sized(point.y().unwrap(), &mut body);
    let mut out = vec![];
    sized(&body, &mut out);
    out
}
pub struct TpmFixture {
    pub trust: TrustedDevice,
    pub ak: SigningKey,
    pub device: SigningKey,
    pub policy: [u8; 32],
}
impl TpmFixture {
    pub fn new() -> Self {
        let ak = SigningKey::random(&mut OsRng);
        let device = SigningKey::random(&mut OsRng);
        let mut nv_body = vec![];
        nv_body.extend_from_slice(&0x0150_0020u32.to_be_bytes());
        nv_body.extend_from_slice(&0x0bu16.to_be_bytes());
        nv_body.extend_from_slice(&0x2004_0012u32.to_be_bytes());
        nv_body.extend_from_slice(&0u16.to_be_bytes());
        nv_body.extend_from_slice(&8u16.to_be_bytes());
        let mut nv_public = vec![];
        sized(&nv_body, &mut nv_public);
        let mut nv_name = vec![0, 0x0b];
        nv_name.extend_from_slice(&Sha256::digest(&nv_body));
        let policy = attestation::nv_policy(&nv_name, 1);
        let trust = TrustedDevice {
            schema_version: 1,
            environment: "simulator".into(),
            organization_id: "org-1".into(),
            product_id: "ecochain".into(),
            system_uuid: "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
            board_serial: "BOARD-A".into(),
            ak_public_tpm_b64: STANDARD.encode(public_blob(&ak, 0x0005_0072, &[])),
            ak_qualified_name_hex: format!("000b{}", "ac".repeat(32)),
            device_public_tpm_b64: STANDARD.encode(public_blob(&device, 0x0004_0032, &policy)),
            nv_name_hex: hex::encode(nv_name),
            nv_public_tpm_b64: STANDARD.encode(nv_public),
            activation_counter: 1,
        };
        Self {
            trust,
            ak,
            device,
            policy,
        }
    }
    pub fn sign_proof(&self, bytes: &[u8]) -> NvProof {
        let sig: Signature = self.ak.sign(bytes);
        NvProof {
            attestation_b64: STANDARD.encode(bytes),
            signature_b64: STANDARD.encode(sig.to_der().as_bytes()),
        }
    }
    pub fn proof(&self, counter: u64, nonce: &[u8]) -> NvProof {
        let mut bytes = vec![];
        bytes.extend_from_slice(&0xff54_4347u32.to_be_bytes());
        bytes.extend_from_slice(&0x8014u16.to_be_bytes());
        sized(
            &hex::decode(&self.trust.ak_qualified_name_hex).unwrap(),
            &mut bytes,
        );
        sized(nonce, &mut bytes);
        bytes.extend_from_slice(&1000u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        sized(&hex::decode(&self.trust.nv_name_hex).unwrap(), &mut bytes);
        bytes.extend_from_slice(&0u16.to_be_bytes());
        sized(&counter.to_be_bytes(), &mut bytes);
        self.sign_proof(&bytes)
    }
    pub fn activation(&self) -> ActivationRequest {
        let device = SoftwareDevice::new(
            self.device.clone(),
            self.trust.system_uuid.clone(),
            self.trust.board_serial.clone(),
        );
        ecochain_license::issuer::enroll(
            &device,
            &self.trust.organization_id,
            &self.trust.product_id,
        )
        .unwrap()
    }
    pub fn public_pem(&self) -> String {
        self.device
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
    }
}
