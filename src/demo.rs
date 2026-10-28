use crate::{
    config::{Caller, DeviceConfig, ServerConfig},
    device::{Device, SoftwareDevice},
    files,
    license::Claims,
};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub fn create(root: &Path) -> anyhow::Result<()> {
    // Never overwrite an existing installation or key directory.
    fs::create_dir(root)?;
    for dir in [
        "vendor", "server-a", "server-b", "state-a", "state-b", "client",
    ] {
        fs::create_dir(root.join(dir))?;
    }
    let vendor = ed25519_dalek::SigningKey::generate(&mut OsRng);
    files::secret(
        &root.join("vendor/vendor.key"),
        hex::encode(vendor.to_bytes()),
    )?;
    files::secret(
        &root.join("vendor/vendor.pub"),
        hex::encode(vendor.verifying_key().to_bytes()),
    )?;

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Ecochain Demo CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key)?;
    files::secret(&root.join("vendor/ca.key"), ca_key.serialize_pem())?;
    files::secret(&root.join("vendor/ca.pem"), ca.pem())?;

    let server_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![
        "license-server".into(),
        "localhost".into(),
        "127.0.0.1".into(),
    ])?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let server_certificate = params.signed_by(&server_key, &ca, &ca_key)?;
    let client_key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Demo provisioned client");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_certificate = params.signed_by(&client_key, &ca, &ca_key)?;
    files::secret(&root.join("client/ca.pem"), ca.pem())?;
    files::secret(&root.join("client/client.pem"), client_certificate.pem())?;
    files::secret(&root.join("client/client.key"), client_key.serialize_pem())?;

    let mut callers = Vec::new();
    for subject in ["alice", "bob"] {
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        let token = hex::encode(random);
        callers.push(Caller {
            token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
            organization: "demo-org".into(),
            subject: subject.into(),
        });
        files::secret(&root.join(format!("client/{subject}.token")), token)?;
    }

    let mut configs = Vec::new();
    let mut devices: Vec<SoftwareDevice> = Vec::new();
    for (name, uuid, serial) in [
        (
            "server-a",
            "aaba4679-b41d-46a8-b8af-4fa855843211",
            "DEMO-BOARD-A",
        ),
        (
            "server-b",
            "aaba4679-b41d-46a8-b8af-4fa855843212",
            "DEMO-BOARD-B",
        ),
    ] {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        files::secret(
            &root.join(name).join("device.key"),
            key.to_pkcs8_pem(LineEnding::LF)?.as_bytes(),
        )?;
        devices.push(SoftwareDevice::new(key, uuid.into(), serial.into()));
        let base = root.join(name);
        files::secret(
            &base.join("vendor.pub"),
            hex::encode(vendor.verifying_key().to_bytes()),
        )?;
        files::secret(&base.join("ca.pem"), ca.pem())?;
        files::secret(&base.join("server.pem"), server_certificate.pem())?;
        files::secret(&base.join("server.key"), server_key.serialize_pem())?;
        let config = ServerConfig {
            organization: "demo-org".into(),
            product: "ecochain".into(),
            vendor_key_id: "vendor-demo-1".into(),
            vendor_public_key: "vendor.pub".into(),
            license: "license.lic".into(),
            device: DeviceConfig::Development {
                key: "device.key".into(),
                system_uuid: uuid.into(),
                board_serial: serial.into(),
            },
            ca: "ca.pem".into(),
            certificate: "server.pem".into(),
            private_key: "server.key".into(),
            callers: callers.clone(),
        };
        files::json(&base.join("server.json"), &config)?;
        configs.push(config);
    }
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let salt = hex::encode(random);
    let now = crate::clock::unix_now();
    let claims = Claims {
        schema_version: 1,
        license_id: "demo-license".into(),
        revision: 1,
        organization_id: "demo-org".into(),
        product_id: "ecochain".into(),
        issued_at: now - 1,
        not_before: now - 1,
        expiration_date: now + 86_400,
        allowed_modules: vec!["inventory".into(), "analytics".into()],
        max_users: 1,
        hardware_profile: "dmi-v1".into(),
        hardware_salt: salt.clone(),
        hardware_hash: devices[0].hardware_hash(&salt)?,
        server_public_key_pem: devices[0].public_key_pem()?,
        binding_mode: "development".into(),
    };
    let envelope = crate::issuer::issue_registered(
        &root.join("vendor/issuer.db"),
        &claims,
        "vendor-demo-1",
        &vendor,
    )?;
    for name in ["server-a", "server-b", "client"] {
        files::json(&root.join(name).join("license.lic"), &envelope)?;
    }
    files::secret(
        &root.join("client/vendor.pub"),
        hex::encode(vendor.verifying_key().to_bytes()),
    )?;
    crate::config::load_engine(
        &configs[0],
        &root.join("server-a"),
        &root.join("state-a/state.db"),
        true,
        true,
    )?;
    Ok(())
}
