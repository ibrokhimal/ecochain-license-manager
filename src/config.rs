use crate::{device::Device, engine::Engine};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub token_sha256: String,
    pub organization: String,
    pub subject: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeviceConfig {
    Development {
        key: PathBuf,
        system_uuid: String,
        board_serial: String,
    },
    Tpm2 {
        socket: PathBuf,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub organization: String,
    pub product: String,
    pub vendor_key_id: String,
    pub vendor_public_key: PathBuf,
    pub license: PathBuf,
    pub device: DeviceConfig,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub callers: Vec<Caller>,
}
pub fn load(path: &Path) -> anyhow::Result<ServerConfig> {
    let config: ServerConfig = serde_json::from_slice(&crate::files::read(path, 1024 * 1024)?)?;
    anyhow::ensure!(
        !config.callers.is_empty(),
        "at least one caller is required"
    );
    let mut hashes = std::collections::BTreeSet::new();
    for caller in &config.callers {
        anyhow::ensure!(
            hex::decode(&caller.token_sha256)?.len() == 32
                && hashes.insert(&caller.token_sha256)
                && crate::license::valid_id(&caller.subject)
                && caller.organization == config.organization,
            "invalid or duplicate caller mapping"
        );
    }
    Ok(config)
}
pub fn device(config: &DeviceConfig, base: &Path) -> anyhow::Result<Arc<dyn Device>> {
    use p256::pkcs8::DecodePrivateKey;
    Ok(match config {
        DeviceConfig::Development {
            key,
            system_uuid,
            board_serial,
        } => {
            let pem = String::from_utf8(crate::files::read(&base.join(key), 8192)?)?;
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem)?;
            Arc::new(crate::device::SoftwareDevice::new(
                key,
                system_uuid.clone(),
                board_serial.clone(),
            ))
        }
        DeviceConfig::Tpm2 { socket } => Arc::new(crate::agent::RemoteDevice {
            socket: base.join(socket),
        }),
    })
}
pub fn load_engine(
    config: &ServerConfig,
    base: &Path,
    state: &Path,
    allow_dev: bool,
    initialize: bool,
) -> anyhow::Result<Arc<Engine>> {
    let public = hex::decode(
        String::from_utf8(crate::files::read(
            &base.join(&config.vendor_public_key),
            256,
        )?)?
        .trim(),
    )?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &public
            .try_into()
            .map_err(|_| anyhow::anyhow!("vendor public key must be 32 bytes"))?,
    )?;
    let file = crate::files::read(&base.join(&config.license), crate::license::MAX_FILE_BYTES)?;
    let claims = crate::license::verify(&file, &config.vendor_key_id, &key)?;
    anyhow::ensure!(
        claims.organization_id == config.organization && claims.product_id == config.product,
        "license organization/product mismatch"
    );
    Ok(Arc::new(Engine::open(
        state,
        claims,
        device(&config.device, base)?,
        allow_dev,
        initialize,
        crate::clock::unix_now(),
    )?))
}
pub fn tls(
    config: &ServerConfig,
    base: &Path,
) -> anyhow::Result<tonic::transport::ServerTlsConfig> {
    use tonic::transport::{Certificate, Identity, ServerTlsConfig};
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(
            crate::files::read(&base.join(&config.certificate), 8192)?,
            crate::files::read(&base.join(&config.private_key), 8192)?,
        ))
        .client_ca_root(Certificate::from_pem(crate::files::read(
            &base.join(&config.ca),
            8192,
        )?)))
}
