//! Vendor-side pinned TPM attestation workflow. Does not execute TPM commands.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand};
use ecochain_license::{
    attestation::{self, NvProof, TrustedDevice},
    clock,
    device::fingerprint,
    files,
    issuer::{self, ActivationClaims, ActivationRequest},
    migration::{self, Proofs, SignedChallenge, Terms},
};
use rand_core::{OsRng, RngCore};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Offline pinned-TPM attestation and license migration tools")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Args)]
struct Vendor {
    #[arg(long)]
    registry: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value = "vendor-1")]
    key_id: String,
}
#[derive(Subcommand)]
enum Action {
    InspectChallenge {
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    PackTrust {
        #[arg(long)]
        ak_public: PathBuf,
        #[arg(long)]
        ak_qualified_name: PathBuf,
        #[arg(long)]
        device_public: PathBuf,
        #[arg(long)]
        nv_name: PathBuf,
        #[arg(long)]
        nv_public: PathBuf,
        #[arg(long)]
        counter: PathBuf,
        #[arg(long)]
        organization: String,
        #[arg(long, default_value = "ecochain")]
        product: String,
        #[arg(long)]
        system_uuid: String,
        #[arg(long)]
        board_serial: String,
        #[arg(long,value_parser=["physical","simulator"])]
        environment: String,
        #[arg(long)]
        output: PathBuf,
    },
    TrustImport {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        approve_physical_onboarding: bool,
        #[arg(long)]
        allow_simulator: bool,
    },
    PrepareActivation {
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        payload_output: PathBuf,
        #[arg(long)]
        message_output: PathBuf,
    },
    PackActivation {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Challenge {
        #[command(flatten)]
        vendor: Vendor,
        #[arg(long,value_parser=["enroll","migrate"])]
        kind: String,
        #[arg(long)]
        license_id: String,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        allow_simulator: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Nonce {
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long,value_parser=["target","old"])]
        role: String,
        #[arg(long)]
        output: PathBuf,
    },
    PackProof {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Complete {
        #[command(flatten)]
        vendor: Vendor,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        target_proof: PathBuf,
        #[arg(long)]
        old_proof: Option<PathBuf>,
        #[arg(long)]
        terms: Option<PathBuf>,
        #[arg(long)]
        allow_simulator: bool,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyProof {
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        challenge: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long,value_parser=["target","old"])]
        role: String,
        #[arg(long)]
        allow_simulator: bool,
    },
}
fn json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&files::read(path, 65536)?)?)
}
fn vendor_key(path: &Path) -> Result<ed25519_dalek::SigningKey> {
    let raw = hex::decode(String::from_utf8(files::read(path, 256)?)?.trim())?;
    Ok(ed25519_dalek::SigningKey::from_bytes(
        &raw.try_into()
            .map_err(|_| anyhow::anyhow!("32-byte vendor key required"))?,
    ))
}
fn public_key(path: &Path) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = hex::decode(String::from_utf8(files::read(path, 256)?)?.trim())?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(
        &raw.try_into()
            .map_err(|_| anyhow::anyhow!("32-byte vendor public key required"))?,
    )?)
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Action::InspectChallenge {
            challenge,
            public_key: public,
        } => {
            let c = migration::verify_challenge(&json(&challenge)?, &public_key(&public)?)?;
            println!("{}", serde_json::to_string_pretty(&c)?);
        }
        Action::PackTrust {
            ak_public,
            ak_qualified_name,
            device_public,
            nv_name,
            nv_public,
            counter,
            organization,
            product,
            system_uuid,
            board_serial,
            environment,
            output,
        } => {
            let bytes: [u8; 8] = files::read(&counter, 8)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("8-byte counter required"))?;
            let record = TrustedDevice {
                schema_version: 1,
                environment,
                organization_id: organization,
                product_id: product,
                system_uuid,
                board_serial,
                ak_public_tpm_b64: STANDARD.encode(files::read(&ak_public, 4096)?),
                ak_qualified_name_hex: hex::encode(files::read(&ak_qualified_name, 34)?),
                device_public_tpm_b64: STANDARD.encode(files::read(&device_public, 4096)?),
                nv_name_hex: hex::encode(files::read(&nv_name, 34)?),
                nv_public_tpm_b64: STANDARD.encode(files::read(&nv_public, 4096)?),
                activation_counter: u64::from_be_bytes(bytes),
            };
            attestation::validate_trust(&record, true)?;
            files::json(&output, &record)?;
        }
        Action::TrustImport {
            registry,
            record,
            approve_physical_onboarding,
            allow_simulator,
        } => {
            let record: TrustedDevice = json(&record)?;
            if record.environment == "physical" {
                anyhow::ensure!(approve_physical_onboarding,"trusted physical onboarding approval required; a client-supplied AK is not trusted automatically");
            }
            let hash = migration::register_trust(&registry, &record, allow_simulator)?;
            println!(
                "{}",
                serde_json::json!({"trusted_device_key":hash,"environment":record.environment})
            );
        }
        Action::PrepareActivation {
            record,
            payload_output,
            message_output,
        } => {
            anyhow::ensure!(
                !payload_output.exists() && !message_output.exists(),
                "output already exists"
            );
            let record: TrustedDevice = json(&record)?;
            attestation::validate_trust(&record, true)?;
            let mut random = [0u8; 32];
            OsRng.fill_bytes(&mut random);
            let salt = hex::encode(random);
            OsRng.fill_bytes(&mut random);
            let activation = ActivationClaims {
                organization_id: record.organization_id.clone(),
                product_id: record.product_id.clone(),
                hardware_salt: salt.clone(),
                hardware_hash: fingerprint(&record.system_uuid, &record.board_serial, &salt)?,
                server_public_key_pem: attestation::device_public_pem(&record)?,
                binding_mode: if record.environment == "physical" {
                    "tpm2"
                } else {
                    "development"
                }
                .into(),
                nonce: hex::encode(random),
            };
            let payload = serde_json::to_vec(&activation)?;
            let mut message = issuer::ACTIVATION_DOMAIN.to_vec();
            message.extend_from_slice(&payload);
            files::secret(&payload_output, payload)?;
            files::secret(&message_output, message)?;
        }
        Action::PackActivation {
            payload,
            signature,
            output,
        } => {
            let request = ActivationRequest {
                payload_b64: STANDARD.encode(files::read(&payload, 16384)?),
                signature_b64: STANDARD.encode(files::read(&signature, 128)?),
            };
            issuer::verify_activation(&request)?;
            files::json(&output, &request)?;
        }
        Action::Challenge {
            vendor,
            kind,
            license_id,
            request,
            allow_simulator,
            output,
        } => {
            anyhow::ensure!(!output.exists(), "output exists");
            let document = migration::create_challenge(
                &vendor.registry,
                &kind,
                &license_id,
                &json(&request)?,
                &vendor.key_id,
                &vendor_key(&vendor.key)?,
                clock::unix_now(),
                allow_simulator,
            )?;
            files::json(&output, &document)?;
        }
        Action::Nonce {
            challenge,
            public_key: public,
            role,
            output,
        } => {
            let document: SignedChallenge = json(&challenge)?;
            let c = migration::verify_challenge(&document, &public_key(&public)?)?;
            anyhow::ensure!(
                clock::unix_now() >= c.created_at && clock::unix_now() < c.expires_at,
                "challenge outside validity window"
            );
            anyhow::ensure!(
                role != "old" || c.kind == "migrate",
                "old proof is only for migration"
            );
            files::secret(&output, migration::nonce(&document, &role)?)?;
        }
        Action::PackProof {
            attestation,
            signature,
            output,
        } => files::json(
            &output,
            &NvProof {
                attestation_b64: STANDARD.encode(files::read(&attestation, 4096)?),
                signature_b64: STANDARD.encode(files::read(&signature, 128)?),
            },
        )?,
        Action::Complete {
            vendor,
            challenge,
            request,
            target_proof,
            old_proof,
            terms,
            allow_simulator,
            output,
        } => {
            anyhow::ensure!(!output.exists(), "output exists");
            let proofs = Proofs {
                target: json(&target_proof)?,
                old: old_proof.as_deref().map(json).transpose()?,
            };
            let terms: Option<Terms> = terms.as_deref().map(json).transpose()?;
            let result = migration::complete(
                &vendor.registry,
                &json(&challenge)?,
                &json(&request)?,
                &proofs,
                terms.as_ref(),
                &vendor.key_id,
                &vendor_key(&vendor.key)?,
                clock::unix_now(),
                allow_simulator,
            )?;
            files::json(&output, &result)?;
            println!(
                "{}",
                serde_json::json!({"license_saved":output,"simulator_allowed":allow_simulator})
            );
        }
        Action::VerifyProof {
            record,
            challenge,
            public_key: public,
            proof,
            role,
            allow_simulator,
        } => {
            let document: SignedChallenge = json(&challenge)?;
            migration::verify_challenge(&document, &public_key(&public)?)?;
            let evidence = attestation::verify_nv(
                &json(&record)?,
                &json(&proof)?,
                &migration::nonce(&document, &role)?,
                allow_simulator,
            )
            .context("TPM NV proof rejected")?;
            println!(
                "{}",
                serde_json::json!({"signature_valid":true,"counter":evidence.counter,"clock":evidence.clock,"reset_count":evidence.reset_count,"restart_count":evidence.restart_count})
            );
        }
    }
    Ok(())
}
