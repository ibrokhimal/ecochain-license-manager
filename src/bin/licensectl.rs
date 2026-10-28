use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use ecochain_license::{
    clock, config, demo, files, issuer,
    lease::{self, LeaseToken},
    license::{self, Claims},
    pb, rpc,
};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(about = "Offline License Manager operator/client CLI")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Args)]
struct ClientArgs {
    #[arg(long)]
    credentials: PathBuf,
    #[arg(long, default_value = "https://127.0.0.1:50051")]
    endpoint: String,
    #[arg(long, default_value = "alice")]
    user: String,
}
#[derive(Subcommand)]
enum Action {
    Demo {
        #[arg(long, default_value = "demo")]
        out: PathBuf,
    },
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Enroll {
        #[arg(long)]
        device_config: PathBuf,
        #[arg(long)]
        organization: String,
        #[arg(long, default_value = "ecochain")]
        product: String,
        #[arg(long)]
        output: PathBuf,
    },
    Issue {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        license_id: String,
        #[arg(long, default_value = "vendor-1")]
        key_id: String,
        #[arg(long, default_value_t = 1)]
        revision: u64,
        #[arg(long)]
        max_users: u32,
        #[arg(long, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long)]
        expiration_date: i64,
        #[arg(long)]
        allow_development: bool,
        #[arg(long)]
        approve_tpm_enrollment: bool,
    },
    Inspect {
        #[arg(long)]
        license: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value = "vendor-1")]
        key_id: String,
    },
    InitState {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        allow_development: bool,
    },
    Status {
        #[command(flatten)]
        client: ClientArgs,
    },
    Acquire {
        #[command(flatten)]
        client: ClientArgs,
        #[arg(long)]
        session: String,
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long, value_delimiter = ',', default_value = "inventory")]
        modules: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Renew {
        #[command(flatten)]
        client: ClientArgs,
        #[arg(long)]
        lease: PathBuf,
        #[arg(long)]
        request_id: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Validate {
        #[command(flatten)]
        client: ClientArgs,
        #[arg(long)]
        lease: PathBuf,
        #[arg(long, default_value = "inventory")]
        module: String,
    },
    Smoke {
        #[arg(long)]
        credentials: PathBuf,
        #[arg(long, default_value = "https://127.0.0.1:50051")]
        endpoint: String,
    },
}

fn public_key(path: &Path) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = hex::decode(String::from_utf8(files::read(path, 256)?)?.trim())?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(
        &raw.try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte public key"))?,
    )?)
}
fn saved_token(path: &Path) -> Result<LeaseToken> {
    Ok(serde_json::from_slice(&files::read(path, 65536)?)?)
}
fn token_claims(token: &LeaseToken) -> Result<lease::LeaseClaims> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    // Parsing only for routing renewal; server independently verifies authorization and signature.
    Ok(serde_json::from_slice(
        &STANDARD.decode(&token.payload_b64)?,
    )?)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Action::Demo { out } => {
            demo::create(&out)?;
            println!(
                "{}",
                serde_json::json!({"created":out,"mode":"development","anti_clone_guarantee":false})
            );
        }
        Action::Keygen { out } => {
            std::fs::create_dir(&out)?;
            let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            files::secret(&out.join("vendor.key"), hex::encode(key.to_bytes()))?;
            files::secret(
                &out.join("vendor.pub"),
                hex::encode(key.verifying_key().to_bytes()),
            )?;
            println!("Vendor keys created in {}", out.display());
        }
        Action::Enroll {
            device_config,
            organization,
            product,
            output,
        } => {
            let cfg: config::DeviceConfig =
                serde_json::from_slice(&files::read(&device_config, 8192)?)?;
            let base = device_config.parent().unwrap_or(Path::new("."));
            let request = issuer::enroll(
                config::device(&cfg, base)?.as_ref(),
                &organization,
                &product,
            )?;
            files::json(&output, &request)?;
            println!("Activation request created: {}", output.display());
        }
        Action::Issue {
            request,
            key,
            registry,
            output,
            license_id,
            key_id,
            revision,
            max_users,
            modules,
            expiration_date,
            allow_development,
            approve_tpm_enrollment: _,
        } => {
            anyhow::ensure!(!output.exists(), "output exists; choose a new filename");
            let activation: issuer::ActivationRequest =
                serde_json::from_slice(&files::read(&request, 65536)?)?;
            let binding = issuer::verify_activation(&activation)?;
            if binding.binding_mode == "development" {
                anyhow::ensure!(
                    allow_development,
                    "development request requires --allow-development"
                );
            } else {
                anyhow::bail!("TPM issuance requires license-tpm trust-import/challenge/complete with a fresh pinned NV proof; boolean approval is insufficient");
            }
            let raw = hex::decode(String::from_utf8(files::read(&key, 256)?)?.trim())?;
            let key = ed25519_dalek::SigningKey::from_bytes(
                &raw.try_into()
                    .map_err(|_| anyhow::anyhow!("expected 32-byte vendor seed"))?,
            );
            let now = clock::unix_now();
            let claims = Claims {
                schema_version: 1,
                license_id,
                revision,
                organization_id: binding.organization_id,
                product_id: binding.product_id,
                issued_at: now,
                not_before: now,
                expiration_date,
                allowed_modules: modules,
                max_users,
                hardware_profile: "dmi-v1".into(),
                hardware_salt: binding.hardware_salt,
                hardware_hash: binding.hardware_hash,
                server_public_key_pem: binding.server_public_key_pem,
                binding_mode: binding.binding_mode,
            };
            anyhow::ensure!(expiration_date > now, "expiration must be in the future");
            let envelope = issuer::issue_registered(&registry, &claims, &key_id, &key)?;
            files::json(&output, &envelope)?;
            println!("License issued: {}", output.display());
        }
        Action::Inspect {
            license: path,
            public_key: public,
            key_id,
        } => {
            let claims = license::verify(
                &files::read(&path, license::MAX_FILE_BYTES)?,
                &key_id,
                &public_key(&public)?,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"signature_valid":true,"device_binding_checked":false,"claims":claims})
                )?
            );
        }
        Action::InitState {
            config: path,
            state,
            allow_development,
        } => {
            let cfg = config::load(&path)?;
            config::load_engine(
                &cfg,
                path.parent().unwrap_or(Path::new(".")),
                &state,
                allow_development,
                true,
            )?;
            println!("State initialized: {}", state.display());
        }
        Action::Status { client } => {
            let state = rpc::connect(&client.credentials, &client.endpoint, &client.user)
                .await?
                .get_status(pb::StatusRequest {})
                .await?
                .into_inner();
            println!(
                "{}",
                serde_json::json!({"license_id":state.license_id,"revision":state.revision,"max_users":state.max_users,"active_users":state.active_users,"expiration_date":state.expiration_date,"modules":state.modules,"binding_mode":state.binding_mode})
            );
        }
        Action::Acquire {
            client,
            session,
            request_id,
            modules,
            output,
        } => {
            anyhow::ensure!(!output.exists(), "output already exists");
            let response = rpc::connect(&client.credentials, &client.endpoint, &client.user)
                .await?
                .acquire(pb::AcquireRequest {
                    request_id: request_id.unwrap_or_else(clock::request_id),
                    session_id: session,
                    modules,
                })
                .await?
                .into_inner();
            files::json(
                &output,
                &rpc::from_wire(response.lease.context("missing lease")?),
            )?;
            println!(
                "{}",
                serde_json::json!({"lease_saved":output,"heartbeat_seconds":response.heartbeat_after_seconds})
            );
        }
        Action::Renew {
            client,
            lease: path,
            request_id,
            output,
        } => {
            anyhow::ensure!(!output.exists(), "output already exists");
            let old = token_claims(&saved_token(&path)?)?;
            let response = rpc::connect(&client.credentials, &client.endpoint, &client.user)
                .await?
                .renew(pb::RenewRequest {
                    request_id: request_id.unwrap_or_else(clock::request_id),
                    lease_id: old.lease_id,
                    session_id: old.session_id,
                })
                .await?
                .into_inner();
            files::json(
                &output,
                &rpc::from_wire(response.lease.context("missing lease")?),
            )?;
            println!("Lease renewed: {}", output.display());
        }
        Action::Validate {
            client,
            lease: path,
            module,
        } => {
            let token = saved_token(&path)?;
            let response = rpc::connect(&client.credentials, &client.endpoint, &client.user)
                .await?
                .validate(pb::ValidateRequest {
                    lease: Some(rpc::to_wire(&token)?),
                    module,
                })
                .await?
                .into_inner();
            println!(
                "{}",
                serde_json::json!({"valid":true,"expires_at":response.expires_at})
            );
        }
        Action::Smoke {
            credentials,
            endpoint,
        } => smoke(&credentials, &endpoint).await?,
    }
    Ok(())
}

async fn smoke(credentials: &Path, endpoint: &str) -> Result<()> {
    let mut alice = rpc::connect(credentials, endpoint, "alice").await?;
    let mut bob = rpc::connect(credentials, endpoint, "bob").await?;
    let unique = uuid::Uuid::new_v4().to_string();
    let request = pb::AcquireRequest {
        request_id: clock::request_id(),
        session_id: format!("desktop-{unique}"),
        modules: vec!["inventory".into()],
    };
    let token = alice
        .acquire(request.clone())
        .await?
        .into_inner()
        .lease
        .context("missing lease")?;
    anyhow::ensure!(
        alice
            .acquire(request.clone())
            .await?
            .into_inner()
            .lease
            .as_ref()
            == Some(&token),
        "retry changed lease"
    );
    alice
        .validate(pb::ValidateRequest {
            lease: Some(token.clone()),
            module: "inventory".into(),
        })
        .await?;
    let denied = bob
        .acquire(pb::AcquireRequest {
            request_id: clock::request_id(),
            session_id: "bob-desktop".into(),
            modules: vec!["inventory".into()],
        })
        .await
        .unwrap_err();
    anyhow::ensure!(
        denied.code() == tonic::Code::ResourceExhausted,
        "seat limit bypass"
    );
    let denied = bob
        .validate(pb::ValidateRequest {
            lease: Some(token.clone()),
            module: "inventory".into(),
        })
        .await
        .unwrap_err();
    anyhow::ensure!(
        denied.code() == tonic::Code::Unauthenticated,
        "owner check bypass"
    );
    let denied = alice
        .validate(pb::ValidateRequest {
            lease: Some(token.clone()),
            module: "billing".into(),
        })
        .await
        .unwrap_err();
    anyhow::ensure!(
        denied.code() == tonic::Code::PermissionDenied,
        "module check bypass"
    );
    let old = token_claims(&rpc::from_wire(token))?;
    let renewal = pb::RenewRequest {
        request_id: clock::request_id(),
        lease_id: old.lease_id,
        session_id: request.session_id,
    };
    let renewed = alice
        .renew(renewal.clone())
        .await?
        .into_inner()
        .lease
        .context("missing renewed lease")?;
    anyhow::ensure!(
        alice.renew(renewal).await?.into_inner().lease.as_ref() == Some(&renewed),
        "renew retry changed lease"
    );
    alice
        .validate(pb::ValidateRequest {
            lease: Some(renewed),
            module: "inventory".into(),
        })
        .await?;
    println!(
        "{}",
        serde_json::json!({"smoke":"passed","checks":["mtls","acquire","idempotency","validate","capacity","owner","module","renew","renew-idempotency"]})
    );
    Ok(())
}
