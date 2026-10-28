use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Linux host TPM signer. No software-key fallback.")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    socket: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    #[cfg(unix)]
    {
        use ecochain_license::{
            agent::{self, TpmConfig, TpmDevice},
            files,
        };
        use std::{
            fs,
            os::unix::{fs::PermissionsExt, net::UnixListener},
        };
        let mut cfg: TpmConfig = serde_json::from_slice(&files::read(&args.config, 8192)?)?;
        let base = args.config.parent().unwrap_or(std::path::Path::new("."));
        cfg.public_key_file = base.join(cfg.public_key_file);
        cfg.expected_counter_file = base.join(cfg.expected_counter_file);
        let device = TpmDevice::new(cfg)?;
        // Existing paths are never unlinked implicitly.
        let listener = UnixListener::bind(&args.socket)?;
        fs::set_permissions(&args.socket, fs::Permissions::from_mode(0o660))?;
        eprintln!(
            "{}",
            serde_json::json!({"event":"tpm_agent_ready","socket":args.socket})
        );
        for connection in listener.incoming() {
            match connection {
                Ok(stream) => {
                    if agent::serve_connection(stream, &device).is_err() {
                        eprintln!("{{\"event\":\"agent_request_failed\"}}");
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        anyhow::bail!("Unix/Linux host required")
    }
}
