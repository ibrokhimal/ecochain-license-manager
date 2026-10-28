use clap::Parser;
use ecochain_license::{config, rpc};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Offline License Server (mTLS gRPC)")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    state: PathBuf,
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,
    #[arg(long, default_value_t = false)]
    allow_development: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let base = args.config.parent().unwrap_or(std::path::Path::new("."));
    let cfg = config::load(&args.config)?;
    let engine = config::load_engine(&cfg, base, &args.state, args.allow_development, false)?;
    if args.allow_development {
        eprintln!("{{\"event\":\"development_mode_enabled\",\"anti_clone_guarantee\":false}}");
    }
    let tls = config::tls(&cfg, base)?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!(
        "{}",
        serde_json::json!({"event":"license_server_ready","listen":listener.local_addr()?.to_string(),"license_id":engine.claims.license_id,"binding_mode":engine.claims.binding_mode})
    );
    rpc::serve(listener, tls, engine, cfg.callers, shutdown()).await
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
