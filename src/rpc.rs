// tonic's public RPC/interceptor APIs intentionally use its unboxed Status type.
#![allow(clippy::result_large_err)]

use crate::{
    clock::Clock,
    config::Caller,
    engine::{Engine, Principal, HEARTBEAT_SECONDS},
    error::Error,
    lease::LeaseToken,
    pb::{
        self,
        license_service_client::LicenseServiceClient,
        license_service_server::{LicenseService, LicenseServiceServer},
    },
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use tonic::{
    service::interceptor::InterceptedService,
    transport::{
        Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
    },
    Request, Response, Status,
};
#[derive(Clone)]
pub struct Auth {
    pub token: String,
}
impl tonic::service::Interceptor for Auth {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token.trim())
                .parse()
                .map_err(|_| Status::unauthenticated("invalid credentials"))?,
        );
        Ok(request)
    }
}
pub type Client = LicenseServiceClient<InterceptedService<Channel, Auth>>;
pub async fn connect(credentials: &Path, endpoint: &str, user: &str) -> anyhow::Result<Client> {
    anyhow::ensure!(endpoint.starts_with("https://"), "TLS endpoint required");
    anyhow::ensure!(crate::license::valid_id(user), "invalid user name");
    let tls = ClientTlsConfig::new()
        .domain_name("license-server")
        .ca_certificate(Certificate::from_pem(crate::files::read(
            &credentials.join("ca.pem"),
            8192,
        )?))
        .identity(Identity::from_pem(
            crate::files::read(&credentials.join("client.pem"), 8192)?,
            crate::files::read(&credentials.join("client.key"), 8192)?,
        ));
    let channel = Endpoint::from_shared(endpoint.to_owned())?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(3))
        .connect()
        .await?;
    let token = String::from_utf8(crate::files::read(
        &credentials.join(format!("{user}.token")),
        512,
    )?)?;
    Ok(LicenseServiceClient::with_interceptor(
        channel,
        Auth { token },
    ))
}

struct Service {
    engine: Arc<Engine>,
    callers: BTreeMap<String, Principal>,
    clock: Arc<Clock>,
}
impl Service {
    fn principal<T>(&self, request: &Request<T>) -> Result<Principal, Status> {
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() >= 32 && v.len() <= 512)
            .ok_or_else(|| Status::unauthenticated("UNAUTHORIZED"))?;
        self.callers
            .get(&hex::encode(Sha256::digest(bearer.as_bytes())))
            .cloned()
            .ok_or_else(|| Status::unauthenticated("UNAUTHORIZED"))
    }
    fn now(&self) -> Result<i64, Status> {
        self.clock.now().map_err(status)
    }
}

#[tonic::async_trait]
impl LicenseService for Service {
    async fn acquire(
        &self,
        request: Request<pb::AcquireRequest>,
    ) -> Result<Response<pb::LeaseResponse>, Status> {
        let principal = self.principal(&request)?;
        let now = self.now()?;
        let input = request.into_inner();
        let engine = self.engine.clone();
        let token = tokio::task::spawn_blocking(move || {
            engine.acquire(
                &principal,
                &input.request_id,
                &input.session_id,
                &input.modules,
                now,
            )
        })
        .await
        .map_err(|_| Status::internal("worker failure"))?
        .map_err(status)?;
        Ok(Response::new(pb::LeaseResponse {
            lease: Some(to_wire(&token)?),
            server_time: now,
            heartbeat_after_seconds: HEARTBEAT_SECONDS,
        }))
    }
    async fn renew(
        &self,
        request: Request<pb::RenewRequest>,
    ) -> Result<Response<pb::LeaseResponse>, Status> {
        let principal = self.principal(&request)?;
        let now = self.now()?;
        let input = request.into_inner();
        let engine = self.engine.clone();
        let token = tokio::task::spawn_blocking(move || {
            engine.renew(
                &principal,
                &input.request_id,
                &input.lease_id,
                &input.session_id,
                now,
            )
        })
        .await
        .map_err(|_| Status::internal("worker failure"))?
        .map_err(status)?;
        Ok(Response::new(pb::LeaseResponse {
            lease: Some(to_wire(&token)?),
            server_time: now,
            heartbeat_after_seconds: HEARTBEAT_SECONDS,
        }))
    }
    async fn validate(
        &self,
        request: Request<pb::ValidateRequest>,
    ) -> Result<Response<pb::ValidateResponse>, Status> {
        let principal = self.principal(&request)?;
        let now = self.now()?;
        let input = request.into_inner();
        let engine = self.engine.clone();
        let token = from_wire(
            input
                .lease
                .ok_or_else(|| Status::invalid_argument("lease required"))?,
        );
        let claims = tokio::task::spawn_blocking(move || {
            engine.validate(&principal, &token, &input.module, now)
        })
        .await
        .map_err(|_| Status::internal("worker failure"))?
        .map_err(status)?;
        Ok(Response::new(pb::ValidateResponse {
            expires_at: claims.expires_at,
        }))
    }
    async fn get_status(
        &self,
        request: Request<pb::StatusRequest>,
    ) -> Result<Response<pb::StatusResponse>, Status> {
        let principal = self.principal(&request)?;
        let now = self.now()?;
        let engine = self.engine.clone();
        let state = tokio::task::spawn_blocking(move || engine.status(&principal, now))
            .await
            .map_err(|_| Status::internal("worker failure"))?
            .map_err(status)?;
        Ok(Response::new(pb::StatusResponse {
            license_id: state.license_id,
            revision: state.revision,
            expiration_date: state.expiration_date,
            max_users: state.max_users,
            active_users: state.active_users,
            modules: state.modules,
            binding_mode: state.binding_mode,
        }))
    }
}

pub fn to_wire(token: &LeaseToken) -> Result<pb::SignedLease, Status> {
    Ok(pb::SignedLease {
        payload_json: STANDARD
            .decode(&token.payload_b64)
            .map_err(|_| Status::internal("invalid saved lease"))?,
        signature_der: STANDARD
            .decode(&token.signature_b64)
            .map_err(|_| Status::internal("invalid saved signature"))?,
    })
}
pub fn from_wire(token: pb::SignedLease) -> LeaseToken {
    LeaseToken {
        payload_b64: STANDARD.encode(token.payload_json),
        signature_b64: STANDARD.encode(token.signature_der),
    }
}
fn status(error: Error) -> Status {
    let message = error.to_string();
    match error {
        Error::Unauthorized => Status::unauthenticated(message),
        Error::ModuleDenied => Status::permission_denied(message),
        Error::Limit | Error::SessionLimit | Error::RateLimit => {
            Status::resource_exhausted(message)
        }
        Error::Invalid(_) | Error::Json(_) => Status::invalid_argument("INVALID_INPUT"),
        Error::Device(_) | Error::Io(_) => Status::unavailable("DEVICE_UNAVAILABLE"),
        Error::Storage(_) => {
            eprintln!("{{\"event\":\"storage_error\"}}");
            Status::internal("STATE_UNAVAILABLE")
        }
        _ => Status::failed_precondition(message),
    }
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    tls: ServerTlsConfig,
    engine: Arc<Engine>,
    callers: Vec<Caller>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let callers = callers
        .into_iter()
        .map(|c| {
            (
                c.token_sha256,
                Principal {
                    organization: c.organization,
                    subject: c.subject,
                },
            )
        })
        .collect();
    let service = Service {
        engine,
        callers,
        clock: Arc::new(Clock::default()),
    };
    Server::builder()
        .tls_config(tls)?
        .concurrency_limit_per_connection(32)
        .timeout(Duration::from_secs(5))
        .add_service(
            LicenseServiceServer::new(service)
                .max_decoding_message_size(64 * 1024)
                .max_encoding_message_size(64 * 1024),
        )
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}
