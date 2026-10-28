use ecochain_license::{config, demo, pb, rpc};
use tonic::Code;

#[tokio::test]
async fn mtls_grpc_enforces_capacity_identity_and_signed_lease() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("demo");
    demo::create(&root).unwrap();
    let base = root.join("server-a");
    let cfg = config::load(&base.join("server.json")).unwrap();
    let engine =
        config::load_engine(&cfg, &base, &root.join("state-a/state.db"), true, false).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let tls = config::tls(&cfg, &base).unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(rpc::serve(listener, tls, engine, cfg.callers, async {
        let _ = shutdown.await;
    }));
    let credentials = root.join("client");
    let mut alice = rpc::connect(&credentials, &endpoint, "alice")
        .await
        .unwrap();
    let mut bob = rpc::connect(&credentials, &endpoint, "bob").await.unwrap();
    let request = pb::AcquireRequest {
        request_id: format!("{}:a-1", ecochain_license::clock::unix_now()),
        session_id: "desktop".into(),
        modules: vec!["inventory".into()],
    };
    let lease = alice
        .acquire(request.clone())
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    let retry = alice
        .acquire(request)
        .await
        .unwrap()
        .into_inner()
        .lease
        .unwrap();
    assert_eq!(lease, retry);
    alice
        .validate(pb::ValidateRequest {
            lease: Some(lease.clone()),
            module: "inventory".into(),
        })
        .await
        .unwrap();
    assert_eq!(
        bob.validate(pb::ValidateRequest {
            lease: Some(lease.clone()),
            module: "inventory".into()
        })
        .await
        .unwrap_err()
        .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        bob.acquire(pb::AcquireRequest {
            request_id: format!("{}:b-1", ecochain_license::clock::unix_now()),
            session_id: "desktop".into(),
            modules: vec!["inventory".into()]
        })
        .await
        .unwrap_err()
        .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        alice
            .validate(pb::ValidateRequest {
                lease: Some(lease),
                module: "billing".into()
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    std::fs::write(credentials.join("mallory.token"), "invalid-token").unwrap();
    let mut mallory = rpc::connect(&credentials, &endpoint, "mallory")
        .await
        .unwrap();
    assert_eq!(
        mallory
            .get_status(pb::StatusRequest {})
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    // A client with no certificate cannot use the service even with Alice's token.
    let ca =
        tonic::transport::Certificate::from_pem(std::fs::read(credentials.join("ca.pem")).unwrap());
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .domain_name("license-server")
                .ca_certificate(ca),
        )
        .unwrap()
        .connect_lazy();
    let mut uncertified = pb::license_service_client::LicenseServiceClient::with_interceptor(
        channel,
        rpc::Auth {
            token: std::fs::read_to_string(credentials.join("alice.token")).unwrap(),
        },
    );
    assert!(uncertified.get_status(pb::StatusRequest {}).await.is_err());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
