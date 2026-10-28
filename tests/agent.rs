#![cfg(unix)]
use ecochain_license::{
    agent::{serve_connection, RemoteDevice},
    device::{verify_device_signature, Device, SoftwareDevice},
    lease::LEASE_DOMAIN,
};
use rand_core::OsRng;
use std::{os::unix::net::UnixListener, sync::Arc};

#[test]
fn unix_agent_roundtrip_and_domain_restriction() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let device = Arc::new(SoftwareDevice::new(
        p256::ecdsa::SigningKey::random(&mut OsRng),
        "aaba4679-b41d-46a8-b8af-4fa855843211".into(),
        "BOARD-A".into(),
    ));
    let expected_key = device.public_key_pem().unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..4 {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream, device.as_ref()).unwrap();
        }
    });
    let remote = RemoteDevice { socket };
    assert_eq!(remote.public_key_pem().unwrap(), expected_key);
    assert_eq!(remote.hardware_hash(&"ab".repeat(32)).unwrap().len(), 64);
    let mut message = LEASE_DOMAIN.to_vec();
    message.extend_from_slice(b"sample");
    verify_device_signature(&expected_key, &message, &remote.sign(&message).unwrap()).unwrap();
    assert!(remote.sign(b"arbitrary TLS or document signing").is_err());
    worker.join().unwrap();
}
