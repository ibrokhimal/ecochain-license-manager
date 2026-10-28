use ecochain_license::{clock, config, files};
use std::process::Command;

fn ctl(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_licensectl"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn operator_can_enroll_issue_and_inspect_without_server_having_vendor_key() {
    let temp = tempfile::tempdir().unwrap();
    let demo = temp.path().join("demo");
    let out = ctl(&["demo", "--out", demo.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let server = demo.join("server-a");
    assert!(!server.join("vendor.key").exists());
    let cfg = config::load(&server.join("server.json")).unwrap();
    files::json(&server.join("device.json"), &cfg.device).unwrap();
    let request = temp.path().join("activation.json");
    let out = ctl(&[
        "enroll",
        "--device-config",
        server.join("device.json").to_str().unwrap(),
        "--organization",
        "demo-org",
        "--output",
        request.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let license = temp.path().join("issued.lic");
    let expiration = (clock::unix_now() + 3600).to_string();
    let out = ctl(&[
        "issue",
        "--request",
        request.to_str().unwrap(),
        "--key",
        demo.join("vendor/vendor.key").to_str().unwrap(),
        "--registry",
        temp.path().join("issuer.db").to_str().unwrap(),
        "--output",
        license.to_str().unwrap(),
        "--license-id",
        "cli-license",
        "--max-users",
        "3",
        "--modules",
        "inventory,analytics",
        "--expiration-date",
        &expiration,
        "--allow-development",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = ctl(&[
        "inspect",
        "--license",
        license.to_str().unwrap(),
        "--public-key",
        server.join("vendor.pub").to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["signature_valid"], true);
    assert_eq!(result["claims"]["max_users"], 3);
    assert_eq!(result["claims"]["organization_id"], "demo-org");
    // The normal server never accepts the software demo without the explicit flag.
    let out = Command::new(env!("CARGO_BIN_EXE_license-server"))
        .args([
            "--config",
            server.join("server.json").to_str().unwrap(),
            "--state",
            demo.join("state-a/state.db").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("DEVELOPMENT_MODE_FORBIDDEN"));
    let out = ctl(&[
        "init-state",
        "--config",
        demo.join("server-b/server.json").to_str().unwrap(),
        "--state",
        demo.join("state-b/state.db").to_str().unwrap(),
        "--allow-development",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("HARDWARE_MISMATCH"));
}
