use crate::{
    device::{public_key_hash, verify_device_signature, Device},
    error::{Error, Result},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_MESSAGE: usize = 64 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum AgentRequest {
    PublicKey,
    Hardware { salt: String },
    Sign { message_b64: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentResponse {
    value: Option<String>,
    error: Option<String>,
}

pub struct RemoteDevice {
    pub socket: PathBuf,
}
#[cfg(unix)]
pub fn serve_connection(
    mut stream: std::os::unix::net::UnixStream,
    device: &dyn Device,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_line(&stream)
        .and_then(|line| serde_json::from_slice::<AgentRequest>(&line).map_err(Error::from));
    let result = request.and_then(|request| match request {
        AgentRequest::PublicKey => device.public_key_pem(),
        AgentRequest::Hardware { salt } => device.hardware_hash(&salt),
        AgentRequest::Sign { message_b64 } => {
            let bytes = STANDARD
                .decode(message_b64)
                .map_err(|_| Error::Invalid("invalid base64".into()))?;
            let permitted = bytes.starts_with(crate::lease::LEASE_DOMAIN)
                || bytes.starts_with(crate::license::PROOF_DOMAIN)
                || bytes.starts_with(crate::issuer::ACTIVATION_DOMAIN);
            if !permitted || bytes.len() > 32_768 {
                return Err(Error::Invalid("signing domain denied".into()));
            }
            Ok(STANDARD.encode(device.sign(&bytes)?))
        }
    });
    let response = match result {
        Ok(value) => AgentResponse {
            value: Some(value),
            error: None,
        },
        Err(error) => AgentResponse {
            value: None,
            error: Some(error.to_string()),
        },
    };
    stream.write_all(&serde_json::to_vec(&response)?)?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn read_line(stream: impl Read) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    BufReader::new(stream.take((MAX_MESSAGE + 1) as u64)).read_until(b'\n', &mut line)?;
    if line.len() > MAX_MESSAGE || !line.ends_with(b"\n") {
        return Err(Error::Invalid("agent message size/framing".into()));
    }
    Ok(line)
}

impl RemoteDevice {
    fn call(&self, request: AgentRequest) -> Result<String> {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixStream;
            let mut stream = UnixStream::connect(&self.socket)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            stream.write_all(&serde_json::to_vec(&request)?)?;
            stream.write_all(b"\n")?;
            let response: AgentResponse = serde_json::from_slice(&read_line(stream)?)?;
            response.value.ok_or_else(|| {
                Error::Device(
                    response
                        .error
                        .unwrap_or_else(|| "empty agent response".into()),
                )
            })
        }
        #[cfg(not(unix))]
        {
            let _ = request;
            Err(Error::Device("Unix host agent required".into()))
        }
    }
}
impl Device for RemoteDevice {
    fn mode(&self) -> &str {
        "tpm2"
    }
    fn public_key_pem(&self) -> Result<String> {
        self.call(AgentRequest::PublicKey)
    }
    fn hardware_hash(&self, salt: &str) -> Result<String> {
        self.call(AgentRequest::Hardware { salt: salt.into() })
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        STANDARD
            .decode(self.call(AgentRequest::Sign {
                message_b64: STANDARD.encode(message),
            })?)
            .map_err(|_| Error::Signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmConfig {
    pub key_handle: String,
    pub public_key_file: PathBuf,
    pub nv_index: String,
    pub expected_counter_file: PathBuf,
    pub tcti: String,
}

pub struct TpmDevice {
    config: TpmConfig,
}
impl TpmDevice {
    pub fn new(config: TpmConfig) -> Result<Self> {
        for handle in [&config.key_handle, &config.nv_index] {
            if handle.len() != 10
                || !handle.starts_with("0x")
                || u32::from_str_radix(&handle[2..], 16).is_err()
            {
                return Err(Error::Invalid("invalid TPM handle".into()));
            }
        }
        if !config.tcti.starts_with("device:") {
            return Err(Error::Device(
                "physical device TCTI required; simulator is not production TPM".into(),
            ));
        }
        let counter = std::fs::read(&config.expected_counter_file)?;
        if counter.len() != 8 {
            return Err(Error::Invalid("NV counter operand must be 8 bytes".into()));
        }
        let device = Self { config };
        public_key_hash(&device.public_key_pem()?)?;
        Ok(device)
    }
    fn run(&self, program: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
        let mut child = Command::new(program)
            .args(args)
            .env("TPM2TOOLS_TCTI", &self.config.tcti)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                return Err(Error::Device(format!(
                    "{program} failed (policy/key/device unavailable)"
                )));
            }
            if start.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Device(format!("{program} timeout")));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Device for TpmDevice {
    fn mode(&self) -> &str {
        "tpm2"
    }
    fn public_key_pem(&self) -> Result<String> {
        let bytes = std::fs::read(&self.config.public_key_file)?;
        if bytes.len() > 8192 {
            return Err(Error::Invalid("public key file too large".into()));
        }
        String::from_utf8(bytes).map_err(|_| Error::Invalid("public key must be PEM UTF-8".into()))
    }
    fn hardware_hash(&self, salt: &str) -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            crate::device::fingerprint(
                &std::fs::read_to_string("/sys/class/dmi/id/product_uuid")?,
                &std::fs::read_to_string("/sys/class/dmi/id/board_serial")?,
                salt,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = salt;
            Err(Error::Device(
                "TPM host adapter currently requires Linux".into(),
            ))
        }
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use std::ffi::OsStr;
        let temp = tempfile::tempdir()?;
        let session = temp.path().join("session.ctx");
        let input = temp.path().join("message");
        let output = temp.path().join("signature.der");
        std::fs::write(&input, message)?;
        self.run(
            "tpm2_startauthsession",
            &[
                OsStr::new("--policy-session"),
                OsStr::new("-S"),
                session.as_os_str(),
            ],
        )?;
        let result = (|| {
            self.run(
                "tpm2_policynv",
                &[
                    OsStr::new("-S"),
                    session.as_os_str(),
                    OsStr::new("-i"),
                    self.config.expected_counter_file.as_os_str(),
                    OsStr::new(&self.config.nv_index),
                    OsStr::new("eq"),
                ],
            )?;
            let auth = format!("session:{}", session.display());
            self.run(
                "tpm2_sign",
                &[
                    OsStr::new("-c"),
                    OsStr::new(&self.config.key_handle),
                    OsStr::new("-p"),
                    OsStr::new(&auth),
                    OsStr::new("-g"),
                    OsStr::new("sha256"),
                    OsStr::new("-s"),
                    OsStr::new("ecdsa"),
                    OsStr::new("-f"),
                    OsStr::new("plain"),
                    OsStr::new("-o"),
                    output.as_os_str(),
                    input.as_os_str(),
                ],
            )?;
            let signature = std::fs::read(&output)?;
            verify_device_signature(&self.public_key_pem()?, message, &signature)?;
            Ok(signature)
        })();
        let _ = self.run("tpm2_flushcontext", &[session.as_os_str()]);
        result
    }
}
