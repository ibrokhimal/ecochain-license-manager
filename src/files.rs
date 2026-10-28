use anyhow::{bail, Result};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("file exceeds size limit: {}", path.display());
    }
    Ok(bytes)
}
pub fn secret(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_ref())?;
    file.sync_all()?;
    Ok(())
}
pub fn json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    secret(path, serde_json::to_vec_pretty(value)?)
}
