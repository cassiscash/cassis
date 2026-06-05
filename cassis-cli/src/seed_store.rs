use std::path::{Path, PathBuf};

/// On-disk location of the plaintext mnemonic seed file.
pub const SEED_FILENAME: &str = "seed";

/// Resolve `~/.cassis/seed`. The directory is created by callers as
/// needed.
pub fn seed_path(home: &Path) -> PathBuf {
    home.join(SEED_FILENAME)
}

/// Read the mnemonic from `path`, trimming trailing whitespace.
pub fn read_mnemonic(path: &Path) -> std::io::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    Ok(raw.trim().to_string())
}

/// Write the mnemonic to `path` with mode 0600. Refuses to overwrite
/// an existing file unless `force` is true.
pub fn write_mnemonic(path: &Path, mnemonic: &str, force: bool) -> std::io::Result<()> {
    use std::io::ErrorKind;
    match std::fs::metadata(path) {
        Ok(_) if !force => {
            return Err(std::io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "seed file already exists at {}; pass --force to overwrite",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(mnemonic.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all().ok();
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, format!("{mnemonic}\n"))?;
    }
    Ok(())
}
