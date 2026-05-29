use std::path::PathBuf;

pub const CASSIS_DIRNAME: &str = ".cassis";
pub const STORE_FILENAME: &str = "store.db";

/// Resolve the user's cassis config dir (`$CASSIS_HOME` or
/// `$HOME/.cassis`). Does not create it.
pub fn cassis_home() -> PathBuf {
    if let Ok(custom) = std::env::var("CASSIS_HOME") {
        return PathBuf::from(custom);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(CASSIS_DIRNAME);
    }
    PathBuf::from(CASSIS_DIRNAME)
}

pub fn store_path() -> PathBuf {
    cassis_home().join(STORE_FILENAME)
}

/// Create the cassis home directory if it does not exist.
pub fn ensure_cassis_home() -> std::io::Result<PathBuf> {
    let dir = cassis_home();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
