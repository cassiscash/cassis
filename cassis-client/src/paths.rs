use std::cell::RefCell;
use std::path::PathBuf;

pub const CASSIS_DIRNAME: &str = ".cassis";
pub const STORE_FILENAME: &str = "store.db";

thread_local! {
    /// Explicit override set by the CLI's `--home` flag.
    /// Wins over `CASSIS_HOME` / `$HOME/.cassis`. Reset by
    /// the CLI at startup; tests should `set_home_override`
    /// themselves.
    static HOME_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Set the explicit home-dir override. Pass `None` to clear.
pub fn set_home_override(home: PathBuf) {
    HOME_OVERRIDE.with(|h| *h.borrow_mut() = Some(home));
}

/// Resolve the user's cassis config dir. Precedence:
/// 1. The value passed to [`set_home_override`] (set by the
///    `--home` flag).
/// 2. `$CASSIS_HOME` if set.
/// 3. `$HOME/.cassis`.
/// 4. `.cassis` in the current working directory.
pub fn cassis_home() -> PathBuf {
    if let Some(p) = HOME_OVERRIDE.with(|h| h.borrow().clone()) {
        return p;
    }
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
