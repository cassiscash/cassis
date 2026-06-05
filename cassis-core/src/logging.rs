use std::io::Write;

const RESET: &str = "\x1b[0m";

const CONTEXTS: &[(&str, &str, &str)] = &[
    ("iroh_server", "\x1b[34m", "iroh server"),
    ("iroh_client", "\x1b[32m", "iroh client"),
    ("nostr", "\x1b[33m", "nostr"),
    ("cassisd", "\x1b[36m", "cassisd"),
    ("cassis_cli", "\x1b[35m", "cassis-cli"),
];

const OUR_TARGETS: &[&str] = &[
    "iroh_server",
    "iroh_client",
    "nostr",
    "cassisd",
    "cassis_cli",
];

pub fn init_logging() {
    let default_filter = {
        let mut f = "warn".to_string();
        for t in OUR_TARGETS {
            f.push_str(&format!(",{t}=debug"));
        }
        f
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&default_filter))
        .format(|buf, record| {
            let target = record.target();
            let (color, display) = CONTEXTS
                .iter()
                .find(|(t, _, _)| *t == target)
                .map(|(_, c, d)| (*c, *d))
                .unwrap_or(("", target));
            let level_color = match record.level() {
                log::Level::Error => "\x1b[31m",
                log::Level::Warn => "\x1b[33m",
                log::Level::Info => "\x1b[32m",
                log::Level::Debug => "\x1b[36m",
                log::Level::Trace => "\x1b[37m",
            };
            writeln!(
                buf,
                "{color}[{display}]{RESET} {level_color}{:<5}{RESET} {}",
                record.level(),
                record.args(),
            )
        })
        .init();
}
