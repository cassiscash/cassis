use std::fmt::Write;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

const RESET: &str = "\x1b[0m";

const CONTEXTS: &[(&str, &str, &str)] = &[
    ("iroh_server", "\x1b[34m", "iroh server"),
    ("iroh_client", "\x1b[32m", "iroh client"),
    ("nostr", "\x1b[33m", "nostr"),
    ("cassisd", "\x1b[36m", "cassisd"),
    ("cassis_router", "\x1b[36m", "router"),
    ("cassis_cli", "\x1b[35m", "cassis-cli"),
    ("cassis_client", "\x1b[33m", "cassis-client"),
];

const OUR_TARGETS: &[&str] = &[
    "iroh_server",
    "iroh_client",
    "nostr",
    "cassisd",
    "cassis_router",
    "cassis_cli",
    "cassis_client",
];

pub fn init_logging() {
    let default_filter = {
        let mut f = "warn".to_string();
        for t in OUR_TARGETS {
            f.push_str(&format!(",{t}=debug"));
        }
        f
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().event_format(CassisFormatter))
        .init();
}

struct CassisFormatter;

impl<S, N> FormatEvent<S, N> for CassisFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let target = event.metadata().target();
        let (color, display) = CONTEXTS
            .iter()
            .find(|(t, _, _)| *t == target)
            .map(|(_, c, d)| (*c, *d))
            .unwrap_or(("", target));
        let level = *event.metadata().level();
        let level_color = match level {
            tracing::Level::ERROR => "\x1b[31m",
            tracing::Level::WARN => "\x1b[33m",
            tracing::Level::INFO => "\x1b[32m",
            tracing::Level::DEBUG => "\x1b[36m",
            tracing::Level::TRACE => "\x1b[37m",
        };
        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));
        writeln!(
            writer,
            "{color}[{display}]{RESET} {level_color}{level:<5}{RESET} {message}"
        )
    }
}

struct MessageVisitor<'a>(&'a mut String);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}
