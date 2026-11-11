use std::fmt::Write;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, SpanRef};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

/// Crates whose logs are shown at `debug` by default; everything else
/// only from `warn`. `RUST_LOG` overrides this.
const OUR_CRATES: &[&str] = &[
    "cassis_core",
    "cassis_networks",
    "cassis_routerd",
    "cassis_wallet",
    "cassis_arkade",
    "cassis_bitcoin",
    "cassis_cashu",
    "cassis_fedimint",
    "cassis_liquid",
    "cassis_lnd",
    "cassis_rootstock",
];

pub fn init_logging() {
    let default_filter = OUR_CRATES.iter().fold("warn".to_string(), |filter, krate| {
        format!("{filter},{krate}=debug")
    });
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::registry()
        .with(filter)
        // Must be registered for the formatter to see `node` / `network`:
        // the registry does not retain span field values on its own.
        .with(ScopeLayer)
        // Logs go to stderr so stdout stays machine-readable: commands
        // like `cassis-wallet receive` print JSON there, and mixing debug
        // lines into it breaks every script that parses the output.
        .with(
            fmt::layer()
                .event_format(CassisFormatter)
                .with_writer(std::io::stderr),
        )
        .init();
}

/// `cassis_wallet::node::payer` renders as `wallet::payer`, in a color
/// picked from the crate name.
fn context(target: &str) -> (&'static str, String) {
    const COLORS: &[&str] = &[
        "\x1b[34m", "\x1b[32m", "\x1b[33m", "\x1b[36m", "\x1b[35m", "\x1b[91m", "\x1b[94m",
    ];
    let mut segments = target.split("::");
    let krate = segments.next().unwrap_or(target);
    let module = segments.last();
    let name = krate.strip_prefix("cassis_").unwrap_or(krate);
    let color = COLORS[krate.bytes().map(usize::from).sum::<usize>() % COLORS.len()];
    match module {
        Some(module) => (color, format!("{name}::{module}")),
        None => (color, name.to_string()),
    }
}

struct CassisFormatter;

impl<S, N> FormatEvent<S, N> for CassisFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let (color, display) = context(event.metadata().target());
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
        let scope = ctx
            .event_scope()
            .map(ScopeFields::from_scope)
            .unwrap_or_default();
        writeln!(
            writer,
            "{color}[{display}]{RESET} {level_color}{level:<5}{RESET}{scope} {message}"
        )
    }
}

/// The `node` / `network` fields collected from an event's span scope,
/// rendered as ` [node/network]`.
///
/// Both are looked up by walking the whole scope rather than reading the
/// innermost span, because a per-network span is a *child* of the node
/// span: the innermost span alone carries `network` but not `node`.
#[derive(Default)]
pub struct ScopeFields {
    pub node: Option<String>,
    pub network: Option<String>,
}

impl ScopeFields {
    /// Collect the nearest `node` / `network` in an event's span scope.
    ///
    /// `spans` must yield innermost-first, which is what both
    /// [`FmtContext::event_scope`] and
    /// [`tracing_subscriber::layer::Context::event_scope`] produce. The
    /// two contexts have different signatures, so callers pass the
    /// iterator rather than the context.
    pub fn from_scope<'a, S>(spans: impl Iterator<Item = SpanRef<'a, S>>) -> Self
    where
        S: for<'b> LookupSpan<'b> + 'a,
    {
        let mut scope = Self::default();
        // Only fill empty slots, so the nearest span wins on a repeat.
        for span in spans {
            if let Some(fields) = span.extensions().get::<ScopeFields>() {
                if scope.node.is_none() {
                    scope.node = fields.node.clone();
                }
                if scope.network.is_none() {
                    scope.network = fields.network.clone();
                }
            }
        }
        scope
    }
}

impl std::fmt::Display for ScopeFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.node, &self.network) {
            (Some(node), Some(network)) => write!(f, " {BOLD}[{node}/{network}]{RESET}"),
            (Some(node), None) => write!(f, " {BOLD}[{node}]{RESET}"),
            (None, Some(network)) => write!(f, " {BOLD}[{network}]{RESET}"),
            (None, None) => Ok(()),
        }
    }
}

struct ScopeVisitor<'a>(&'a mut ScopeFields);

impl tracing::field::Visit for ScopeVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "node" => self.0.node = Some(value.to_string()),
            "network" => self.0.network = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "node" => self.0.node = Some(format!("{value:?}")),
            "network" => self.0.network = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

/// Records `node` / `network` off every new span into its extensions so
/// a formatter can read them back when formatting an event.
///
/// Required because the registry keeps no record of a span's field
/// values. Any subscriber that wants the `[node/network]` prefix — this
/// crate's [`init_logging`] or a custom one — must install
/// this alongside it, once.
pub struct ScopeLayer;

impl<S> tracing_subscriber::Layer<S> for ScopeLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = ScopeFields::default();
        attrs.record(&mut ScopeVisitor(&mut fields));
        if fields.node.is_none() && fields.network.is_none() {
            return;
        }
        if let Some(span) = ctx.span(id) {
            // `replace`, not `insert`: `insert` asserts nothing of the
            // type is present and would panic if this layer were ever
            // registered twice on one subscriber.
            span.extensions_mut().replace(fields);
        }
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
