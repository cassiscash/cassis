use std::fmt::Write;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{format::Writer, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, SpanRef};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

const CONTEXTS: &[(&str, &str, &str)] = &[
    ("iroh_server", "\x1b[34m", "iroh server"),
    ("iroh_client", "\x1b[32m", "iroh client"),
    ("nostr", "\x1b[33m", "nostr"),
    ("cassisd", "\x1b[36m", "cassisd"),
    ("cassis_router", "\x1b[36m", "router"),
    ("cassis_cli", "\x1b[35m", "cassis-cli"),
    ("cassis_client", "\x1b[33m", "cassis-client"),
    ("cassis_rootstock", "\x1b[91m", "rootstock"),
    ("cassis_cashu", "\x1b[94m", "cashu"),
];

const OUR_TARGETS: &[&str] = &[
    "iroh_server",
    "iroh_client",
    "nostr",
    "cassisd",
    "cassis_router",
    "cassis_cli",
    "cassis_client",
    // Network adapters. Without these the per-network logs (HTLC
    // lock/claim, preimage reveal) fall under the `warn` default and
    // are silently dropped everywhere except the playground, which
    // installs no filter at all.
    "cassis_rootstock",
    "cassis_cashu",
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
        // Must be registered for the formatter to see `node` / `network`:
        // the registry does not retain span field values on its own.
        .with(ScopeLayer)
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
        ctx: &FmtContext<'_, S, N>,
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
/// crate's [`init_logging`] or the playground's own layer — must install
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
