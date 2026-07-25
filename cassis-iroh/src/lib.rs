use cassis_core::{
    Bytes32, HopCommit, HopCommitted, HopDiscard, HopDiscarded, HopDispatch, HopDispatched,
    HopPrepare, HopPrepared, HtlcDescriptor, NetworkId,
};
use iroh::endpoint::presets;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::error::Error as _;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub const ALPN_PROTOCOL: &[u8] = b"cassis-hop/1";

#[derive(thiserror::Error, Debug)]
pub enum IrohError {
    #[error("io error: {0}")]
    Io(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("connection closed")]
    Closed,
}

/// Every message the hop protocol carries on the wire. The
/// `Direction` tag discriminates sender vs receiver roles; the
/// router (intermediate hop) handles `Prepare`, `Prepared`,
/// `Dispatch`, `Dispatched`, `Discard` and `Discarded`; the payee
/// (final hop) handles `Commit` and `Committed`. Both peers run the
/// same [`IrohServer`] and dispatch by the tag.
#[derive(Debug, Serialize, Deserialize)]
pub enum Frame {
    Prepare(HopPrepare),
    Prepared(HopPrepared),
    Dispatch(HopDispatch),
    Dispatched(HopDispatched),
    Commit(HopCommit),
    Committed(HopCommitted),
    Discard(HopDiscard),
    Discarded(HopDiscarded),
    Error {
        payment_hash: Bytes32,
        message: String,
    },
}

impl Frame {
    pub fn payment_hash(&self) -> Bytes32 {
        match self {
            Frame::Prepare(m) => m.payment_hash,
            Frame::Prepared(m) => m.payment_hash,
            Frame::Dispatch(m) => m.payment_hash,
            Frame::Dispatched(m) => m.payment_hash,
            Frame::Commit(m) => m.payment_hash,
            Frame::Committed(m) => m.payment_hash,
            Frame::Discard(m) => m.payment_hash,
            Frame::Discarded(m) => m.payment_hash,
            Frame::Error { payment_hash, .. } => *payment_hash,
        }
    }
}

/// Build an [`EndpointAddr`] from a route announcement's iroh fields.
pub fn node_addr_from_announcement(
    ann: &cassis_core::RouteAnnouncement,
) -> Result<EndpointAddr, IrohError> {
    let peer_id =
        PublicKey::from_str(&ann.iroh_peer_id).map_err(|e| IrohError::Io(e.to_string()))?;
    let mut addr = EndpointAddr::new(peer_id);
    if let Some(relay_url) = &ann.iroh_relay {
        let relay = RelayUrl::from_str(relay_url).map_err(|e| IrohError::Io(e.to_string()))?;
        addr = addr.with_relay_url(relay);
    }
    Ok(addr)
}

/// Build an [`EndpointAddr`] for a payee (receiver) from an
/// [`Invoice`](cassis_core::Invoice) that carries optional
/// `iroh_peer_id` / `iroh_relay` fields.
pub fn node_addr_from_invoice(
    peer_id: &str,
    relay: Option<&str>,
) -> Result<EndpointAddr, IrohError> {
    let id = PublicKey::from_str(peer_id).map_err(|e| IrohError::Io(e.to_string()))?;
    let mut addr = EndpointAddr::new(id);
    if let Some(relay_url) = relay {
        let relay = RelayUrl::from_str(relay_url).map_err(|e| IrohError::Io(e.to_string()))?;
        addr = addr.with_relay_url(relay);
    }
    Ok(addr)
}

/// Default iroh relay URL when the node has no home relay.
pub const DEFAULT_IROH_RELAY: &str = "https://euw1-1.relay.iroh.network";

pub use iroh::{EndpointId, PublicKey};

/// Per-request handler. The second argument is the authenticated
/// remote endpoint identity of the connection the frame arrived on,
/// so handlers can bind protocol state (e.g. PREPARE reservations) to
/// the peer that created it.
pub type RequestHandler = Arc<
    dyn Fn(Frame, PublicKey) -> Pin<Box<dyn Future<Output = Result<Frame, IrohError>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct IrohClient {
    endpoint: Endpoint,
}

impl IrohClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Build a new client endpoint with the same defaults as the server.
    pub async fn bind() -> Result<Self, IrohError> {
        debug!(target: "iroh_client", "binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        debug!(target: "iroh_client", "bound peer_id={}", endpoint.id());
        Ok(Self::new(endpoint))
    }

    pub fn peer_id(&self) -> PublicKey {
        self.endpoint.id()
    }

    /// Underlying endpoint; exposed so callers can publish route
    /// announcements or do other transport-level work.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    async fn round_trip(
        &self,
        addr: EndpointAddr,
        send: Frame,
        op: &'static str,
    ) -> Result<Frame, IrohError> {
        let relay = addr.relay_urls().next();
        let direct = addr.ip_addrs().count();
        info!(
            target: "iroh_client",
            "{op}: connecting to {} (relay={:?}, direct_addrs={})...",
            addr.id, relay, direct
        );
        let conn = match self.endpoint.connect(addr, ALPN_PROTOCOL).await {
            Ok(c) => c,
            Err(e) => {
                error!(target: "iroh_client", "connect error: {e}");
                let mut source = e.source();
                while let Some(cause) = source {
                    error!(target: "iroh_client", "  caused by: {cause}");
                    source = cause.source();
                }
                return Err(IrohError::Io(format!("{e:#}")));
            }
        };
        debug!(target: "iroh_client", "{op}: connected, opening bi stream...");

        let (mut writer, mut reader) = conn
            .open_bi()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        debug!(target: "iroh_client", "{op}: stream opened, writing frame...");

        let data = postcard::to_allocvec(&send).map_err(|e| IrohError::Protocol(e.to_string()))?;
        writer
            .write_all(&data)
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let _ = writer.finish();
        debug!(
            target: "iroh_client",
            "{op}: wrote {} byte(s), awaiting response...",
            data.len()
        );

        let buf = match reader.read_to_end(1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                error!(target: "iroh_client", "read_to_end error: {e:?}");
                return Err(IrohError::Io(format!("read error: {e:?}")));
            }
        };
        debug!(
            target: "iroh_client",
            "{op}: got {} byte(s) of response",
            buf.len()
        );

        let frame: Frame =
            postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
        Ok(frame)
    }

    pub async fn send_prepare(
        &self,
        addr: EndpointAddr,
        prepare: HopPrepare,
    ) -> Result<HopPrepared, IrohError> {
        let reply = self
            .round_trip(addr, Frame::Prepare(prepare), "send_prepare")
            .await?;
        match reply {
            Frame::Prepared(m) => Ok(m),
            Frame::Error { message, .. } => Err(IrohError::Protocol(message)),
            other => Err(IrohError::Protocol(format!(
                "send_prepare: unexpected reply frame {:?}",
                other
            ))),
        }
    }

    pub async fn send_dispatch(
        &self,
        addr: EndpointAddr,
        dispatch: HopDispatch,
    ) -> Result<HopDispatched, IrohError> {
        let reply = self
            .round_trip(addr, Frame::Dispatch(dispatch), "send_dispatch")
            .await?;
        match reply {
            Frame::Dispatched(m) => Ok(m),
            Frame::Error { message, .. } => Err(IrohError::Protocol(message)),
            other => Err(IrohError::Protocol(format!(
                "send_dispatch: unexpected reply frame {:?}",
                other
            ))),
        }
    }

    /// Best-effort reservation release. The payer never treats a
    /// failure here as a payment error; it just means the hop keeps
    /// its reservation until its own expiry.
    pub async fn send_discard(
        &self,
        addr: EndpointAddr,
        discard: HopDiscard,
    ) -> Result<HopDiscarded, IrohError> {
        let reply = self
            .round_trip(addr, Frame::Discard(discard), "send_discard")
            .await?;
        match reply {
            Frame::Discarded(m) => Ok(m),
            Frame::Error { message, .. } => Err(IrohError::Protocol(message)),
            other => Err(IrohError::Protocol(format!(
                "send_discard: unexpected reply frame {:?}",
                other
            ))),
        }
    }

    pub async fn send_commit(
        &self,
        addr: EndpointAddr,
        commit: HopCommit,
    ) -> Result<HopCommitted, IrohError> {
        let reply = self
            .round_trip(addr, Frame::Commit(commit), "send_commit")
            .await?;
        match reply {
            Frame::Committed(m) => Ok(m),
            Frame::Error { message, .. } => Err(IrohError::Protocol(message)),
            other => Err(IrohError::Protocol(format!(
                "send_commit: unexpected reply frame {:?}",
                other
            ))),
        }
    }
}

/// Identifier the handler uses to log which direction a frame
/// came from. Useful for routing to a router vs receiver handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    SenderSide,
    ReceiverSide,
}

pub struct IrohServer {
    endpoint: Endpoint,
    home_relay: Option<String>,
}

impl IrohServer {
    pub async fn new(secret_key: SecretKey) -> Result<(Self, SecretKey), IrohError> {
        info!(target: "iroh_server", "binding endpoint with ALPN {:?}", ALPN_PROTOCOL);
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN_PROTOCOL.to_vec()])
            .bind()
            .await
            .map_err(|e| IrohError::Io(e.to_string()))?;
        let key = endpoint.secret_key().clone();
        info!(
            target: "iroh_server",
            "bound peer_id={}, waiting for home relay...",
            endpoint.secret_key().public()
        );
        let home_relay = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            endpoint.online(),
        )
        .await
        {
            Ok(()) => {
                let url = endpoint.addr().relay_urls().next().cloned();
                match url {
                    Some(url) => {
                        info!(target: "iroh_server", "home relay established: {url}");
                        Some(url.to_string())
                    }
                    None => {
                        warn!(target: "iroh_server", "endpoint online but no relay URL available");
                        None
                    }
                }
            }
            Err(_) => {
                warn!(
                    target: "iroh_server",
                    "timed out waiting 10s for home relay to initialize; \
                     incoming relay connections will fail"
                );
                None
            }
        };
        Ok((
            Self {
                endpoint,
                home_relay,
            },
            key,
        ))
    }

    pub fn peer_id(&self) -> PublicKey {
        self.endpoint.secret_key().public()
    }

    pub fn home_relay(&self) -> Option<&str> {
        self.home_relay.as_deref()
    }

    pub async fn run(self, handler: RequestHandler) -> Result<(), IrohError> {
        debug!(target: "iroh_server", "entering accept loop");
        loop {
            debug!(target: "iroh_server", "waiting for incoming connection...");
            let incoming = match self.endpoint.accept().await {
                Some(i) => i,
                None => {
                    error!(target: "iroh_server", "accept() returned None, endpoint closed");
                    return Err(IrohError::Closed);
                }
            };
            debug!(target: "iroh_server", "got incoming, awaiting handshake...");
            let conn = match incoming.await {
                Ok(c) => {
                    debug!(
                        target: "iroh_server",
                        "handshake complete from remote={:?}",
                        c.remote_id()
                    );
                    c
                }
                Err(e) => {
                    warn!(target: "iroh_server", "handshake error: {e}");
                    continue;
                }
            };

            let handler = handler.clone();
            tokio::spawn(async move {
                debug!(target: "iroh_server", "handling new connection");
                if let Err(e) = handle_conn(conn, handler).await {
                    error!(target: "iroh_server", "handle error: {e}");
                } else {
                    debug!(target: "iroh_server", "connection handled successfully");
                }
            });
        }
    }
}

async fn handle_conn(conn: Connection, handler: RequestHandler) -> Result<(), IrohError> {
    debug!(target: "iroh_server", "accept_bi waiting for stream...");
    let (mut writer, mut reader) = conn
        .accept_bi()
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    debug!(target: "iroh_server", "stream opened, reading payload...");

    let buf = reader
        .read_to_end(1024 * 1024)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    debug!(target: "iroh_server", "read {} byte(s) of payload", buf.len());

    let frame: Frame =
        postcard::from_bytes(&buf).map_err(|e| IrohError::Protocol(e.to_string()))?;
    debug!(
        target: "iroh_server",
        "decoded frame, dispatching to handler (payment_hash={})",
        frame.payment_hash()
    );
    let payment_hash = frame.payment_hash();
    // Authenticated transport identity of the requester: iroh's
    // handshake already tied this connection to the peer key, so this
    // is the authoritative "who sent it" for peer-binding checks.
    let remote = conn.remote_id();
    let response = match handler(frame, remote).await {
        Ok(frame) => frame,
        Err(e) => {
            error!(target: "iroh_server", "handler returned error: {e}");
            Frame::Error {
                payment_hash,
                message: e.to_string(),
            }
        }
    };

    let data = postcard::to_allocvec(&response).map_err(|e| IrohError::Protocol(e.to_string()))?;
    debug!(target: "iroh_server", "writing {} byte(s) of response", data.len());
    writer
        .write_all(&data)
        .await
        .map_err(|e| IrohError::Io(e.to_string()))?;
    let _ = writer.finish();
    debug!(target: "iroh_server", "response written and stream finished, waiting for peer to close...");

    // Keep the connection open until the peer (client) closes its side.
    // If we drop `conn` now, the client may see `ConnectionLost` instead
    // of a clean stream FIN.
    let close_reason = conn.closed().await;
    debug!(target: "iroh_server", "connection closed by peer: {close_reason}");

    Ok(())
}

/// Convenience: build a [`HopCommit`] from the wire-level fields a
/// payee needs to claim the final HTLC.
pub fn build_commit(
    payment_hash: Bytes32,
    amount_msat: u64,
    network: NetworkId,
    incoming_deadline: u64,
    incoming_descriptor: HtlcDescriptor,
) -> HopCommit {
    HopCommit {
        payment_hash,
        amount_msat,
        network,
        incoming_deadline,
        incoming_descriptor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_frame_with_cashu_descriptor_round_trips_through_postcard() {
        // Regression: HtlcDescriptor used to be internally-tagged
        // (#[serde(tag, content)]), which postcard cannot
        // deserialize (it needs deserialize_any). DISPATCH frames
        // carry a descriptor, so any multi-hop pay would fail to
        // decode on the router with postcard's WontImplement error
        // and the connection would drop. External tagging round-trips
        // fine.
        let recipient = cassis_core::PubKey::from_bytes([
            0x17, 0x16, 0x2c, 0x92, 0x1d, 0xc4, 0xd2, 0x51, 0x8f, 0x9a, 0x10, 0x1d, 0xb3, 0x36,
            0x95, 0xdf, 0x1a, 0xfb, 0x56, 0xab, 0x82, 0xf5, 0xff, 0x3e, 0x5d, 0xa6, 0xee, 0xc3,
            0xca, 0x5c, 0xd9, 0x17,
        ])
        .expect("valid x-only pubkey");
        let dispatch = Frame::Dispatch(HopDispatch {
            payment_hash: Bytes32([0x42u8; 32]),
            recipient,
            incoming_descriptor: HtlcDescriptor::Cashu {
                proofs_b64: vec!["eyJhbW91bnQiOjF9".into(), "eyJhbW91bnQiOjJ9".into()],
            },
            outgoing_target: Some(HtlcDescriptor::Lightning {
                payment_request: "lnbc...".into(),
            }),
        });
        let bytes = postcard::to_allocvec(&dispatch).expect("encode dispatch");
        let decoded: Frame = postcard::from_bytes(&bytes).expect("decode dispatch");
        match decoded {
            Frame::Dispatch(d) => {
                assert_eq!(d.recipient, recipient);
                assert_eq!(
                    d.incoming_descriptor,
                    HtlcDescriptor::Cashu {
                        proofs_b64: vec!["eyJhbW91bnQiOjF9".into(), "eyJhbW91bnQiOjJ9".into(),],
                    }
                );
                assert_eq!(
                    d.outgoing_target,
                    Some(HtlcDescriptor::Lightning {
                        payment_request: "lnbc...".into(),
                    })
                );
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[test]
    fn commit_frame_with_fedimint_descriptor_round_trips_through_postcard() {
        let commit = Frame::Commit(HopCommit {
            payment_hash: Bytes32([0x24u8; 32]),
            amount_msat: 1234,
            network: NetworkId("fedimint::x".into()),
            incoming_deadline: 1_786_000_000,
            incoming_descriptor: HtlcDescriptor::Fedimint {
                claim_pubkey: "02aa".into(),
                funding_txid: None,
                funding_out_idx: None,
                contract: None,
            },
        });
        let bytes = postcard::to_allocvec(&commit).expect("encode commit");
        let decoded: Frame = postcard::from_bytes(&bytes).expect("decode commit");
        match decoded {
            Frame::Commit(c) => assert_eq!(
                c.incoming_descriptor,
                HtlcDescriptor::Fedimint {
                    claim_pubkey: "02aa".into(),
                    funding_txid: None,
                    funding_out_idx: None,
                    contract: None,
                }
            ),
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}
