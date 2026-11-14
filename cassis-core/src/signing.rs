//! The canonical bytes every Cassis signature covers.
//!
//! Each signed statement is written field by field, in a fixed order,
//! with the rules below, never through serde, so its bytes depend only
//! on the values signed (see `SPEC.md`, "Signatures"):
//!
//! * the message starts with its domain, a length-prefixed ASCII tag
//!   naming the statement and its version;
//! * integers are 8 bytes big-endian;
//! * keys, hashes and signatures are their raw fixed-size bytes;
//! * strings and byte strings are a 4-byte big-endian length, then the
//!   bytes (strings in UTF-8);
//! * lists are a 4-byte big-endian count, then each item;
//! * optional values are a byte `0` when absent, or `1` and the value;
//! * enumerations are one tag byte, then the variant's fields.

use crate::network::{InvoiceTarget, LightningTarget};
use crate::primitives::Bytes32;
use iroh_base::PublicKey;

/// A message being written for signing.
pub struct SigningMessage(Vec<u8>);

impl SigningMessage {
    /// A message for the statement `domain`.
    pub fn new(domain: &str) -> Self {
        let mut message = Self(Vec::new());
        message.str(domain);
        message
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Fixed-size bytes, with no length.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn bytes32(&mut self, value: &Bytes32) -> &mut Self {
        self.raw(&value.0)
    }

    /// An Ed25519 (iroh) public key: 32 bytes.
    pub fn key(&mut self, key: &PublicKey) -> &mut Self {
        self.raw(key.as_bytes())
    }

    /// Length-prefixed bytes.
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.length(bytes.len());
        self.raw(bytes)
    }

    /// Length-prefixed UTF-8.
    pub fn str(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    /// The count of a list whose items follow.
    pub fn count(&mut self, count: usize) -> &mut Self {
        self.length(count);
        self
    }

    /// `0`, or `1` and the value written by `write`.
    pub fn option<T>(
        &mut self,
        value: Option<T>,
        write: impl FnOnce(&mut Self, T) -> &mut Self,
    ) -> &mut Self {
        match value {
            None => self.u8(0),
            Some(value) => write(self.u8(1), value),
        }
    }

    /// What an HTLC is locked to: the network, then tag `0` and a
    /// 32-byte x-only key, tag `1` and a 33-byte compressed key, or tag
    /// `2` and a BOLT11 string.
    pub fn invoice_target<L: LightningTarget>(&mut self, target: &InvoiceTarget<L>) -> &mut Self {
        self.str(&target.network().0);
        match target {
            InvoiceTarget::Cashu { target, .. }
            | InvoiceTarget::Fedimint { target, .. }
            | InvoiceTarget::Arkade { target, .. }
            | InvoiceTarget::Bitcoin { target, .. } => self.u8(0).raw(&target.0),
            InvoiceTarget::Liquid { target, .. } | InvoiceTarget::Rootstock { target, .. } => {
                self.u8(1).raw(target.as_bytes())
            }
            InvoiceTarget::Lightning { invoice, .. } => self.u8(2).str(invoice.invoice()),
        }
    }

    fn length(&mut self, length: usize) {
        let length = u32::try_from(length).expect("signed fields are under 4 GiB");
        self.0.extend_from_slice(&length.to_be_bytes());
    }
}
