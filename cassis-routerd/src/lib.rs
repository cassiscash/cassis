//! The router: answers the hop requests of payers on the endpoint and
//! networks of a wallet [`Node`](cassis_wallet::Node) (see [`router`]),
//! journaling its hops in `<data dir>/router.redb` (see [`db`]). The
//! `cassis-routerd` daemon runs it from its config.

pub mod db;
pub mod router;
