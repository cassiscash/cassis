# hyperb-cassis-wallet

A [hyperb](https://github.com/hypereffect/hyperb) interface to manage Cassis
wallets, to drop into the admin page of any server that has them. It works
with every network `cassis-networks` supports (one cargo feature each, as in
`cassis-wallet`; `all` turns them all on).

What the page does:

- **Add, edit and remove networks** in a config file: a table of
  `[networks."<id>"]` with a wallet `mnemonic` (made when added) and the
  network's settings. A Cassis home's `config.toml` is one (table `networks`);
  any other TOML file works with a table of any name, and the rest of the file,
  comments included, is left alone. Removing asks first, since the mnemonic goes.
- **Keep them open**: networks are opened, closed and reopened as the file
  changes (also by hand), with the upkeep each network needs.
- **See the internals** of each: kind, status, what its wallet can do, its
  settings, and its mnemonic (on request).
- **Deposit**: deposit addresses, new addresses, peg-in addresses, Lightning
  invoices, redeeming tokens, onboarding.
- **Withdraw**: send, pay a Lightning invoice, take funds out as a token.

## Using it

It lives in the [cassis](https://github.com/andunieee/cassis) repository,
next to the crates it builds on, so take it from there at the same commit as
the other cassis crates you use:

```toml
cassis-core = { git = "https://github.com/andunieee/cassis", rev = "<commit>", default-features = false, features = ["node"] }
hyperb-cassis-wallet = { git = "https://github.com/andunieee/cassis", rev = "<commit>", features = ["cashu"] }
```

Turn on in it the network features you turn on in `cassis-networks` or
`cassis-wallet`: it refuses Lightning networks (LND, bark) it was not built
for. The Cassis daemons
(`cassis-routerd`, `cassis-gateway`) serve it through `cassis-admin`.

The crate brings no transport: the host keeps its session and page.

```rust
let file = ConfigFile::new(home.join("config.toml"), "networks");
let (wallets, networks) = WalletAdmin::open(file, &home, span).await?;
// start what pays and gets paid with `networks`, then:
wallets.attach(host); // a `Host`: gets networks opened and closed later
wallets.offer(&["arkade", "cashu"]); // optional: the kinds the page adds, else all

// per session:
//   send  wallets.signals(&mut drafts)   (the forms' drafts, before the page)
//   draw  wallets.view()                 (in a tab of your page)
//   route actions: if let Some(handled) = wallets.act(&action) { send handled.patch }
//   redraw whenever wallets.updates() fires; hold wallets.watch() while open
```

See the docs at the top of `src/lib.rs` for the list of actions, which carry
what they act on in their payload and can be sent from anywhere
(`hypb action <address> wallet.send --payload '{"id":…,"to":…,"amount_sat":…}'`).

Elements are `hw/…` and signals live under `hw`; it needs hypereffect 0.6.
