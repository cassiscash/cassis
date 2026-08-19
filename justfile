# ---- configuration ---------------------------------------------------------

# Global knobs ---------------------------------------------------------------
CASSIS  := "target/debug/cassis-cli"
RELAY    := "ws://localhost:10547"
RSK_SEED := "tmp/rsk-seed"

# Mints (cdk-mintd) ----------------------------------------------------------
MINT1_DIR := "tmp/mint1"
MINT2_DIR := "tmp/mint2"
MINT3_DIR := "tmp/mint3"
MINT1_URL := "http://127.0.0.1:8091"
MINT2_URL := "http://127.0.0.1:8092"
MINT3_URL := "http://127.0.0.1:8093"

# Routers (cassis-cli router) -----------------------------------------------
R1_DIR := "tmp/router1"  # mint1 <-> mint2
R2_DIR := "tmp/router2"  # mint2 <-> rootstock::testnet  (seed = copy of rsk-seed)
R3_DIR := "tmp/router3"  # rootstock::testnet <-> mint3

# Users (cassis-cli wallets) -------------------------------------------------
U1_DIR := "tmp/user1"    # at mint1
U3_DIR := "tmp/user3"    # at mint3

# cdk-cli mint wallets -------------------------------------------------------
CDK1_DIR := "tmp/cdk1"
CDK2_DIR := "tmp/cdk2"
CDK3_DIR := "tmp/cdk3"

# ---- recipes ---------------------------------------------------------------

# Build the CLI with the cashu + rootstock features
build:
  cargo build -p cassis-cli --features cashu,rootstock

# Fresh dirs + seeds for mints, routers, users and cdk wallets.
# Wipes previous stores so a re-run starts clean (new seeds = new wallets).
setup:
  mkdir -p {{MINT1_DIR}} {{MINT2_DIR}} {{MINT3_DIR}}
  mkdir -p {{R1_DIR}} {{R2_DIR}} {{R3_DIR}}
  mkdir -p {{U1_DIR}} {{U3_DIR}}
  mkdir -p {{CDK1_DIR}} {{CDK2_DIR}} {{CDK3_DIR}}
  # stale stores would leave unspendable proofs / stale routing state
  rm -f {{R1_DIR}}/store.db {{R2_DIR}}/store.db {{R3_DIR}}/store.db
  rm -f {{U1_DIR}}/store.db {{U3_DIR}}/store.db
  # shared mint seed (deterministic across runs)
  printf 'hire movie pyramid only journey sun eight stadium salt engage inmate enlist\n' > {{MINT1_DIR}}/seed
  cp {{MINT1_DIR}}/seed {{MINT2_DIR}}/seed
  cp {{MINT1_DIR}}/seed {{MINT3_DIR}}/seed
  # routers: fresh seeds, except router2 reuses rsk-seed (rootstock funder)
  {{CASSIS}} --home {{R1_DIR}} seed init --force
  cp {{RSK_SEED}} {{R2_DIR}}/seed
  {{CASSIS}} --home {{R3_DIR}} seed init --force
  # users: fresh seeds
  {{CASSIS}} --home {{U1_DIR}} seed init --force
  {{CASSIS}} --home {{U3_DIR}} seed init --force
  @echo "setup done"

# Start the local Nostr relay (nak serve)
relay:
  nak serve --port 10547

# Start a cdk-mintd (usage: just mint 1|2|3)
mint n:
  @test -f tmp/mint{{n}}/seed
  @echo "minting on :809{{n}}"
  CDK_MINTD_LISTEN_PORT=809{{n}} \
  CDK_MINTD_LISTEN_HOST=127.0.0.1 \
  CDK_MINTD_LN_BACKEND=fakewallet \
  CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS=sat \
  CDK_MINTD_FAKE_WALLET_FEE_PERCENT=0 \
  CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN=0 \
  cdk-mintd -w tmp/mint{{n}} --seed-file tmp/mint{{n}}/seed --enable-logging

# Start a router (usage: just router 1|2|3)
router n:
  @case {{n}} in \
    1) a="cashu::127.0.0.1:8091"; b="cashu::127.0.0.1:8092"; home={{R1_DIR}};; \
    2) a="cashu::127.0.0.1:8092"; b="rootstock::testnet"; home={{R2_DIR}};; \
    3) a="rootstock::testnet"; b="cashu::127.0.0.1:8093"; home={{R3_DIR}};; \
    *) echo "router must be 1, 2 or 3"; exit 1;; \
  esac; \
  echo "routing ($home): $a <-> $b"; \
  {{CASSIS}} router --home "$home" --network "$a" --network "$b" --nostr-relay {{RELAY}}

# Interactive shell for a user (usage: just user 1|3)
user n:
  @export CASSIS_HOME=tmp/user{{n}}; echo "cassis user at mint{{n}} ($CASSIS_HOME)"; exec $$SHELL

# Mint money and deliver to the cli users + fund the rsk leg (runs once mints are up)
fund:
  bash scripts/rsk-ctrl.sh

# Open a tmux session with the full topology (relay, mints, routers,
# users, ctrl). One window per service. Works headless and interactive.
dev: build setup
  tmux kill-session -t cassis 2>/dev/null || true
  tmux new-session -d -s cassis -x 220 -y 55
  tmux set-option -t cassis remain-on-exit on
  # relay
  tmux rename-window -t cassis:0 relay
  tmux send-keys -t cassis:relay "nak serve --port 10547" C-m
  # mints
  tmux new-window -t cassis -n mint1
  tmux send-keys -t cassis:mint1 "CDK_MINTD_LISTEN_PORT=8091 CDK_MINTD_LISTEN_HOST=127.0.0.1 CDK_MINTD_LN_BACKEND=fakewallet CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS=sat CDK_MINTD_FAKE_WALLET_FEE_PERCENT=0 CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN=0 cdk-mintd -w tmp/mint1 --seed-file tmp/mint1/seed --enable-logging" C-m
  tmux new-window -t cassis -n mint2
  tmux send-keys -t cassis:mint2 "CDK_MINTD_LISTEN_PORT=8092 CDK_MINTD_LISTEN_HOST=127.0.0.1 CDK_MINTD_LN_BACKEND=fakewallet CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS=sat CDK_MINTD_FAKE_WALLET_FEE_PERCENT=0 CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN=0 cdk-mintd -w tmp/mint2 --seed-file tmp/mint2/seed --enable-logging" C-m
  tmux new-window -t cassis -n mint3
  tmux send-keys -t cassis:mint3 "CDK_MINTD_LISTEN_PORT=8093 CDK_MINTD_LISTEN_HOST=127.0.0.1 CDK_MINTD_LN_BACKEND=fakewallet CDK_MINTD_FAKE_WALLET_SUPPORTED_UNITS=sat CDK_MINTD_FAKE_WALLET_FEE_PERCENT=0 CDK_MINTD_FAKE_WALLET_RESERVE_FEE_MIN=0 cdk-mintd -w tmp/mint3 --seed-file tmp/mint3/seed --enable-logging" C-m
  # routers
  tmux new-window -t cassis -n router1
  tmux send-keys -t cassis:router1 "target/debug/cassis-cli router --home tmp/router1 --network cashu::127.0.0.1:8091 --network cashu::127.0.0.1:8092 --nostr-relay ws://localhost:10547" C-m
  tmux new-window -t cassis -n router2
  tmux send-keys -t cassis:router2 "target/debug/cassis-cli router --home tmp/router2 --network cashu::127.0.0.1:8092 --network rootstock::testnet --nostr-relay ws://localhost:10547" C-m
  tmux new-window -t cassis -n router3
  tmux send-keys -t cassis:router3 "target/debug/cassis-cli router --home tmp/router3 --network rootstock::testnet --network cashu::127.0.0.1:8093 --nostr-relay ws://localhost:10547" C-m
  # users (interactive shells with their wallet home exported)
  tmux new-window -t cassis -n user1
  tmux send-keys -t cassis:user1 "export CASSIS_HOME=tmp/user1; echo 'cassis user at mint1'; exec bash -i" C-m
  tmux new-window -t cassis -n user3
  tmux send-keys -t cassis:user3 "export CASSIS_HOME=tmp/user3; echo 'cassis user at mint3'; exec bash -i" C-m
  # control: wait for mints, fund users + rsk leg, keep pane open
  tmux new-window -t cassis -n ctrl
  tmux send-keys -t cassis:ctrl "bash scripts/rsk-ctrl.sh" C-m
  # focus the ctrl window, then attach (attaches only when a TTY is present)
  tmux select-window -t cassis:ctrl
  tmux attach -t cassis || true

# Kill the tmux session (stops relay, mints, routers in their panes)
down:
  tmux kill-session -t cassis || true

# Show which cassis-cli services are running
status:
  pgrep -af "cassis-cli (router|cashu|receive|rootstock)" || true
  pgrep -af "cdk-mintd" || true
  pgrep -af "nak serve" || true

# Show user wallet balances
balances:
  {{CASSIS}} --home {{U1_DIR}} cashu balance --network cashu::127.0.0.1:8091
  {{CASSIS}} --home {{U3_DIR}} cashu balance --network cashu::127.0.0.1:8093
  @echo "---- router rootstock addresses ----"
  {{CASSIS}} --home {{R2_DIR}} rootstock --network rootstock::testnet info || true
  {{CASSIS}} --home {{R3_DIR}} rootstock --network rootstock::testnet info || true

# Remove all generated runtime dirs (data loss)
clean:
  rm -rf {{MINT1_DIR}} {{MINT2_DIR}} {{MINT3_DIR}}
  rm -rf {{R1_DIR}} {{R2_DIR}} {{R3_DIR}}
  rm -rf {{U1_DIR}} {{U3_DIR}}
  rm -rf {{CDK1_DIR}} {{CDK2_DIR}} {{CDK3_DIR}}

default:
  @just --list
