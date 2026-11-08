# Shared settings of the live-test scripts; source it.
#
# Everything they create lives under $LIVE (default <workspace>/tmp/live),
# which is git-ignored: node homes, mints, fedimintd and arkd data, binaries.
LIVE_SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$LIVE_SCRIPTS/../.." && pwd)"
LIVE="${LIVE:-$WORKSPACE/tmp/live}"
BIN="$LIVE/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"

# Public mutinynet ledgers.
MUTINYNET_ESPLORA="https://mutinynet.com/api"
MUTINYNET_FEDIMINT="fedimint::fed11qgqzc2nhwden5te0vejkg6tdd9h8gepwvejkg6tdd9h8garhduhx6at5d9h8jmn9wshxxmmd9uqqzgxg6s3evnr6m9zdxr6hxkdkukexpcs3mn7mj3g5pc5dfh63l4tj6g9zk4er"
MUTINYNET_CASHU="cashu::cashu.mutinynet.com"
MUTINYNET_ARKADE="arkade::mutinynet"

# The networks of the live routes (README.md).
M1="cashu::127.0.0.1:3338"
M2="cashu::127.0.0.1:3339"
MM="$MUTINYNET_CASHU"
R="rootstock::testnet"
A="$MUTINYNET_ARKADE"
AL="arkade::127.0.0.1:7070"
# Our federation, known once it ran DKG (scripts/live/fedimint.sh).
fedimint_network() { echo "fedimint::$(tr -d '[:space:]' < "$LIVE/fedimint/invite-code")"; }

# Private relay for route announcements (scripts/live/relay.sh).
RELAY_PORT=10547
RELAY="ws://localhost:$RELAY_PORT"

# Binaries built from this workspace, and hypb, built from the hyperb
# repository (`cargo install --path crates/cli`).
if [ -z "${CASSIS_WALLET:-}" ] || [ -z "${CASSIS_ROUTERD:-}" ] ||
  [ -z "${CASSIS_GATEWAY:-}" ] || [ -z "${CASSIS_PREIMAGE_SERVER:-}" ]; then
  TARGET="$(cd "$WORKSPACE" && cargo metadata --format-version 1 --no-deps |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug"
  CASSIS_WALLET="${CASSIS_WALLET:-$TARGET/cassis-wallet}"
  CASSIS_ROUTERD="${CASSIS_ROUTERD:-$TARGET/cassis-routerd}"
  CASSIS_GATEWAY="${CASSIS_GATEWAY:-$TARGET/cassis-gateway}"
  CASSIS_PREIMAGE_SERVER="${CASSIS_PREIMAGE_SERVER:-$TARGET/cassis-preimage-server}"
fi
HYPB="${HYPB:-hypb}"

# Whether the node `$LIVE/nodes/<name>` has a live process.
running() {
  [ -f "$LIVE/nodes/$1.pid" ] && kill -0 "$(cat "$LIVE/nodes/$1.pid")" 2> /dev/null
}

# Whether `$LIVE/nodes/<name>` is a daemon running now: its wallets are
# then in its hands, and reached through its admin interface.
daemon_up() { [ -f "$LIVE/nodes/$1/config.toml" ] && running "$1"; }

# cassis-wallet against the node home `$LIVE/nodes/<name>`.
cassis() {
  local name="$1"
  shift
  if daemon_up "$name"; then
    echo "$name is a running daemon, which holds its wallets: use its admin interface (node.sh)" >&2
    return 1
  fi
  "$CASSIS_WALLET" --home "$LIVE/nodes/$name" "$@"
}

# The loopback port of a daemon's admin interface: all of them default
# to the same few, and one that finds its port taken keeps running without.
admin_port() {
  case "$1" in
    gateway) echo 7980 ;;
    preimage) echo 7981 ;;
    r[0-9]*) echo $((7100 + ${1#r})) ;;
    *) echo "$1: no admin port for that name" >&2; return 1 ;;
  esac
}

# Start the daemon `$LIVE/nodes/<name>`, `binary <flag> <home>`, with its
# log at $LIVE/nodes/<name>.log, and wait for its admin interface, which
# only comes up once its networks opened.
start_daemon() {
  local name="$1" binary="$2" flag="$3" port waited=0
  local log="$LIVE/nodes/$name.log" pidfile="$LIVE/nodes/$name.pid"
  port="$(admin_port "$name")"
  if running "$name"; then
    echo "$name already running (pid $(cat "$pidfile"))"
    return 0
  fi
  if (: < "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
    echo "$name: something else listens on its admin port $port" >&2
    return 1
  fi
  if [ ! -x "$binary" ]; then
    echo "$binary is missing: cargo build it" >&2
    return 1
  fi
  mkdir -p "$LIVE/nodes/$name"
  nohup "$binary" "$flag" "$LIVE/nodes/$name" >> "$log" 2>&1 &
  echo $! > "$pidfile"
  until (: < "/dev/tcp/127.0.0.1/$port") 2> /dev/null; do
    if ! running "$name" || [ "$waited" -ge 600 ]; then
      echo "$name did not come up; the end of $log:" >&2
      grep -v DEBUG "$log" | tail -5 >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "$name running (pid $(cat "$pidfile")), admin on hyperb://localhost:$port, log at $log"
}

# What the admin_* functions run in their hypb session.
ADMIN_JS='
function fail(message) { throw new Error(message); }
// Send an action and wait for its outcome: failures only show on the page.
function act(name, payload) {
  action(name, payload);
  const notice = wait(m => m.kind == "element" && m.id == "result").element.attrs;
  if (notice.variant == "failure") fail(name + ": " + notice.text);
  return notice.text;
}
// What check() returns once it is not undefined, asking again until then.
function until(check, secs) {
  const end = Date.now() + secs * 1000;
  while (true) {
    const value = check();
    if (value !== undefined) return value;
    if (Date.now() > end) fail("still waiting after " + secs + "s");
    sleep(500);
  }
}
// The text of the element under a network, if it is there.
function under(id, part) {
  const found = element("network/" + id + "/" + part);
  return found ? found.attrs : undefined;
}
// Wait for the wallet of a network to be done, returning its last outcome.
function outcome(id, secs) {
  const last = until(() => {
    if (under(id, "wallet/busy") || under(id, "wallet/waiting")) return undefined;
    return under(id, "wallet/outcome");
  }, secs);
  if (last.variant == "failure") fail(id + ": " + last.text);
  return last.text;
}
'

# Run JavaScript against the admin interface of daemon <name>.
admin_js() {
  "$HYPB" run "hyperb://localhost:$(admin_port "$1")" --timeout 60000 -e "$ADMIN_JS
$2"
}

# admin_act <name> <action> [json payload]: send an action, failing if it fails.
admin_act() {
  admin_js "$1" "console.error(\"$1: \" + act(\"$2\", ${3:-null}));"
}

# admin_text <name> <element id>: the text of an element of the page.
admin_text() {
  admin_js "$1" "const found = element(\"$2\");
    if (!found) fail(\"$1 has no element $2\");
    print(found.attrs.text);"
}

# network_open <name> <network> [secs]: wait until a daemon opened it.
network_open() {
  admin_js "$1" "until(() => {
    const status = under(\"$2\", \"status\");
    if (status && status.variant == \"failure\") fail(\"$2: \" + status.text);
    return status && status.text == \"open\" ? true : undefined;
  }, ${3:-600});"
}

# wallet_op <name> <network> <op> [extra json fields] [secs]: run a
# `wallet.<op>` to its outcome, printing what it handed out if anything.
wallet_op() {
  local name="$1" id="$2" op="$3" fields="${4:-}" secs="${5:-600}"
  admin_act "$name" wallet.dismiss "{\"id\":\"$id\"}" 2> /dev/null
  admin_js "$name" "act(\"wallet.$op\", {\"id\":\"$id\"${fields:+,$fields}});
    until(() => under(\"$id\", \"wallet/busy\") ? undefined : under(\"$id\", \"wallet/outcome\") || undefined, $secs);
    const last = under(\"$id\", \"wallet/outcome\");
    if (last.variant == \"failure\") fail(\"$id: \" + last.text);
    console.error(\"$name: \" + last.text);
    const output = under(\"$id\", \"wallet/output/value\");
    if (output) print(output.text);"
}

# wallet_done <name> <network> [secs]: wait for what the last wallet_op
# left waiting (a deposit), failing if that failed.
wallet_done() {
  admin_js "$1" "console.error(\"$1: \" + outcome(\"$2\", ${3:-3600}));"
}

# wallet_balance <name> <network>: what the wallet holds, read now.
wallet_balance() {
  admin_js "$1" "const id = \"$2\";
    act(\"wallet.refresh\", {id});
    sleep(1000);
    until(() => {
      const read = under(id, \"wallet/read/when\");
      return read && read.text.startsWith(\"Read \") ? true : undefined;
    }, 120);
    const error = under(id, \"wallet/balances/error\");
    if (error) fail(id + \": \" + error.text);
    for (let i = 0; under(id, \"wallet/balance/\" + i + \"/amount\"); i++) {
      print(under(id, \"wallet/balance/\" + i + \"/label\").text + \": \"
        + under(id, \"wallet/balance/\" + i + \"/amount\").text);
    }"
}

# wallet_address <name> <network> <label start>: its deposit address
# under a label starting that way: Rootstock, Bitcoin, Boarding, Arkade...
wallet_address() {
  admin_js "$1" "const id = \"$2\";
    act(\"wallet.refresh\", {id});
    print(until(() => {
      const error = under(id, \"wallet/addresses/error\");
      if (error) fail(id + \": \" + error.text);
      for (let i = 0; under(id, \"wallet/address/\" + i + \"/label\"); i++) {
        if (under(id, \"wallet/address/\" + i + \"/label\").text.startsWith(\"$3\")) {
          return under(id, \"wallet/address/\" + i + \"/value\").text;
        }
      }
      return undefined;
    }, 120));"
}
