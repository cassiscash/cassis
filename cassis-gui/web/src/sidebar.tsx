import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { MAX_NODES, type Network, type Node } from "./types";

interface Props {
  networks: Network[];
  nodes: Node[];
  setNodes: (n: Node[]) => void;
  pushOutput: (line: string) => void;
}

export default function Sidebar({ networks, nodes, setNodes, pushOutput }: Props) {
  // Form state for commands
  const [newLabel, setNewLabel] = useState("");
  const [newColor, setNewColor] = useState("");
  const [newNets, setNewNets] = useState<string[]>([]);
  const [addNetNodeId, setAddNetNodeId] = useState("");
  const [addNetNetId, setAddNetNetId] = useState("");
  const [moneyNodeId, setMoneyNodeId] = useState("");
  const [moneyNetId, setMoneyNetId] = useState("");
  const [moneyAmt, setMoneyAmt] = useState(1000);
  const [routeFrom, setRouteFrom] = useState("");
  const [routeTo, setRouteTo] = useState("");
  const [invNodeId, setInvNodeId] = useState("");
  const [invNetId, setInvNetId] = useState("");
  const [invAmount, setInvAmount] = useState(1000);
  const [listenNodeId, setListenNodeId] = useState("");
  const [payFromNodeId, setPayFromNodeId] = useState("");
  const [payInvoice, setPayInvoice] = useState("");

  const run = async (
    label: string,
    fn: (() => Promise<unknown>) | Promise<unknown>,
  ) => {
    pushOutput(`> ${label}\n`);
    try {
      const out = typeof fn === "function" ? await fn() : await fn;
      const text = typeof out === "string" ? out : JSON.stringify(out, null, 2);
      pushOutput(text + "\n");
    } catch (e: unknown) {
      const msg =
        typeof e === "object" && e && "message" in e
          ? String((e as { message: unknown }).message)
          : String(e);
      pushOutput(`error: ${msg}\n`);
    }
  };

  return (
    <div className="sidebar">
      <h1>cassis gui</h1>

      <h2>infrastructure</h2>
      <button onClick={() => run("bootstrap", invoke("bootstrap"))}>
        bootstrap (start relay + mints)
      </button>

      <h2>nodes</h2>
      <label>label</label>
      <input
        placeholder={`node ${nodes.length + 1}`}
        value={newLabel}
        onChange={(e) => setNewLabel(e.target.value)}
      />
      <label>color (optional)</label>
      <input
        placeholder="#e6194B"
        value={newColor}
        onChange={(e) => setNewColor(e.target.value)}
      />
      <label>memberships</label>
      <select
        multiple
        value={newNets}
        onChange={(e) =>
          setNewNets(
            Array.from(e.target.selectedOptions).map((o) => o.value),
          )
        }
        style={{ height: 64 }}
      >
        {networks.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <button
        disabled={nodes.length >= MAX_NODES}
        onClick={async () => {
          await run("add node", async () => {
            const node = (await invoke("add_node", {
              args: { label: newLabel, color: newColor || null, networks: newNets },
            })) as Node;
            setNodes([...nodes, node]);
            setNewLabel("");
            setNewColor("");
            setNewNets([]);
            return `node ${node.id} added`;
          });
        }}
      >
        add node to network
      </button>

      <label>node</label>
      <select value={addNetNodeId} onChange={(e) => setAddNetNodeId(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>network</label>
      <select value={addNetNetId} onChange={(e) => setAddNetNetId(e.target.value)}>
        <option value="">…</option>
        {networks.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <button
        disabled={!addNetNodeId || !addNetNetId}
        onClick={() =>
          run(
            "add node to network",
            async () => {
              const updated = (await invoke("add_node_to_network", {
                args: { node_id: addNetNodeId, network_id: addNetNetId },
              })) as Node;
              setNodes(nodes.map((n) => (n.id === updated.id ? updated : n)));
              return `node now in ${updated.memberships.length} network(s)`;
            },
          )
        }
      >
        add node to network
      </button>
      <button
        disabled={!addNetNodeId || !addNetNetId}
        onClick={() =>
          run(
            "remove node from network",
            async () => {
              const updated = (await invoke("remove_node_from_network", {
                args: { node_id: addNetNodeId, network_id: addNetNetId },
              })) as Node;
              setNodes(nodes.map((n) => (n.id === updated.id ? updated : n)));
              return `node removed from network`;
            },
          )
        }
      >
        remove node from network
      </button>

      <h2>money</h2>
      <label>node</label>
      <select value={moneyNodeId} onChange={(e) => setMoneyNodeId(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>network (cashu mint)</label>
      <select value={moneyNetId} onChange={(e) => setMoneyNetId(e.target.value)}>
        <option value="">…</option>
        {networks
          .filter((n) => n.kind === "cashu")
          .map((n) => (
            <option key={n.id} value={n.id}>
              {n.label}
            </option>
          ))}
      </select>
      <label>amount (sats)</label>
      <input
        type="number"
        min={1}
        value={moneyAmt}
        onChange={(e) => setMoneyAmt(Number(e.target.value))}
      />
      <button
        disabled={!moneyNodeId || !moneyNetId}
        onClick={() =>
          run(
            "give money to node",
            invoke("give_money_to_node", {
              args: { node_id: moneyNodeId, network_id: moneyNetId, amount: moneyAmt },
            }),
          )
        }
      >
        give money to node
      </button>

      <h2>routing</h2>
      <button
        disabled={!addNetNodeId}
        onClick={() =>
          run(
            "start node router",
            invoke("start_router", { args: { node_id: addNetNodeId } }),
          )
        }
      >
        start node router
      </button>

      <label>from node</label>
      <select value={routeFrom} onChange={(e) => setRouteFrom(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>to node</label>
      <select value={routeTo} onChange={(e) => setRouteTo(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <button
        disabled={!routeFrom || !routeTo}
        onClick={() =>
          run(
            "display routes",
            invoke("list_routes", { args: { from: routeFrom, to: routeTo } }),
          )
        }
      >
        display possible routes
      </button>

      <h2>payments</h2>
      <label>node (receiver)</label>
      <select value={invNodeId} onChange={(e) => setInvNodeId(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>network</label>
      <select value={invNetId} onChange={(e) => setInvNetId(e.target.value)}>
        <option value="">…</option>
        {networks.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>amount (msat)</label>
      <input
        type="number"
        min={1}
        value={invAmount}
        onChange={(e) => setInvAmount(Number(e.target.value))}
      />
      <button
        disabled={!invNodeId || !invNetId}
        onClick={() =>
          run(
            "create invoice",
            invoke("create_invoice", {
              args: { node_id: invNodeId, network_id: invNetId, amount_msat: invAmount },
            }),
          )
        }
      >
        create invoice on node
      </button>

      <label>node (listener)</label>
      <select value={listenNodeId} onChange={(e) => setListenNodeId(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <button
        disabled={!listenNodeId}
        onClick={() =>
          run(
            "start listener",
            invoke("start_listener", { args: { node_id: listenNodeId } }),
          )
        }
      >
        start listening for invoice payments
      </button>

      <label>from node (payer)</label>
      <select value={payFromNodeId} onChange={(e) => setPayFromNodeId(e.target.value)}>
        <option value="">…</option>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.label}
          </option>
        ))}
      </select>
      <label>invoice json</label>
      <textarea
        rows={4}
        value={payInvoice}
        onChange={(e) => setPayInvoice(e.target.value)}
        style={{ width: "100%", fontSize: 11, fontFamily: "ui-monospace, monospace" }}
      />
      <button
        disabled={!payFromNodeId || !payInvoice}
        onClick={() =>
          run(
            "pay invoice",
            invoke("pay_invoice", {
              args: { from_node_id: payFromNodeId, invoice_json: payInvoice },
            }),
          )
        }
      >
        pay invoice from node
      </button>
    </div>
  );
}
