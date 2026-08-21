import { useCallback, useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Node as RfNode,
  type Edge as RfEdge,
  type NodeChange,
  applyNodeChanges,
} from "@xyflow/react";
import { invoke } from "@tauri-apps/api/core";
import { MAX_NODES, type Network, type Node } from "./types";

type RfData = Record<string, unknown>;

function networkRect(n: Network): RfNode<RfData> {
  // Prearranged positions (canvas coordinates).
  const positions: Record<string, { x: number; y: number }> = {
    cashu1: { x: 40, y: 40 },
    cashu2: { x: 320, y: 40 },
    cashu3: { x: 600, y: 40 },
    rootstock_testnet: { x: 40, y: 320 },
  };
  return {
    id: `net:${n.id}`,
    type: "network",
    position: positions[n.id] ?? { x: 40, y: 40 },
    data: { network: n },
    style: { width: 240, height: 220 },
    draggable: true,
    selectable: true,
  };
}

function peerNode(p: Node, idx: number): RfNode<RfData> {
  return {
    id: `peer:${p.id}`,
    type: "peer",
    position: { x: 100 + idx * 10, y: 100 + idx * 10 },
    data: { peer: p },
    style: {
      width: 60,
      height: 60,
      borderRadius: "50%",
      background: p.color,
      color: "#fff",
      fontWeight: 700,
      fontSize: 10,
    },
    draggable: true,
  };
}

interface Props {
  networks: Network[];
  nodes: Node[];
  setNodes: (n: Node[]) => void;
}

export default function Canvas({ networks, nodes, setNodes }: Props) {
  // Initial layout
  const initial: RfNode<RfData>[] = useMemo(
    () => [
      ...networks.map(networkRect),
      ...nodes.map((p, i) => peerNode(p, i)),
    ],
    // only on first mount — react-flow nodes are otherwise user-controlled
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const [rfNodes, setRfNodes] = useState<RfNode<RfData>[]>(initial);

  const onNodesChange = useCallback(
    (changes: NodeChange<RfNode<RfData>>[]) => {
      setRfNodes((curr) => {
        const next = applyNodeChanges(changes, curr);
        // Pull membership info back from React Flow into our Node model
        // when nodes get dragged into a network rectangle. For now we only
        // keep positions; membership is managed via the sidebar commands.
        return next;
      });
    },
    [],
  );

  const nodeTypes = useMemo(
    () => ({
      network: ({ data }: { data: RfData }) => {
        const n = data.network as Network;
        return (
          <div className="network-rect">
            {n.label}
            <div style={{ fontSize: 10, fontWeight: 400, color: "#374151" }}>
              {n.kind === "cashu"
                ? `mint on :${n.port}`
                : "phantom network (no mint)"}
            </div>
          </div>
        );
      },
      peer: ({ data }: { data: RfData }) => {
        const p = data.peer as Node;
        return <div className="peer-circle">{p.label}</div>;
      },
    }),
    [],
  );

  const edges: RfEdge[] = [];

  return (
    <div className="canvas-host" style={{ width: "100%", height: "100%" }}>
      <ReactFlow
        nodes={rfNodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
        <MiniMap pannable zoomable />
        <Controls />
      </ReactFlow>
      <div className="legend">
        {nodes.length}/{MAX_NODES} nodes · drag the canvas to pan, scroll to zoom
      </div>
    </div>
  );
}
