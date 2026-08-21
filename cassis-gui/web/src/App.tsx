import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Canvas from "./canvas";
import Sidebar from "./sidebar";
import type { Network, Node } from "./types";

export default function App() {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [output, setOutput] = useState<string>("");
  const outRef = useRef<HTMLPreElement>(null);

  // Always scroll the output pane to the bottom on append.
  useEffect(() => {
    if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight;
  }, [output]);

  useEffect(() => {
    (async () => {
      try {
        const ns = (await invoke("list_networks")) as Network[];
        setNetworks(ns);
        const ps = (await invoke("list_nodes")) as Node[];
        setNodes(ps);
      } catch (e) {
        pushOutput(`init: ${String(e)}\n`);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pushOutput = (line: string) =>
    setOutput((o) => o + line);

  return (
    <div className="app">
      <aside className="sidebar">
        <Sidebar
          networks={networks}
          nodes={nodes}
          setNodes={setNodes}
          pushOutput={pushOutput}
        />
        <h2>log</h2>
        <pre className="output" ref={outRef}>
          {output || "(no output yet)"}
        </pre>
      </aside>
      <main>
        <Canvas networks={networks} nodes={nodes} setNodes={setNodes} />
      </main>
    </div>
  );
}
