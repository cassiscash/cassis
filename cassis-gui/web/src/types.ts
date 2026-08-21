export type NetworkKind = "cashu" | "rootstock";

export interface Network {
  id: string;
  label: string;
  kind: NetworkKind;
  port: number | null;
  mint_url: string | null;
}

export interface Node {
  id: string;
  label: string;
  color: string;
  memberships: string[];
  router_pid: number | null;
  listener_pid: number | null;
}

export const MAX_NODES = 10;
