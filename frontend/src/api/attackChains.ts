import { http } from './client';

/** Attack chain node (a verified vulnerability in the DAG). */
export interface AttackChainNode {
  id: string;
  attack_chain_id: string;
  finding_id: string;
  node_id: string;
  label: string;
  asset: string | null;
  vuln_type: string;
  precondition: string | null;
  post_capability: string | null;
  privilege_level: string | null;
  node_order: number;
  created_at: string | null;
}

/** Attack chain edge (directed link between two nodes). */
export interface AttackChainEdge {
  id: string;
  attack_chain_id: string;
  source_node_id: string;
  target_node_id: string;
  condition: string | null;
  action: string | null;
  privilege_escalation: string | null;
  step: number;
  created_at: string | null;
}

/** Complete attack chain (nodes + edges + metadata). */
export interface AttackChain {
  id: string;
  task_id: string;
  name: string;
  final_impact: string | null;
  overall_severity: string;
  overall_cvss: number | null;
  node_count: number;
  edge_count: number;
  is_single_node: boolean;
  nodes: AttackChainNode[];
  edges: AttackChainEdge[];
  created_at: string | null;
  updated_at: string | null;
}

export interface AttackChainListResponse {
  items: AttackChain[];
  total: number;
}

/** Fetch all attack chains for a task. */
export async function listAttackChains(
  taskId: string
): Promise<AttackChainListResponse> {
  const res = await http.get<AttackChainListResponse>(
    `/tasks/${taskId}/attack-chains`
  );
  return res.data;
}

/** Fetch a single attack chain by ID. */
export async function getAttackChain(
  chainId: string
): Promise<AttackChain> {
  const res = await http.get<AttackChain>(`/attack-chains/${chainId}`);
  return res.data;
}
