import { http } from './client';

/** 环境侦察摘要响应 */
export interface ReconSummary {
  language: string;
  framework: string;
  dependency_count: number;
  entry_point_count: number;
  service_ports: number[] | null;
  db_type: string;
  run_command: string | null;
}

/** 端口信息 */
export interface PortInfo {
  port: number;
  protocol: string;
  description: string;
}

/** 入口文件信息 */
export interface EntryPoint {
  file: string;
  type: string;
  line: number | null;
  routes?: Record<string, unknown>[] | null;
}

/** 完整 RuntimeProfile 响应 */
export interface RuntimeProfile {
  id: string;
  task_id: string;
  project_id: string | null;
  language: string;
  framework: string;
  dependencies: Record<string, string | null> | null;
  run_command: string | null;
  service_ports: PortInfo[] | null;
  entry_points: EntryPoint[] | null;
  db_type: string;
  raw_result: Record<string, unknown> | null;
  created_at: string;
  updated_at: string | null;
}

/** 获取环境侦察摘要 */
export async function getReconSummary(taskId: string) {
  const res = await http.get<ReconSummary>(
    `/tasks/${taskId}/recon/summary`
  );
  return res.data;
}

/** 获取完整 runtime_profile */
export async function getReconProfile(taskId: string) {
  const res = await http.get<RuntimeProfile>(`/tasks/${taskId}/recon`);
  return res.data;
}
