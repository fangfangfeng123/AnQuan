import { http } from './client';

/** 沙箱运行状态响应 */
export interface SandboxStatus {
  sandbox_id: string | null;
  container_id: string | null;
  db_status: string;
  docker_status: string;
  image: string | null;
  created_at: string | null;
  ready_at: string | null;
  destroyed_at: string | null;
}

/** 沙箱资源使用统计 */
export interface SandboxStats {
  cpu_percent: number;
  memory_usage_mb: number;
  memory_limit_mb: number;
  memory_percent: number;
  pid_count: number;
  available: boolean;
  error?: string;
}

/** 沙箱实例详情 */
export interface SandboxDetail {
  id: string;
  task_id: string;
  container_id: string | null;
  container_name: string | null;
  image: string;
  status: string;
  network_mode: string;
  memory_limit: string | null;
  cpu_limit: number | null;
  pid_limit: number | null;
  timeout_secs: number;
  mount_source: string | null;
  mount_target: string;
  tmp_dir: string;
  exit_code: number | null;
  error_message: string | null;
  resource_usage: Record<string, unknown> | null;
  created_at: string;
  ready_at: string | null;
  destroyed_at: string | null;
}

/** 命令执行结果 */
export interface SandboxExecResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  timed_out: boolean;
}

/** 获取沙箱运行状态 */
export async function getSandboxStatus(taskId: string) {
  const res = await http.get<SandboxStatus>(`/tasks/${taskId}/sandbox/status`);
  return res.data;
}

/** 获取沙箱资源使用统计 */
export async function getSandboxStats(taskId: string) {
  const res = await http.get<SandboxStats>(`/tasks/${taskId}/sandbox/stats`);
  return res.data;
}

/** 获取沙箱容器日志 */
export async function getSandboxLogs(taskId: string, tail = 200) {
  const res = await http.get<string>(`/tasks/${taskId}/sandbox/logs`, {
    params: { tail },
  });
  return res.data;
}

/** 获取沙箱实例详情 */
export async function getSandboxDetail(taskId: string) {
  const res = await http.get<SandboxDetail | null>(`/tasks/${taskId}/sandbox`);
  return res.data;
}

/** 手动销毁沙箱 */
export async function destroySandbox(taskId: string) {
  const res = await http.post<{ message: string }>(
    `/tasks/${taskId}/sandbox/destroy`
  );
  return res.data;
}

/** 在沙箱中执行命令 */
export async function execInSandbox(
  taskId: string,
  command: string,
  timeout?: number,
  workingDir?: string
) {
  const res = await http.post<SandboxExecResult>(
    `/tasks/${taskId}/sandbox/exec`,
    { command, timeout, working_dir: workingDir }
  );
  return res.data;
}
