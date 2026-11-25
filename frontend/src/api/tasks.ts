import { http } from './client';
import type { Paginated } from './projects';

export interface Task {
  id: string;
  project_id: string;
  source_snapshot_id: string | null;
  status: string;
  current_phase: string | null;
  phase_status: Record<string, string>;
  overall_progress: number;
  overall_risk: string | null;
  sandbox_id: string | null;
  llm_mode: string;
  error_message: string | null;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TaskLog {
  id: number;
  task_id: string;
  phase: string;
  agent: string;
  level: string;
  message: string;
  detail: Record<string, unknown> | null;
  created_at: string;
}

export interface CreateTaskReq {
  source_snapshot_id?: string | null;
  sandbox_image?: string | null;
  network_mode?: string;
  timeout_secs?: number;
  llm_mode?: string;
  max_concurrent?: number;
}

export async function createTask(projectId: string, data: CreateTaskReq = {}) {
  const res = await http.post<Task>(`/projects/${projectId}/tasks`, {
    source_snapshot_id: data.source_snapshot_id || null,
    sandbox_image: data.sandbox_image || null,
    network_mode: data.network_mode || 'restricted',
    timeout_secs: data.timeout_secs || 1800,
    llm_mode: data.llm_mode || 'demo',
    max_concurrent: data.max_concurrent || 3,
  });
  return res.data;
}

export async function startTask(taskId: string) {
  const res = await http.post<Task>(`/tasks/${taskId}/start`);
  return res.data;
}

export async function stopTask(taskId: string) {
  const res = await http.post<Task>(`/tasks/${taskId}/stop`);
  return res.data;
}

export async function purgeTaskRecord(taskId: string) {
  const res = await http.delete(`/tasks/${taskId}/purge`);
  return res.data;
}

export async function getTask(taskId: string) {
  const res = await http.get<Task>(`/tasks/${taskId}`);
  return res.data;
}

export async function listTasks(params?: {
  status?: string;
  project_id?: string;
  page?: number;
  size?: number;
}) {
  const res = await http.get<Paginated<Task>>('/tasks', { params });
  return res.data;
}

export async function listTaskLogs(taskId: string, params?: { page?: number; size?: number }) {
  const res = await http.get<Paginated<TaskLog>>(`/tasks/${taskId}/logs`, { params });
  return res.data;
}
