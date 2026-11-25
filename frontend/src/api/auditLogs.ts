import { http } from './client';

export interface AuditLog {
  id: number;
  action: string;
  task_id: string | null;
  project_id: string | null;
  operator: string;
  target_type: string | null;
  target_id: string | null;
  detail: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

export async function listAuditLogs(params?: {
  action?: string;
  operator?: string;
  target_id?: string;
  task_id?: string;
  project_id?: string;
  start_date?: string;
  end_date?: string;
  page?: number;
  size?: number;
}): Promise<{
  items: AuditLog[];
  total: number;
  page: number;
  size: number;
  pages: number;
}> {
  const res = await http.get('/audit-logs', { params });
  return res.data;
}

export async function deleteAuditLog(logId: number) {
  const res = await http.delete(`/audit-logs/${logId}`);
  return res.data;
}

export async function clearAuditLogs() {
  const res = await http.delete('/audit-logs');
  return res.data;
}
