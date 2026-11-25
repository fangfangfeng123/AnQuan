import { http } from './client';

export interface DashboardStats {
  total_projects: number;
  total_tasks: number;
  running_tasks: number;
  completed_tasks: number;
  total_findings: number;
  verified_findings: number;
  total_chains: number;
  max_cvss: number | null;
  overall_risk_distribution: Record<string, number>;
}

export interface SeverityItem {
  severity: string;
  count: number;
}

export interface RecentTask {
  id: string;
  project_name: string;
  status: string;
  overall_risk: string | null;
  current_phase: string | null;
  created_at: string | null;
}

export async function getDashboardStats(): Promise<DashboardStats> {
  const res = await http.get<DashboardStats>('/dashboard/stats');
  return res.data;
}

export async function getSeverityDistribution(): Promise<{
  items: SeverityItem[];
  total: number;
}> {
  const res = await http.get('/dashboard/severity-distribution');
  return res.data;
}

export async function getRecentTasks(
  limit = 10
): Promise<{ items: RecentTask[]; total: number }> {
  const res = await http.get('/dashboard/recent-tasks', { params: { limit } });
  return res.data;
}
