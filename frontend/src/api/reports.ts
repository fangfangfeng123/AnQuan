import { http } from './client';

export interface ReportItem {
  id: string;
  project_name: string | null;
  task_id: string;
  project_id: string;
  overall_risk: string;
  overall_cvss: number | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  markdown_path: string | null;
  html_path: string | null;
  pdf_path: string | null;
  version: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface ReportFindingEntry {
  id: string;
  vuln_type: string;
  cwe_id: string | null;
  severity: string;
  cvss_score: number | null;
  status: string;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  remediation: string | null;
  patch?: {
    id: string | null;
    adopt_status: string | null;
    validated: boolean;
    diff_content: string | null;
    description: string | null;
  } | null;
}

export interface ReportChainEntry {
  id: string;
  name: string | null;
  final_impact: string | null;
  overall_severity: string | null;
  overall_cvss: number | null;
  node_count: number | null;
  edge_count: number | null;
  is_single_node: boolean;
}

export interface ReportRemediationEntry {
  finding_id: string;
  vuln_type: string;
  severity: string;
  cvss_score: number | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  remediation: string;
  patch_description: string;
}

export interface ReportDetail extends ReportItem {
  sections?: {
    executive_summary?: {
      summary_text?: string;
      total_chains?: number;
      multi_step_chains?: number;
    } | null;
    scope?: Record<string, unknown> | null;
    findings?: ReportFindingEntry[] | null;
    attack_chains?: ReportChainEntry[] | null;
    remediation?: ReportRemediationEntry[] | null;
  } | null;
}

export type ReportFileFormat = 'markdown' | 'html' | 'pdf';

export async function listReports(params?: {
  page?: number;
  size?: number;
}): Promise<{
  items: ReportItem[];
  total: number;
  page: number;
  size: number;
  pages: number;
}> {
  const res = await http.get('/reports', { params });
  return res.data;
}

export async function getReportDetail(reportId: string): Promise<ReportDetail> {
  const res = await http.get<ReportDetail>(`/reports/${reportId}`);
  return res.data;
}

export async function exportReport(
  taskId: string,
  format: ReportFileFormat
) {
  const res = await http.post(`/tasks/${taskId}/report/export`, { format });
  return res.data;
}

export async function deleteReport(reportId: string) {
  const res = await http.delete(`/reports/${reportId}`);
  return res.data;
}

export function getReportDownloadUrl(reportId: string, format: ReportFileFormat) {
  return `/api/v1/reports/${reportId}/download/${format}`;
}

export async function downloadReportFile(
  reportId: string,
  format: ReportFileFormat
) {
  const res = await http.get<Blob>(`/reports/${reportId}/download/${format}`, {
    responseType: 'blob',
  });
  const objectUrl = URL.createObjectURL(res.data);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = `report_${reportId}.${format === 'markdown' ? 'md' : format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
  return res.data;
}
