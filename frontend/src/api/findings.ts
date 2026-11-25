import { http } from './client';

/** Taint step in the source-to-sink path. */
export interface TaintStep {
  step: number;
  type: 'source' | 'transfer' | 'sink' | 'sanitizer';
  file: string;
  line: number;
  code: string;
  detail?: string | null;
}

export interface Finding {
  id: string;
  task_id: string;
  vuln_type: string;
  cwe_id: string | null;
  owasp: string | null;
  status: string;
  severity: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string | null;
  source_file: string | null;
  source_line: number | null;
  source_code: string | null;
  sink_file: string | null;
  sink_line: number | null;
  sink_code: string | null;
  taint_path: TaintStep[] | null;
  detected_by: string;
  confidence: number;
  remediation: string | null;
  created_at: string | null;
}

export interface FindingListResponse {
  items: Finding[];
  total: number;
  verified_count: number;
  unverified_count: number;
}

export interface FindingSummaryResponse {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
}

export async function listFindings(
  taskId: string,
  params?: {
    severity?: string;
    status?: string;
    vuln_type?: string;
    detected_by?: string;
  }
): Promise<FindingListResponse> {
  const res = await http.get<FindingListResponse>(
    `/tasks/${taskId}/findings`,
    { params }
  );
  return res.data;
}

export async function getFindingSummary(
  taskId: string
): Promise<FindingSummaryResponse> {
  const res = await http.get<FindingSummaryResponse>(
    `/tasks/${taskId}/findings/summary`
  );
  return res.data;
}

export async function getFinding(findingId: string): Promise<Finding> {
  const res = await http.get<Finding>(`/findings/${findingId}`);
  return res.data;
}
