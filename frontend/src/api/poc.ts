import { http } from './client';

/** PoC evidence record for a finding. */
export interface PocEvidence {
  id: string;
  finding_id: string;
  task_id: string;
  poc_type: string;

  // Request
  request_method: string | null;
  request_url: string | null;
  request_headers: Record<string, unknown> | null;
  request_body: string | null;

  // Response
  response_status: number | null;
  response_headers: Record<string, unknown> | null;
  response_body: string | null;

  // Verification result
  expected_feature: string | null;
  actual_feature: string | null;
  matched: boolean;
  validation_status: string;
  error_message: string | null;

  // Timestamps
  executed_at: string | null;
  verified_at: string | null;
  created_at: string | null;
}

export interface PocEvidenceListResponse {
  items: PocEvidence[];
  total: number;
}

/** Fetch PoC evidence for a given finding. */
export async function listFindingEvidence(
  findingId: string
): Promise<PocEvidenceListResponse> {
  const res = await http.get<PocEvidenceListResponse>(
    `/findings/${findingId}/evidence`
  );
  return res.data;
}
