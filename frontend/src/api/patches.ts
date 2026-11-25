import { http } from './client';

/** Fix patch for a finding (one-to-one). */
export interface FixPatch {
  id: string;
  finding_id: string;
  task_id: string;

  // Code content
  original_code: string | null;
  patched_code: string | null;
  diff_content: string | null;
  description: string | null;

  // Adopt status
  adopt_status: 'pending' | 'adopted' | 'rejected' | 'superseded';

  // Validation
  validated: boolean;
  validation_result: Record<string, unknown> | null;

  // LLM record
  llm_model: string | null;
  token_usage: number | null;

  // Timestamps
  created_at: string | null;
  updated_at: string | null;
}

export interface FixPatchListResponse {
  items: FixPatch[];
  total: number;
}

export interface FixPatchDiffResponse {
  patch_id: string;
  finding_id: string;
  diff: string;
  adopt_status: string;
}

export interface FixPatchValidateResponse {
  patch_id: string;
  validated: boolean;
  validation_result: Record<string, unknown> | null;
  message: string;
}

/** Generate or force-regenerate a patch for a finding. */
export async function createPatch(
  findingId: string,
  forceRegenerate = false
): Promise<FixPatch> {
  const res = await http.post<FixPatch>(`/findings/${findingId}/patches`, {
    force_regenerate: forceRegenerate,
  });
  return res.data;
}

/** Query an existing patch without creating one. */
export async function getPatchByFinding(findingId: string): Promise<FixPatch> {
  const res = await http.get<FixPatch>(`/findings/${findingId}/patch`);
  return res.data;
}

/** Get patch details. */
export async function getPatch(patchId: string): Promise<FixPatch> {
  const res = await http.get<FixPatch>(`/patches/${patchId}`);
  return res.data;
}

/** Get patch diff as plain text. */
export async function getPatchDiff(
  patchId: string
): Promise<FixPatchDiffResponse> {
  const res = await http.get<FixPatchDiffResponse>(`/patches/${patchId}/diff`);
  return res.data;
}

/** Trigger patch validation (syntax / compile / security regression). */
export async function validatePatch(
  patchId: string
): Promise<FixPatchValidateResponse> {
  const res = await http.post<FixPatchValidateResponse>(
    `/patches/${patchId}/validate`
  );
  return res.data;
}

/** Adopt a patch. */
export async function adoptPatch(patchId: string): Promise<FixPatch> {
  const res = await http.post<FixPatch>(`/patches/${patchId}/adopt`);
  return res.data;
}

/** Reject a patch with optional reason. */
export async function rejectPatch(
  patchId: string,
  reason?: string
): Promise<FixPatch> {
  const res = await http.post<FixPatch>(`/patches/${patchId}/reject`, {
    reason: reason || null,
  });
  return res.data;
}

/** List all patches for a task. */
export async function listTaskPatches(
  taskId: string
): Promise<FixPatchListResponse> {
  const res = await http.get<FixPatchListResponse>(`/tasks/${taskId}/patches`);
  return res.data;
}

/** Export patch as ZIP (returns blob URL). */
export async function exportPatchZip(patchId: string): Promise<Blob> {
  const res = await http.get(`/patches/${patchId}/export`, {
    responseType: 'blob',
  });
  return res.data as Blob;
}
