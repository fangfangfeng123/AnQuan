import { http } from './client';

export interface Project {
  id: string;
  project_name: string;
  source_type: string;
  source_input: string;
  source_ref: string | null;
  commit_id: string | null;
  tech_stack: Record<string, unknown> | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectListItem {
  id: string;
  project_name: string;
  source_type: string;
  status: string;
  created_at: string;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface CreateProjectReq {
  project_name: string;
  source_type: string;
  source_input: string;
  source_ref?: string | null;
}

export async function createProject(data: CreateProjectReq) {
  const res = await http.post<Project>('/projects', data);
  return res.data;
}

export async function listProjects(params?: {
  status?: string;
  page?: number;
  size?: number;
}) {
  const res = await http.get<Paginated<ProjectListItem>>('/projects', { params });
  return res.data;
}

export async function getProject(id: string) {
  const res = await http.get<Project>(`/projects/${id}`);
  return res.data;
}

export async function updateProject(id: string, data: Partial<CreateProjectReq>) {
  const res = await http.put<Project>(`/projects/${id}`, data);
  return res.data;
}

export async function archiveProject(id: string) {
  const res = await http.delete(`/projects/${id}`);
  return res.data;
}

export async function purgeProject(id: string) {
  const res = await http.delete(`/projects/${id}/purge`);
  return res.data;
}

export async function restoreProject(id: string) {
  const res = await http.post<Project>(`/projects/${id}/restore`);
  return res.data;
}

export async function uploadSource(projectId: string, file: File) {
  const formData = new FormData();
  formData.append('file', file);
  // 注意：不要手动设置 Content-Type，axios 会自动生成带 boundary 的完整头
  // 手动设置 'multipart/form-data' 会导致缺少 boundary，后端无法解析
  const res = await http.post(`/projects/${projectId}/upload`, formData, {
    timeout: 120000, // 文件上传单独放宽到 120 秒
  });
  return res.data;
}

export async function cloneSource(projectId: string, gitUrl: string, ref?: string) {
  const res = await http.post(`/projects/${projectId}/clone`, {
    git_url: gitUrl,
    ref: ref || null,
  });
  return res.data;
}

export async function ingestLocalPath(projectId: string, localPath: string) {
  const res = await http.post(`/projects/${projectId}/local-path`, {
    local_path: localPath,
  });
  return res.data;
}

export async function listSnapshots(projectId: string, params?: { page?: number; size?: number }) {
  const res = await http.get(`/projects/${projectId}/snapshots`, { params });
  return res.data;
}
