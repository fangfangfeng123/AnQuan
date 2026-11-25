import { http } from './client';

export interface TargetItem {
  name: string;
  kind: 'directory' | 'file' | 'archive';
  path: string;
  file_count: number;
  total_size_kb: number;
  updated_at: string | null;
}

export async function listTargets(): Promise<{
  root_path: string;
  items: TargetItem[];
}> {
  const res = await http.get('/targets');
  return res.data;
}
