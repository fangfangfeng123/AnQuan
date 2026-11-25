import { create } from 'zustand';
import {
  listProjects,
  createProject,
  uploadSource,
  cloneSource,
  ingestLocalPath,
  type Project,
  type ProjectListItem,
} from '../api/projects';

interface ProjectState {
  projects: ProjectListItem[];
  total: number;
  page: number;
  size: number;
  loading: boolean;
  error: string | null;

  fetchList: (params?: { page?: number; size?: number; status?: string }) => Promise<void>;
  create: (data: {
    project_name: string;
    source_type: string;
    source_input: string;
    source_ref?: string | null;
  }) => Promise<Project>;
  upload: (projectId: string, file: File) => Promise<unknown>;
  clone: (projectId: string, gitUrl: string, ref?: string) => Promise<unknown>;
  ingestPath: (projectId: string, localPath: string) => Promise<unknown>;
}

export const useProjectStore = create<ProjectState>((set) => ({
  projects: [],
  total: 0,
  page: 1,
  size: 20,
  loading: false,
  error: null,

  fetchList: async (params) => {
    set({ loading: true, error: null });
    try {
      const res = await listProjects(params);
      set({
        projects: res.items,
        total: res.total,
        page: res.page,
        size: res.size,
        loading: false,
      });
    } catch (e) {
      set({ loading: false, error: (e as Error).message });
    }
  },

  create: async (data) => {
    const project = await createProject(data);
    return project;
  },

  upload: async (projectId, file) => {
    return await uploadSource(projectId, file);
  },

  clone: async (projectId, gitUrl, ref) => {
    return await cloneSource(projectId, gitUrl, ref);
  },

  ingestPath: async (projectId, localPath) => {
    return await ingestLocalPath(projectId, localPath);
  },
}));
