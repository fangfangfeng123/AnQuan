import { create } from 'zustand';
import {
  createTask,
  startTask,
  stopTask,
  getTask,
  listTasks,
  listTaskLogs,
  type Task,
  type TaskLog,
} from '../api/tasks';
import { listSnapshots } from '../api/projects';
import {
  getSandboxStatus,
  getSandboxStats,
  type SandboxStatus,
  type SandboxStats,
} from '../api/sandbox';
import {
  getReconSummary,
  type ReconSummary,
} from '../api/recon';

const PHASE_LABELS: Record<string, string> = {
  recon: '环境侦察',
  code_audit: '代码审计',
  poc_verify: 'PoC 验证',
  exploit_chain: '攻击链推演',
  report_gen: '报告生成',
};

const PHASE_ORDER = ['recon', 'code_audit', 'poc_verify', 'exploit_chain', 'report_gen'];

let initializeRequestSeq = 0;

interface TaskState {
  currentTask: Task | null;
  logs: TaskLog[];
  loading: boolean;
  error: string | null;
  latestSnapshotId: string | null;
  wsConnected: boolean;
  wsEvents: Record<string, unknown>[];
  sandboxStatus: SandboxStatus | null;
  sandboxStats: SandboxStats | null;
  sandboxLoading: boolean;
  reconSummary: ReconSummary | null;
  reconLoading: boolean;

  create: (projectId: string, sourceSnapshotId?: string | null) => Promise<Task>;
  initializeProject: (projectId: string) => Promise<void>;
  start: (taskId: string) => Promise<Task>;
  stop: (taskId: string) => Promise<Task>;
  fetch: (taskId: string) => Promise<void>;
  fetchLogs: (taskId: string) => Promise<void>;
  fetchSandboxStatus: (taskId: string) => Promise<void>;
  fetchSandboxStats: (taskId: string) => Promise<void>;
  fetchReconSummary: (taskId: string) => Promise<void>;
  setWsConnected: (connected: boolean) => void;
  addWsEvent: (event: Record<string, unknown>) => void;
  clearEvents: () => void;
}

export const useTaskStore = create<TaskState>((set) => ({
  currentTask: null,
  logs: [],
  loading: false,
  error: null,
  latestSnapshotId: null,
  wsConnected: false,
  wsEvents: [],
  sandboxStatus: null,
  sandboxStats: null,
  sandboxLoading: false,
  reconSummary: null,
  reconLoading: false,

  create: async (projectId, sourceSnapshotId) => {
    if (!sourceSnapshotId) {
      throw new Error('项目还没有源码快照，请先上传 ZIP 或克隆 Git 仓库');
    }
    const task = await createTask(projectId, {
      source_snapshot_id: sourceSnapshotId,
    });
    set({ currentTask: task });
    return task;
  },

  initializeProject: async (projectId) => {
    const requestSeq = ++initializeRequestSeq;
    set({
      loading: true,
      error: null,
      currentTask: null,
      logs: [],
      latestSnapshotId: null,
      wsConnected: false,
      wsEvents: [],
      sandboxStatus: null,
      sandboxStats: null,
      reconSummary: null,
      reconLoading: false,
    });
    try {
      const snapshots = await listSnapshots(projectId, { size: 1 });
      if (requestSeq !== initializeRequestSeq) return;
      const snapshotId = snapshots.items[0]?.id || null;
      set({ latestSnapshotId: snapshotId });

      const res = await listTasks({ project_id: projectId, size: 1 });
      if (requestSeq !== initializeRequestSeq) return;
      if (res.items[0]) {
        const task = await getTask(res.items[0].id);
        if (requestSeq !== initializeRequestSeq) return;
        set({ currentTask: task });
      }
      set({ loading: false });
    } catch (e) {
      if (requestSeq === initializeRequestSeq) {
        set({ loading: false, error: (e as Error).message });
      }
    }
  },

  start: async (taskId) => {
    const task = await startTask(taskId);
    set({ currentTask: task });
    return task;
  },

  stop: async (taskId) => {
    const task = await stopTask(taskId);
    set({ currentTask: task });
    return task;
  },

  fetch: async (taskId) => {
    set({ loading: true, error: null });
    try {
      const task = await getTask(taskId);
      set({ currentTask: task, loading: false });
    } catch (e) {
      set({ loading: false, error: (e as Error).message });
    }
  },

  fetchLogs: async (taskId) => {
    try {
      const res = await listTaskLogs(taskId, { size: 100 });
      set({ logs: res.items });
    } catch (e) {
      set({ error: (e as Error).message });
    }
  },

  fetchSandboxStatus: async (taskId) => {
    try {
      const status = await getSandboxStatus(taskId);
      set({ sandboxStatus: status });
    } catch {
      // 沙箱状态获取失败不阻塞主流程
    }
  },

  fetchSandboxStats: async (taskId) => {
    set({ sandboxLoading: true });
    try {
      const stats = await getSandboxStats(taskId);
      set({ sandboxStats: stats, sandboxLoading: false });
    } catch {
      set({ sandboxLoading: false });
    }
  },

  fetchReconSummary: async (taskId) => {
    set({ reconLoading: true });
    try {
      const summary = await getReconSummary(taskId);
      set({ reconSummary: summary, reconLoading: false });
    } catch {
      // 404 表示 Recon 尚未完成，清空摘要不阻塞主流程
      set({ reconSummary: null, reconLoading: false });
    }
  },

  setWsConnected: (connected) => set({ wsConnected: connected }),

  addWsEvent: (event) =>
    set((state) => ({ wsEvents: [...state.wsEvents.slice(-200), event] })),

  clearEvents: () => set({ wsEvents: [] }),
}));

export { PHASE_LABELS, PHASE_ORDER };
