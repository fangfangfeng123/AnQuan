// 验证用模拟接口：替代 ../api/auditLogs，返回固定 253 条审计日志。
// 仅用于本地 UI 行为验证，不参与生产构建。

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

const TOTAL = 253;

const ACTIONS = [
  'create',
  'start',
  'stop',
  'archive',
  'restore',
  'delete',
  'config_update',
];

function buildAll(): AuditLog[] {
  const rows: AuditLog[] = [];
  const base = new Date('2026-09-01T08:00:00Z').getTime();
  for (let i = 1; i <= TOTAL; i += 1) {
    rows.push({
      id: i,
      action: ACTIONS[i % ACTIONS.length],
      task_id: `task-${String(i).padStart(4, '0')}`,
      project_id: `proj-${String(i % 12).padStart(3, '0')}`,
      operator: i % 3 === 0 ? 'admin' : `user-${i % 7}`,
      target_type: 'project',
      target_id: `target-${i}`,
      detail: { note: `第 ${i} 条记录`, seq: i },
      ip_address: `10.0.${i % 20}.${(i * 7) % 250}`,
      created_at: new Date(base + i * 60_000).toISOString(),
    });
  }
  // 与真实接口一致：按时间倒序
  return rows.reverse();
}

const ALL = buildAll();

interface ListParams {
  action?: string;
  operator?: string;
  page?: number;
  size?: number;
}

// 记录最近一次请求参数，供验证时从页面外部读取
export const lastRequest: ListParams = {};

export async function listAuditLogs(params: ListParams = {}) {
  lastRequest.action = params.action;
  lastRequest.operator = params.operator;
  lastRequest.page = params.page;
  lastRequest.size = params.size;

  (globalThis as unknown as { __lastRequest?: ListParams }).__lastRequest = {
    ...lastRequest,
  };

  const page = params.page ?? 1;
  const size = params.size ?? 20;

  let rows = ALL;
  if (params.action) {
    rows = rows.filter((row) => row.action === params.action);
  }
  if (params.operator) {
    rows = rows.filter((row) => row.operator === params.operator);
  }

  const start = (page - 1) * size;
  return {
    items: rows.slice(start, start + size),
    total: rows.length,
    page,
    size,
    pages: Math.ceil(rows.length / size),
  };
}

export async function deleteAuditLog(logId: number) {
  return { message: `审计日志已删除: ${logId}` };
}

export async function clearAuditLogs() {
  return { message: '已清空审计日志' };
}
