export const riskLabels: Record<string, string> = {
  critical: '极高危',
  high: '高危',
  medium: '中危',
  low: '低危',
  secure: '安全',
  info: '信息',
};

export const severityLabels: Record<string, string> = {
  critical: '极高危',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

export const findingStatusLabels: Record<string, string> = {
  unverified: '疑似',
  verified: '已验证',
  latent: '潜在隐患',
  false_positive: '误报',
  adopted: '已采纳',
};

export const taskStatusLabels: Record<string, string> = {
  created: '已创建',
  running: '运行中',
  completed: '已完成',
  failed: '失败',
  stopped: '已停止',
};

export const projectStatusLabels: Record<string, string> = {
  active: '正常',
  archived: '已归档',
};

export const phaseLabels: Record<string, string> = {
  recon: '环境侦察',
  code_audit: '代码审计',
  poc_verify: '动态验证',
  exploit_chain: '攻击链推演',
  report_gen: '报告生成',
  pending: '等待中',
  running: '执行中',
  completed: '已完成',
  failed: '失败',
};

export const riskColorMap: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  secure: 'green',
  info: 'default',
};

export const vulnTypeLabels: Record<string, string> = {
  sql_injection: 'SQL 注入',
  command_injection: '命令注入',
  file_upload: '文件上传',
  idor: '越权访问',
  broken_access: '越权/权限突破',
  sensitive_data: '敏感信息泄露',
  sensitive_info: '敏感信息泄露',
  insecure_config: '不安全配置',
  path_traversal: '路径遍历',
  deserialization: '反序列化',
  xss: '跨站脚本',
  ssrf: '服务端请求伪造',
  rce: '远程代码执行',
  other: '其他',
};

export const detectedByLabels: Record<string, string> = {
  semgrep: '静态规则扫描',
  bandit: 'Python 安全扫描',
  taint_engine: '污点追踪分析',
  codeql: '代码分析',
  other: '其他',
};

export const sourceTypeLabels: Record<string, string> = {
  git: 'Git 仓库',
  archive: '压缩包',
  directory: '文件夹',
  file: '文件',
  local_path: '本地路径',
};

export const languageLabels: Record<string, string> = {
  python: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  java: 'Java',
  go: 'Go',
  php: 'PHP',
  ruby: 'Ruby',
  c: 'C',
  'c++': 'C++',
  shell: 'Shell',
};

export const frameworkLabels: Record<string, string> = {
  flask: 'Flask',
  fastapi: 'FastAPI',
  django: 'Django',
  express: 'Express',
  spring: 'Spring',
  'spring-boot': 'Spring Boot',
  gin: 'Gin',
  laravel: 'Laravel',
  rails: 'Rails',
};

export const dbTypeLabels: Record<string, string> = {
  postgresql: 'PostgreSQL',
  mysql: 'MySQL',
  sqlite: 'SQLite',
  mongodb: 'MongoDB',
  redis: 'Redis',
  not_detected: '未识别',
};

export const taintStepLabels: Record<string, string> = {
  source: '污点入口',
  transfer: '传播过程',
  sink: '危险汇聚点',
  sanitizer: '净化处理',
};

export const pocTypeLabels: Record<string, string> = {
  http: 'HTTP 请求',
  command: '命令执行',
  file_read: '文件读取',
  dns: 'DNS 探测',
  timing: '时间探测',
};

export const privilegeLevelLabels: Record<string, string> = {
  anonymous: '匿名',
  user: '普通用户',
  admin: '管理员',
  system: '系统级',
};

export const targetTypeLabels: Record<string, string> = {
  project: '项目',
  task: '评估任务',
  source_snapshot: '源码快照',
  report: '安全报告',
  audit_log: '审计日志',
  sandbox: '沙箱',
  config: '系统配置',
};

export function pickLabel(
  value: string | null | undefined,
  labels: Record<string, string>,
  fallback = '未识别'
): string {
  if (!value) return fallback;
  return labels[value] || labels[value.toLowerCase()] || value;
}

export function detectedByLabel(
  value: string | null | undefined,
  fallback = '未识别'
): string {
  if (!value) return fallback;
  return value
    .split('+')
    .map((part) => detectedByLabels[part.trim().toLowerCase()] || part.trim())
    .join('+');
}
