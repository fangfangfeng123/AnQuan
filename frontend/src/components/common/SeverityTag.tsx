import React from 'react';
import { Tag } from 'antd';
import type { Finding } from '../../api/findings';

/** Color mapping for each severity level. */
const SEVERITY_COLOR: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
  info: 'default',
};

/** Chinese label for each severity level. */
const SEVERITY_LABEL: Record<string, string> = {
  critical: '极高危',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

interface SeverityTagProps {
  severity: string;
  cvssScore?: number | null;
}

/** Render a severity tag with optional CVSS score. */
const SeverityTag: React.FC<SeverityTagProps> = ({ severity, cvssScore }) => {
  const color = SEVERITY_COLOR[severity] || 'default';
  const label = SEVERITY_LABEL[severity] || severity;
  const scoreText =
    cvssScore !== null && cvssScore !== undefined
      ? ` ${cvssScore.toFixed(1)}`
      : '';
  return (
    <Tag color={color} style={{ fontWeight: 600 }}>
      {label}
      {scoreText}
    </Tag>
  );
};

/** Color mapping for finding status. */
const STATUS_COLOR: Record<string, string> = {
  unverified: 'orange',
  verified: 'green',
  latent: 'gold',
  false_positive: 'default',
  adopted: 'cyan',
};

/** Chinese label for each finding status. */
const STATUS_LABEL: Record<string, string> = {
  unverified: '疑似',
  verified: '已验证',
  latent: '潜在隐患',
  false_positive: '误报',
  adopted: '已采纳',
};

interface StatusTagProps {
  status: string;
}

/** Render a finding verification status tag. */
export const FindingStatusTag: React.FC<StatusTagProps> = ({ status }) => {
  const color = STATUS_COLOR[status] || 'default';
  const label = STATUS_LABEL[status] || status;
  return <Tag color={color}>{label}</Tag>;
};

/** Map vuln_type to a human-readable label. */
const VULN_TYPE_LABEL: Record<string, string> = {
  sql_injection: 'SQL 注入',
  command_injection: '命令注入',
  file_upload: '文件上传',
  idor: '越权访问',
  broken_access: '权限突破',
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

/** Render a vuln type tag. */
export const VulnTypeTag: React.FC<{ vulnType: string }> = ({
  vulnType,
}) => {
  const label = VULN_TYPE_LABEL[vulnType] || vulnType;
  return <Tag>{label}</Tag>;
};

export default SeverityTag;
