import React from 'react';
import { Tag, Tooltip } from 'antd';

interface StatusBadgeProps {
  status: string;
  /** 显示文案前缀，例如 "沙箱" */
  prefix?: string;
}

/** 沙箱状态对应的 Tag 颜色 */
const STATUS_COLORS: Record<string, string> = {
  creating: 'blue',
  ready: 'cyan',
  running: 'processing',
  destroying: 'orange',
  destroyed: 'default',
  error: 'red',
  none: 'default',
};

/** 沙箱状态对应的中文标签 */
const STATUS_LABELS: Record<string, string> = {
  creating: '创建中',
  ready: '就绪',
  running: '执行中',
  destroying: '销毁中',
  destroyed: '已销毁',
  error: '错误',
  none: '无沙箱',
};

/**
 * 状态徽章组件。
 * 根据沙箱状态显示不同颜色的 Tag。
 */
const StatusBadge: React.FC<StatusBadgeProps> = ({ status, prefix }) => {
  const color = STATUS_COLORS[status] || 'default';
  const label = STATUS_LABELS[status] || status;

  return (
      <Tooltip title={`状态: ${label}`}>
      <Tag color={color} style={{ fontSize: '12px' }}>
        {prefix ? `${prefix}: ` : ''}
        {label}
      </Tag>
    </Tooltip>
  );
};

export default StatusBadge;
