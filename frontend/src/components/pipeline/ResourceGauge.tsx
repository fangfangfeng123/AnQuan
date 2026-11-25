import React from 'react';
import { Progress, Statistic, Row, Col, Empty } from 'antd';
import { CloudServerOutlined, DatabaseOutlined } from '@ant-design/icons';
import type { SandboxStats } from '../../api/sandbox';

interface ResourceGaugeProps {
  stats: SandboxStats | null;
  loading?: boolean;
}

/**
 * 资源指标卡片组件。
 * 展示沙箱容器的 CPU 使用率、内存使用量和 PID 数量。
 */
const ResourceGauge: React.FC<ResourceGaugeProps> = ({ stats, loading }) => {
  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '24px', color: '#999' }}>
        正在获取资源指标...
      </div>
    );
  }

  if (!stats || !stats.available) {
    return (
      <Empty
        description={stats?.error || '沙箱未运行，无法获取资源指标'}
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        style={{ padding: '24px 0' }}
      />
    );
  }

  const cpuPercent = Math.round(stats.cpu_percent * 100) / 100;
  const memUsed = stats.memory_usage_mb.toFixed(2);
  const memLimit = stats.memory_limit_mb > 0 ? stats.memory_limit_mb.toFixed(0) : '-';
  const memPercent = Math.round(stats.memory_percent * 100) / 100;

  return (
    <div>
      <Row gutter={16}>
        <Col span={8}>
          <Statistic
            title="处理器使用率"
            value={cpuPercent}
            suffix="%"
            prefix={<CloudServerOutlined />}
            valueStyle={{ fontSize: '20px' }}
          />
          <Progress
            percent={Math.min(cpuPercent, 100)}
            size="small"
            status={cpuPercent > 80 ? 'exception' : 'normal'}
            style={{ marginTop: 4 }}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="内存使用量"
            value={memUsed}
            suffix={`/ ${memLimit} 兆字节`}
            prefix={<DatabaseOutlined />}
            valueStyle={{ fontSize: '20px' }}
          />
          <Progress
            percent={Math.min(memPercent, 100)}
            size="small"
            status={memPercent > 80 ? 'exception' : 'normal'}
            strokeColor={{ '0%': '#1677ff', '100%': '#52c41a' }}
            style={{ marginTop: 4 }}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="进程数量"
            value={stats.pid_count}
            valueStyle={{ fontSize: '20px' }}
          />
        </Col>
      </Row>
    </div>
  );
};

export default ResourceGauge;
