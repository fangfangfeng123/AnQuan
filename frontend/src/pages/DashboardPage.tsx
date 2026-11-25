import React, { useEffect, useState } from 'react';
import {
  Button,
  Card,
  Col,
  message,
  Popconfirm,
  Row,
  Spin,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { DeleteOutlined } from '@ant-design/icons';
import {
  getDashboardStats,
  getRecentTasks,
  getSeverityDistribution,
  type DashboardStats,
  type RecentTask,
  type SeverityItem,
} from '../api/dashboard';
import { purgeTaskRecord } from '../api/tasks';
import { useAuthStore } from '../stores/auth';
import {
  phaseLabels,
  riskLabels,
  riskColorMap,
  severityLabels,
  taskStatusLabels,
} from '../utils/labels';

const { Title, Text } = Typography;

const riskColors: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  secure: 'green',
};

const DashboardPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [severity, setSeverity] = useState<SeverityItem[]>([]);
  const [tasks, setTasks] = useState<RecentTask[]>([]);
  const [loading, setLoading] = useState(false);
  const [deletingTaskId, setDeletingTaskId] = useState<string | null>(null);
  const role = useAuthStore((state) => state.user?.role);
  const canDeleteTask = role === 'admin';

  const refresh = async () => {
    setLoading(true);
    try {
      const [statsData, severityData, taskData] = await Promise.all([
        getDashboardStats(),
        getSeverityDistribution(),
        getRecentTasks(10),
      ]);
      setStats(statsData);
      setSeverity(severityData.items);
      setTasks(taskData.items);
    } catch (e) {
      message.error((e as Error).message || '仪表盘数据加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const handlePurgeTask = async (task: RecentTask) => {
    setDeletingTaskId(task.id);
    try {
      await purgeTaskRecord(task.id);
      message.success(`任务 ${task.id.slice(0, 8)}... 已彻底删除`);
      await refresh();
    } catch (e) {
      message.error((e as Error).message || '任务删除失败');
    } finally {
      setDeletingTaskId(null);
    }
  };

  const columns: ColumnsType<RecentTask> = [
    { title: '项目', dataIndex: 'project_name', key: 'project_name' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (v: string) => taskStatusLabels[v] || v,
    },
    {
      title: '风险',
      dataIndex: 'overall_risk',
      key: 'overall_risk',
      render: (v: string | null) =>
        v ? (
          <Tag color={riskColorMap[v] || 'default'}>
            {riskLabels[v] || v}
          </Tag>
        ) : (
          '-'
        ),
    },
    {
      title: '阶段',
      dataIndex: 'current_phase',
      key: 'current_phase',
      render: (v: string | null) => phaseLabels[v || ''] || v || '-',
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (v: string | null) =>
        v ? new Date(v).toLocaleString('zh-CN') : '-',
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      render: (_: unknown, record: RecentTask) => (
        <>
        {canDeleteTask && (
          <Popconfirm
            title="彻底删除任务"
            description="将删除该任务下的漏洞、攻击链、执行日志、报告和生成文件，不可恢复。"
            okText="确认删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            disabled={record.status === 'running'}
            onConfirm={() => handlePurgeTask(record)}
          >
            <Button
              type="link"
              danger
              size="small"
              icon={<DeleteOutlined />}
              loading={deletingTaskId === record.id}
              disabled={record.status === 'running'}
            >
              删除
            </Button>
          </Popconfirm>
        )}
        </>
      ),
    },
  ];

  if (loading && !stats) {
    return <Spin style={{ display: 'block', marginTop: 80 }} />;
  }

  return (
    <div>
      <Title level={4}>安全评估概览</Title>
      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card><Statistic title="项目" value={stats?.total_projects ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="评估任务" value={stats?.total_tasks ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="运行中" value={stats?.running_tasks ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="已完成" value={stats?.completed_tasks ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="漏洞总数" value={stats?.total_findings ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="已验证" value={stats?.verified_findings ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card><Statistic title="攻击链" value={stats?.total_chains ?? 0} /></Card>
        </Col>
        <Col xs={12} md={6}>
          <Card>
            <Statistic
              title="最高风险评分"
              value={stats?.max_cvss ?? 0}
              precision={1}
            />
          </Card>
        </Col>
      </Row>

      <Card title="漏洞严重等级分布" style={{ marginTop: 16 }}>
        {severity.length === 0 ? (
          <Text type="secondary">暂无漏洞数据</Text>
        ) : (
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {severity.map((item) => (
              <Tag
                key={item.severity}
                color={riskColors[item.severity] || 'default'}
                style={{ fontSize: 14, padding: '6px 12px' }}
              >
                {severityLabels[item.severity] || item.severity}: {item.count}
              </Tag>
            ))}
          </div>
        )}
      </Card>

      <Card title="最近任务" style={{ marginTop: 16 }}>
        <Table
          rowKey="id"
          columns={columns}
          dataSource={tasks}
          pagination={false}
          size="small"
        />
      </Card>
    </div>
  );
};

export default DashboardPage;
