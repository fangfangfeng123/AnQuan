import React, { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Card,
  Empty,
  Input,
  message,
  Pagination,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { DeleteOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import {
  clearAuditLogs,
  deleteAuditLog,
  listAuditLogs,
  type AuditLog,
} from '../api/auditLogs';
import {
  phaseLabels,
  sourceTypeLabels,
  targetTypeLabels,
  taskStatusLabels,
} from '../utils/labels';

const { Title, Text } = Typography;

const actionOptions = [
  { value: 'create', label: '创建' },
  { value: 'start', label: '启动' },
  { value: 'stop', label: '停止' },
  { value: 'archive', label: '归档' },
  { value: 'restore', label: '恢复' },
  { value: 'delete', label: '删除' },
  { value: 'config_update', label: '配置更新' },
];

const actionColors: Record<string, string> = {
  create: 'green',
  start: 'processing',
  stop: 'red',
  archive: 'gold',
  restore: 'cyan',
  delete: 'volcano',
  config_update: 'blue',
};

const actionLabels: Record<string, string> = {
  create: '创建',
  start: '启动',
  stop: '停止',
  archive: '归档',
  restore: '恢复',
  delete: '删除',
  config_update: '配置更新',
};

const operatorLabels: Record<string, string> = {
  admin: '管理员',
  security_auditor: '安全审计员',
  developer: '研发人员',
};

const detailFieldLabels: Record<string, string> = {
  mode: '删除方式',
  project_name: '项目名称',
  source_type: '源码来源',
  source_kind: '源码类型',
  source_input: '源码路径',
  local_path: '本地路径',
  task_status: '任务状态',
  status: '状态',
  current_phase: '当前阶段',
  file_count: '文件数量',
  line_count: '代码行数',
  snapshot_count: '快照数量',
  task_count: '任务数量',
  sandbox_image: '沙箱镜像',
  llm_mode: '模型模式',
  message: '说明',
};

function formatDetailValue(key: string, value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  const text = String(value);
  if (key === 'mode') {
    return text === 'purge' ? '彻底删除' : text;
  }
  if (key === 'source_type' || key === 'source_kind') {
    return sourceTypeLabels[text] || text;
  }
  if (key === 'task_status' || key === 'status') {
    return taskStatusLabels[text] || text;
  }
  if (key === 'current_phase') {
    return phaseLabels[text] || text;
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return text;
}

const AuditLogPage: React.FC = () => {
  const [items, setItems] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(5);
  const [loading, setLoading] = useState(false);
  const [action, setAction] = useState<string | undefined>();
  const [operator, setOperator] = useState('');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [clearing, setClearing] = useState(false);

  const load = async (
    nextPage = page,
    nextSize = size,
    nextAction?: string,
    nextOperator?: string
  ) => {
    setLoading(true);
    try {
      const data = await listAuditLogs({
        page: nextPage,
        size: nextSize,
        action: nextAction || undefined,
        operator: nextOperator?.trim() || undefined,
      });
      setItems(data.items);
      setTotal(data.total);
      setPage(data.page);
      setSize(data.size);
    } catch (e) {
      message.error((e as Error).message || '审计日志加载失败');
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(1, size);
  }, []);

  const knownActions = useMemo(() => {
    const fromRows = new Set(items.map((row) => row.action));
    const merged = new Set(actionOptions.map((item) => item.value));
    fromRows.forEach((item) => merged.add(item));
    return Array.from(merged).map((value) => ({
      value,
      label: actionLabels[value] || value,
    }));
  }, [items]);

  const handleSearch = () => {
    load(1, size, action, operator);
  };

  const handleDelete = async (record: AuditLog) => {
    setDeletingId(record.id);
    try {
      await deleteAuditLog(record.id);
      message.success('审计日志已删除');
      const nextPage = items.length === 1 && page > 1 ? page - 1 : page;
      load(nextPage, size, action, operator);
    } catch (e) {
      message.error((e as Error).message || '审计日志删除失败');
    } finally {
      setDeletingId(null);
    }
  };

  const handleClear = async () => {
    setClearing(true);
    try {
      await clearAuditLogs();
      message.success('审计日志已清空');
      setItems([]);
      setTotal(0);
      setPage(1);
    } catch (e) {
      message.error((e as Error).message || '审计日志清空失败');
    } finally {
      setClearing(false);
    }
  };

  const columns: ColumnsType<AuditLog> = [
    {
      title: '操作时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (value: string) => new Date(value).toLocaleString('zh-CN'),
    },
    {
      title: '操作人',
      dataIndex: 'operator',
      key: 'operator',
      width: 110,
      render: (value: string) => operatorLabels[value] || value || '-',
    },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 120,
      render: (value: string) => (
        <Tag color={actionColors[value] || 'default'}>
          {actionLabels[value] || value}
        </Tag>
      ),
    },
    {
      title: '目标类型',
      dataIndex: 'target_type',
      key: 'target_type',
      width: 130,
      render: (value: string | null) =>
        targetTypeLabels[value || ''] || value || '-',
    },
    {
      title: '目标 ID',
      dataIndex: 'target_id',
      key: 'target_id',
      ellipsis: true,
      render: (value: string | null) =>
        value ? (
          <Text code style={{ fontSize: '12px' }} ellipsis>
            {value}
          </Text>
        ) : (
          '-'
        ),
    },
    {
      title: '任务 ID',
      dataIndex: 'task_id',
      key: 'task_id',
      ellipsis: true,
      render: (value: string | null) =>
        value ? (
          <Text code style={{ fontSize: '12px' }} ellipsis>
            {value}
          </Text>
        ) : (
          '-'
        ),
    },
    {
      title: '项目 ID',
      dataIndex: 'project_id',
      key: 'project_id',
      ellipsis: true,
      render: (value: string | null) =>
        value ? (
          <Text code style={{ fontSize: '12px' }} ellipsis>
            {value}
          </Text>
        ) : (
          '-'
        ),
    },
    {
      title: 'IP',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 140,
      render: (value: string | null) => value || '-',
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      fixed: 'right',
      render: (_: unknown, record: AuditLog) => (
        <Popconfirm
          title="删除审计日志"
          description="该操作会永久删除此条审计记录，不可恢复。"
          okText="确认删除"
          cancelText="取消"
          okButtonProps={{ danger: true }}
          onConfirm={() => handleDelete(record)}
        >
          <Button
            type="link"
            danger
            size="small"
            icon={<DeleteOutlined />}
            loading={deletingId === record.id}
          >
            删除
          </Button>
        </Popconfirm>
      ),
    },
  ];

  const detailColumns: ColumnsType<[string, unknown]> = [
    {
      title: '字段',
      dataIndex: 0,
      key: 'field',
      width: 220,
      render: (value: string, row) =>
        detailFieldLabels[value] || detailFieldLabels[row[0]] || value,
    },
    {
      title: '值',
      dataIndex: 1,
      key: 'value',
      render: (value: unknown, row) => (
        <Text
          code
          style={{
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            fontSize: '12px',
          }}
        >
          {formatDetailValue(row[0], value)}
        </Text>
      ),
    },
  ];

  return (
    <div>
      <div
        style={{
          marginBottom: 16,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div>
          <Title level={4} style={{ margin: 0 }}>
            审计日志
          </Title>
          <Text type="secondary">查看项目、任务、配置与沙箱相关的操作记录</Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => handleSearch()}>
            刷新
          </Button>
          <Popconfirm
            title="清空审计日志"
            description="将删除当前系统中的全部审计日志，不可恢复。"
            okText="确认清空"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={handleClear}
          >
            <Button danger icon={<DeleteOutlined />} loading={clearing}>
              清空日志
            </Button>
          </Popconfirm>
        </Space>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <Space wrap>
          <Select
            allowClear
            placeholder="动作类型"
            style={{ width: 150 }}
            options={knownActions}
            value={action}
            onChange={(value) => setAction(value)}
          />
          <Input
            allowClear
            placeholder="操作人"
            style={{ width: 160 }}
            value={operator}
            onChange={(event) => setOperator(event.target.value)}
            onPressEnter={handleSearch}
          />
          <Button type="primary" icon={<SearchOutlined />} onClick={handleSearch}>
            查询
          </Button>
        </Space>
      </Card>

      <Card>
        {total === 0 && items.length === 0 && !loading ? (
          <Empty description="暂无审计日志" />
        ) : (
          <>
          <Table
            rowKey="id"
            columns={columns}
            dataSource={items}
            loading={loading}
            size="small"
            scroll={{ x: 1200 }}
            expandable={{
              expandedRowRender: (record) => {
                if (!record.detail) {
                  return <Text type="secondary">无详情信息</Text>;
                }
                const rows = Object.entries(record.detail).map(
                  ([key, value]) => [key, value] as [string, unknown]
                );
                return (
                  <div style={{ maxHeight: 360, overflow: 'auto' }}>
                    <Table
                      rowKey={(row) => row[0]}
                      columns={detailColumns}
                      dataSource={rows}
                      pagination={false}
                      size="small"
                      bordered
                    />
                  </div>
                );
              },
            }}
            pagination={false}
          />
          <div
            style={{
              marginTop: 16,
              display: 'flex',
              justifyContent: 'flex-end',
            }}
          >
            <Pagination
              current={page}
              pageSize={size}
              total={total}
              showSizeChanger
              showQuickJumper
              pageSizeOptions={[5, 10, 20, 50, 100]}
              showTotal={(value) => `共 ${value} 条`}
              onChange={(nextPage, nextSize) => {
                setPage(nextPage);
                setSize(nextSize);
                load(nextPage, nextSize, action, operator);
              }}
            />
          </div>
          </>
        )}
      </Card>
    </div>
  );
};

export default AuditLogPage;
