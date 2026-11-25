import React, { useEffect, useState } from 'react';
import {
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  message,
  Popconfirm,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  DownloadOutlined,
  DeleteOutlined,
  EyeOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import {
  deleteReport,
  downloadReportFile,
  getReportDetail,
  listReports,
  type ReportChainEntry,
  type ReportDetail,
  type ReportFileFormat,
  type ReportFindingEntry,
  type ReportItem,
  type ReportRemediationEntry,
} from '../api/reports';
import { vulnTypeLabels } from '../utils/labels';
import { useAuthStore } from '../stores/auth';

const { Title, Text } = Typography;

const riskLabels: Record<string, string> = {
  critical: '极高危',
  high: '高危',
  medium: '中危',
  low: '低危',
  secure: '安全',
};

const riskColors: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  secure: 'green',
};

const severityLabels: Record<string, string> = {
  critical: '极高危',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const statusLabels: Record<string, string> = {
  unverified: '疑似',
  verified: '已验证',
  latent: '潜在隐患',
  false_positive: '误报',
  adopted: '已采纳',
};

const statusColors: Record<string, string> = {
  unverified: 'orange',
  verified: 'green',
  latent: 'gold',
  false_positive: 'default',
  adopted: 'cyan',
};

const scopeLabels: Record<string, string> = {
  project_name: '项目名称',
  project_id: '项目 ID',
  task_id: '任务 ID',
  source_type: '源码来源',
  source_input: '源码路径/地址',
  language: '主语言',
  framework: '主框架',
  dependencies: '依赖清单',
  service_ports: '服务端口',
  entry_points: '入口文件',
  run_command: '启动命令',
  created_at: '任务创建时间',
  started_at: '评估开始时间',
  completed_at: '评估完成时间',
};

const sourceTypeLabels: Record<string, string> = {
  git: 'Git 仓库',
  archive: '压缩包',
  directory: '文件夹',
  file: '单个文件',
  local_path: '本地路径',
};

const languageLabels: Record<string, string> = {
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

const frameworkLabels: Record<string, string> = {
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

function renderRisk(value: string | null) {
  return (
    <Tag color={riskColors[value || ''] || 'default'}>
      {riskLabels[value || ''] || value || '-'}
    </Tag>
  );
}

function formatTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString('zh-CN') : '-';
}

function formatScopeValue(key: string, value: unknown): string {
  const text = value === null || value === undefined ? '' : String(value);

  if (key === 'source_type') {
    return sourceTypeLabels[text.toLowerCase()] || text || '未识别';
  }
  if (key === 'language') {
    return languageLabels[text.toLowerCase()] || text || '未识别';
  }
  if (key === 'framework') {
    return frameworkLabels[text.toLowerCase()] || text || '未识别';
  }
  if (key === 'run_command') {
    return text || '未识别';
  }
  if (key === 'source_input') {
    return text || '未设置';
  }
  if (key === 'created_at' || key === 'started_at' || key === 'completed_at') {
    if (!text) {
      return key === 'created_at' ? '未记录' : key === 'started_at' ? '未开始' : '未完成';
    }
    return formatTime(text);
  }
  if (key === 'dependencies') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return '未识别';
    }
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return '未识别';
    return entries
      .map(([name, version]) => `${name} ${version || ''}`.trim())
      .join('、');
  }
  if (key === 'service_ports') {
    if (!Array.isArray(value) || value.length === 0) return '未识别';
    return value
      .map((item) => {
        const port = item as Record<string, unknown>;
        const description = port.description ? `：${port.description}` : '';
        return `端口 ${port.port ?? item}${description}`;
      })
      .join('；');
  }
  if (key === 'entry_points') {
    if (!Array.isArray(value) || value.length === 0) return '未识别';
    return value
      .map((item) => {
        const entry = item as Record<string, unknown>;
        const line = entry.line ? `:${entry.line}` : '';
        return `${entry.file || entry.name || ''}${line}`;
      })
      .filter(Boolean)
      .join('、');
  }
  if (text === '') return '-';
  if (typeof value === 'object') return JSON.stringify(value);
  return text;
}

function availableFiles(record: ReportItem): ReportFileFormat[] {
  const files: ReportFileFormat[] = [];
  if (record.markdown_path) files.push('markdown');
  if (record.html_path) files.push('html');
  if (record.pdf_path) files.push('pdf');
  return files;
}

const ReportCenterPage: React.FC = () => {
  const [items, setItems] = useState<ReportItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(3);
  const [loading, setLoading] = useState(false);
  const [activeReport, setActiveReport] = useState<ReportItem | null>(null);
  const [detail, setDetail] = useState<ReportDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const role = useAuthStore((state) => state.user?.role);
  const canDeleteReport = role === 'admin';

  const load = async (nextPage = page, nextSize = size) => {
    setLoading(true);
    try {
      const data = await listReports({ page: nextPage, size: nextSize });
      setItems(data.items);
      setTotal(data.total);
      setPage(data.page);
      setSize(data.size);
    } catch (e) {
      message.error((e as Error).message || '报告列表加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load(1);
  }, []);

  const openDetail = async (record: ReportItem) => {
    setActiveReport(record);
    setDetail(null);
    setDetailLoading(true);
    try {
      const data = await getReportDetail(record.id);
      setDetail(data);
    } catch (e) {
      message.error((e as Error).message || '报告详情加载失败');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleDownload = async (
    record: ReportItem,
    format: ReportFileFormat
  ) => {
    try {
      await downloadReportFile(record.id, format);
      message.success(`${format.toUpperCase()} 报告下载已开始`);
    } catch (e) {
      message.error((e as Error).message || '报告下载失败');
    }
  };

  const handleDeleteReport = async (record: ReportItem) => {
    try {
      await deleteReport(record.id);
      message.success(`报告 ${record.id.slice(0, 8)}... 已删除`);
      if (activeReport?.id === record.id) {
        setActiveReport(null);
        setDetail(null);
      }
      const nextPage = items.length === 1 && page > 1 ? page - 1 : page;
      load(nextPage);
    } catch (e) {
      message.error((e as Error).message || '报告删除失败');
    }
  };

  const columns: ColumnsType<ReportItem> = [
    {
      title: '项目',
      dataIndex: 'project_name',
      key: 'project_name',
      ellipsis: true,
      render: (value: string | null) => value || '-',
    },
    {
      title: '风险等级',
      dataIndex: 'overall_risk',
      key: 'overall_risk',
      width: 110,
      render: renderRisk,
    },
    {
      title: '最高风险评分',
      dataIndex: 'overall_cvss',
      key: 'overall_cvss',
      width: 100,
      render: (value: number | null) =>
        value === null || value === undefined ? '-' : value.toFixed(1),
    },
    {
      title: '漏洞数',
      dataIndex: 'total_findings',
      key: 'total_findings',
      width: 90,
      render: (value: number) => value ?? 0,
    },
    {
      title: '严重等级分布',
      key: 'severity_counts',
      width: 260,
      render: (_: unknown, record: ReportItem) => (
        <Space size={[4, 4]} wrap>
          <Tag color="red">严重 {record.critical_count}</Tag>
          <Tag color="orange">高 {record.high_count}</Tag>
          <Tag color="gold">中 {record.medium_count}</Tag>
          <Tag color="blue">低 {record.low_count}</Tag>
        </Space>
      ),
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 70,
      render: (value: number) => `v${value}`,
    },
    {
      title: '生成时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 170,
      render: formatTime,
    },
    {
      title: '操作',
      key: 'actions',
      width: 290,
      render: (_: unknown, record: ReportItem) => {
        const files = availableFiles(record);
        return (
          <Space size={4}>
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => openDetail(record)}
            >
              预览
            </Button>
            {files.includes('markdown') && (
              <Button
                size="small"
                icon={<DownloadOutlined />}
                onClick={() => handleDownload(record, 'markdown')}
              >
                Markdown
              </Button>
            )}
            {files.includes('html') && (
              <Button
                size="small"
                icon={<DownloadOutlined />}
                onClick={() => handleDownload(record, 'html')}
              >
                HTML
              </Button>
            )}
            {files.includes('pdf') && (
              <Button
                size="small"
                icon={<DownloadOutlined />}
                onClick={() => handleDownload(record, 'pdf')}
              >
                PDF
              </Button>
            )}
            {canDeleteReport && (
              <Popconfirm
                title="彻底删除报告"
                description="将删除该报告及其文档、网页、PDF 文件，不可恢复。"
                okText="确认删除"
                cancelText="取消"
                okButtonProps={{ danger: true }}
                onConfirm={() => handleDeleteReport(record)}
              >
                <Button danger size="small" icon={<DeleteOutlined />}>
                  删除
                </Button>
              </Popconfirm>
            )}
          </Space>
        );
      },
    },
  ];

  const findingColumns: ColumnsType<ReportFindingEntry> = [
    {
      title: '类型',
      dataIndex: 'vuln_type',
      key: 'vuln_type',
      width: 150,
      render: (value: string) => vulnTypeLabels[value] || value || '-',
    },
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (value: string, record: ReportFindingEntry) => (
        <Tag color={riskColors[value] || 'default'}>
          {severityLabels[value] || value}
          {record.cvss_score ? ` ${record.cvss_score.toFixed(1)}` : ''}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (value: string) => (
        <Tag color={statusColors[value] || 'default'}>
          {statusLabels[value] || value}
        </Tag>
      ),
    },
    {
      title: '代码位置',
      key: 'location',
      render: (_: unknown, record: ReportFindingEntry) => {
        return (
          <Text code ellipsis style={{ fontSize: '12px' }}>
            {record.line_start ? `第 ${record.line_start} 行` : '-'}
          </Text>
        );
      },
    },
    {
      title: '修复建议',
      dataIndex: 'remediation',
      key: 'remediation',
      ellipsis: true,
      render: (value: string | null) => value || '-',
    },
  ];

  const chainColumns: ColumnsType<ReportChainEntry> = [
    { title: '攻击链名称', dataIndex: 'name', key: 'name' },
    {
      title: '等级',
      dataIndex: 'overall_severity',
      key: 'overall_severity',
      width: 100,
      render: renderRisk,
    },
    {
      title: '风险评分',
      dataIndex: 'overall_cvss',
      key: 'overall_cvss',
      width: 90,
      render: (value: number | null) =>
        value === null || value === undefined ? '-' : value.toFixed(1),
    },
    {
      title: '节点/边',
      key: 'counts',
      width: 100,
      render: (_: unknown, record: ReportChainEntry) =>
        `${record.node_count ?? 0} / ${record.edge_count ?? 0}`,
    },
    {
      title: '最终影响',
      dataIndex: 'final_impact',
      key: 'final_impact',
      ellipsis: true,
    },
  ];

  const remediationColumns: ColumnsType<ReportRemediationEntry> = [
    {
      title: '类型',
      dataIndex: 'vuln_type',
      key: 'vuln_type',
      width: 140,
      render: (value: string) => vulnTypeLabels[value] || value || '-',
    },
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (value: string) => (
        <Tag color={riskColors[value] || 'default'}>
          {severityLabels[value] || value}
        </Tag>
      ),
    },
    {
      title: '代码位置',
      dataIndex: 'line_start',
      key: 'line_start',
      ellipsis: true,
      render: (value: number | null) => (value ? `第 ${value} 行` : '-'),
    },
    {
      title: '整改说明',
      dataIndex: 'remediation',
      key: 'remediation',
      ellipsis: true,
    },
    {
      title: '补丁说明',
      dataIndex: 'patch_description',
      key: 'patch_description',
      width: 180,
      ellipsis: true,
      render: (value: string) => value || '无',
    },
  ];

  const renderDetailContent = () => {
    if (!activeReport) return null;
    const report = detail || activeReport;
    const projectName = activeReport?.project_name || detail?.project_name || '-';
    const summary = detail?.sections?.executive_summary;
    const scope = detail?.sections?.scope;
    const findings = detail?.sections?.findings || [];
    const chains = detail?.sections?.attack_chains || [];
    const remediations = detail?.sections?.remediation || [];

    return (
      <Spin spinning={detailLoading}>
        <Space style={{ marginBottom: 12 }}>
          {availableFiles(report).map((format) => (
            <Button
              key={format}
              type="primary"
              ghost
              icon={<DownloadOutlined />}
              onClick={() => handleDownload(report, format)}
            >
              下载 {format.toUpperCase()}
            </Button>
          ))}
        </Space>

        <Tabs
          items={[
            {
              key: 'overview',
              label: '概览',
              children: (
                <>
                  <Card size="small" style={{ marginBottom: 12 }}>
                    <Space size={24} wrap>
                      <Statistic
                        title="整体风险"
                        value={
                          riskLabels[report.overall_risk] ||
                          report.overall_risk ||
                          '-'
                        }
                      />
                      <Statistic
                        title="最高风险评分"
                        value={report.overall_cvss ?? 0}
                        precision={1}
                      />
                      <Statistic title="漏洞总数" value={report.total_findings} />
                      <Statistic title="严重" value={report.critical_count} />
                      <Statistic title="高危" value={report.high_count} />
                      <Statistic title="中危" value={report.medium_count} />
                      <Statistic title="低危" value={report.low_count} />
                    </Space>
                  </Card>
                  <Descriptions column={1} bordered size="small">
                    <Descriptions.Item label="项目">
                      {projectName}
                    </Descriptions.Item>
                    <Descriptions.Item label="任务 ID">
                      <Text code>{report.task_id}</Text>
                    </Descriptions.Item>
                    <Descriptions.Item label="版本">v{report.version}</Descriptions.Item>
                    <Descriptions.Item label="生成时间">
                      {formatTime(report.created_at)}
                    </Descriptions.Item>
                    <Descriptions.Item label="执行摘要">
                      {summary?.summary_text || '-'}
                    </Descriptions.Item>
                    <Descriptions.Item label="攻击链">
                      {summary?.total_chains ?? 0} 条
                      {summary?.multi_step_chains
                        ? `，其中 ${summary.multi_step_chains} 条多步链路`
                        : ''}
                    </Descriptions.Item>
                  </Descriptions>
                  {scope && Object.keys(scope).length > 0 && (
                    <Descriptions
                      title="评估范围"
                      column={1}
                      bordered
                      size="small"
                      style={{ marginTop: 16 }}
                    >
                      {Object.entries(scope).map(([key, value]) => (
                        <Descriptions.Item
                          key={key}
                          label={scopeLabels[key] || key}
                        >
                          {formatScopeValue(key, value)}
                        </Descriptions.Item>
                      ))}
                    </Descriptions>
                  )}
                </>
              ),
            },
            {
              key: 'findings',
              label: `漏洞详情 (${findings.length})`,
              children:
                findings.length === 0 ? (
                  <Empty description="暂无漏洞详情" />
                ) : (
                  <Table
                    rowKey="id"
                    columns={findingColumns}
                    dataSource={findings}
                    size="small"
                    pagination={{
                      pageSize: 8,
                      showSizeChanger: false,
                      showQuickJumper: true,
                    }}
                    scroll={{ x: 900 }}
                  />
                ),
            },
            {
              key: 'chains',
              label: `攻击链 (${chains.length})`,
              children:
                chains.length === 0 ? (
                  <Empty description="暂无攻击链" />
                ) : (
                  <Table
                    rowKey="id"
                    columns={chainColumns}
                    dataSource={chains}
                    size="small"
                    pagination={false}
                    scroll={{ x: 800 }}
                  />
                ),
            },
            {
              key: 'remediation',
              label: `整改清单 (${remediations.length})`,
              children:
                remediations.length === 0 ? (
                  <Empty description="暂无整改建议" />
                ) : (
                  <Table
                    rowKey="finding_id"
                    columns={remediationColumns}
                    dataSource={remediations}
                    size="small"
                    pagination={{
                      pageSize: 8,
                      showSizeChanger: false,
                      showQuickJumper: true,
                    }}
                    scroll={{ x: 900 }}
                  />
                ),
            },
          ]}
        />
      </Spin>
    );
  };

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
            安全报告中心
          </Title>
          <Text type="secondary">集中预览、核对并导出结构化评估报告</Text>
        </div>
        <Button icon={<ReloadOutlined />} onClick={() => load(page)}>
          刷新
        </Button>
      </div>

      <Card>
        {items.length === 0 && !loading ? (
          <Empty description="暂无报告" />
        ) : (
          <Table
            rowKey="id"
            columns={columns}
            dataSource={items}
            loading={loading}
            size="small"
            scroll={{ x: 1250 }}
            pagination={{
              current: page,
              total,
              pageSize: size,
              showSizeChanger: true,
              showQuickJumper: true,
              pageSizeOptions: [3, 5, 10, 20, 50],
              onChange: (nextPage, nextSize) => {
                setPage(nextPage);
                setSize(nextSize);
                load(nextPage, nextSize);
              },
              showTotal: (value) => `共 ${value} 份报告`,
            }}
          />
        )}
      </Card>

      <Drawer
        title={`${activeReport?.project_name || detail?.project_name || '报告'} 详情`}
        width={980}
        open={Boolean(activeReport)}
        onClose={() => {
          setActiveReport(null);
          setDetail(null);
        }}
      >
        {renderDetailContent()}
      </Drawer>
    </div>
  );
};

export default ReportCenterPage;
