import React, { useState } from 'react';
import {
  Table,
  Tooltip,
  Empty,
  Spin,
  Typography,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import type { Finding } from '../../api/findings';
import SeverityTag, {
  FindingStatusTag,
  VulnTypeTag,
} from '../common/SeverityTag';
import { detectedByLabel } from '../../utils/labels';
import FindingDetail from './FindingDetail';

const { Text } = Typography;

interface FindingTableProps {
  findings: Finding[];
  loading: boolean;
  onNeedRefresh?: () => void;
}

/** Format line number without exposing source file paths. */
function formatLocation(f: Finding): string {
  return f.line_start ? `第 ${f.line_start} 行` : '代码位置';
}

/** Format source-to-sink summary. */
function formatSourceSink(f: Finding): string {
  const src = f.source_code ? f.source_code.substring(0, 40) : '-';
  const snk = f.sink_code ? f.sink_code.substring(0, 40) : '-';
  return `入口: ${src} -> 汇聚点: ${snk}`;
}

/** Finding list table with expandable detail row. */
const FindingTable: React.FC<FindingTableProps> = ({
  findings,
  loading,
  onNeedRefresh,
}) => {
  const [expandedKeys, setExpandedKeys] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const columns: ColumnsType<Finding> = [
    {
      title: '漏洞类型',
      dataIndex: 'vuln_type',
      key: 'vuln_type',
      width: 120,
      render: (val: string) => <VulnTypeTag vulnType={val} />,
    },
    {
      title: '严重等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 130,
      render: (_: string, record: Finding) => (
        <SeverityTag severity={record.severity} cvssScore={record.cvss_score} />
      ),
      sorter: (a, b) => {
        const order: Record<string, number> = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
          info: 0,
        };
        return (order[a.severity] || 0) - (order[b.severity] || 0);
      },
    },
    {
      title: '验证状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (val: string) => <FindingStatusTag status={val} />,
    },
    {
      title: '弱点编号',
      dataIndex: 'cwe_id',
      key: 'cwe_id',
      width: 100,
      render: (val: string | null) =>
        val ? (
          <Text code style={{ fontSize: '12px' }}>
            {val}
          </Text>
        ) : (
          '-'
        ),
    },
    {
      title: '代码位置',
      key: 'location',
      width: 110,
      ellipsis: true,
      render: (_: unknown, record: Finding) => (
        <Tooltip title={formatLocation(record)}>
          <Text code style={{ fontSize: '11px' }} ellipsis>
            {formatLocation(record)}
          </Text>
        </Tooltip>
      ),
    },
    {
      title: '污点入口 -> 汇聚点',
      key: 'source_sink',
      ellipsis: true,
      render: (_: unknown, record: Finding) => (
        <Tooltip title={formatSourceSink(record)}>
          <Text style={{ fontSize: '11px', color: '#666' }} ellipsis>
            {formatSourceSink(record)}
          </Text>
        </Tooltip>
      ),
    },
    {
      title: '检测工具',
      dataIndex: 'detected_by',
      key: 'detected_by',
      width: 110,
      render: (val: string) => (
        <Text type="secondary" style={{ fontSize: '12px' }}>
          {detectedByLabel(val)}
        </Text>
      ),
    },
  ];

  return (
    <Spin spinning={loading}>
      {findings.length === 0 && !loading ? (
        <Empty
          description="暂无漏洞发现"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      ) : (
        <Table<Finding>
          rowKey="id"
          columns={columns}
          dataSource={findings}
          pagination={{
            current: page,
            pageSize,
            showSizeChanger: true,
            showQuickJumper: true,
            onChange: (nextPage, nextSize) => {
              setPage(nextPage);
              setPageSize(nextSize);
              setExpandedKeys([]);
            },
          }}
          size="small"
          expandable={{
            expandedRowKeys: expandedKeys,
            onExpand: (expanded, record) => {
              setExpandedKeys(
                expanded
                  ? [...expandedKeys, record.id]
                  : expandedKeys.filter((k) => k !== record.id),
              );
            },
            expandedRowRender: (record: Finding) => (
              <FindingDetail
                key={record.id}
                finding={record}
                onStatusChange={onNeedRefresh}
              />
            ),
          }}
        />
      )}
    </Spin>
  );
};

export default FindingTable;
