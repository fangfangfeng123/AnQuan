import React, { useEffect, useState, useCallback } from 'react';
import {
  Divider,
  Spin,
  Empty,
  Tag,
  Typography,
  Button,
  Space,
  Tooltip,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ReloadOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import { listFindingEvidence, type PocEvidence } from '../../api/poc';
import { pickLabel, pocTypeLabels } from '../../utils/labels';

const { Text, Paragraph } = Typography;

interface PocEvidencePanelProps {
  findingId: string;
  findingStatus: string;
  /** External refresh trigger — when this number changes, re-fetch evidence. */
  refreshKey: number;
}

/** Format ISO timestamp to zh-CN locale string. */
function formatTime(iso: string | null): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString('zh-CN');
  } catch {
    return iso;
  }
}

/** Render a code block with label and monospace formatting. */
function CodeBlock({
  label,
  content,
  lang,
}: {
  label: string;
  content: string | null;
  lang?: string;
}) {
  if (!content) {
    return (
      <div style={{ marginBottom: 8 }}>
        <Text strong style={{ fontSize: '12px' }}>
          {label}
        </Text>
        <div style={{ color: '#999', fontSize: '12px', marginTop: 2 }}>
          无数据
        </div>
      </div>
    );
  }
  return (
    <div style={{ marginBottom: 8 }}>
      <Text strong style={{ fontSize: '12px' }}>
        {label}
      </Text>
      {lang && (
        <Tag
          style={{ marginLeft: 6, fontSize: '10px', lineHeight: '16px' }}
        >
          {lang}
        </Tag>
      )}
      <pre
        style={{
          background: '#0d1117',
          color: '#c9d1d9',
          padding: '8px 12px',
          borderRadius: 6,
          fontSize: '12px',
          lineHeight: '1.5',
          margin: '4px 0 0',
          overflowX: 'auto',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          maxHeight: '300px',
          overflowY: 'auto',
        }}
      >
        {content}
      </pre>
    </div>
  );
}

/** Render HTTP status badge. */
function HttpStatusBadge({ status }: { status: number | null }) {
  if (status === null) {
    return <Tag>无</Tag>;
  }
  let color = 'default';
  if (status >= 200 && status < 300) color = 'green';
  else if (status >= 300 && status < 400) color = 'blue';
  else if (status >= 400 && status < 500) color = 'orange';
  else if (status >= 500) color = 'red';
  return (
    <Tag color={color} style={{ fontWeight: 600 }}>
      {status}
    </Tag>
  );
}

/** Validation status label and color. */
const VALIDATION_LABEL: Record<string, string> = {
  passed: '验证通过',
  failed: '验证失败',
  error: '执行异常',
  pending: '待验证',
};

const VALIDATION_COLOR: Record<string, string> = {
  passed: 'green',
  failed: 'orange',
  error: 'red',
  pending: 'default',
};

/** PoC Evidence panel — displays request/response, expected/actual features, verification result. */
const PocEvidencePanel: React.FC<PocEvidencePanelProps> = ({
  findingId,
  findingStatus,
  refreshKey,
}) => {
  const [evidences, setEvidences] = useState<PocEvidence[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchEvidence = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listFindingEvidence(findingId);
      setEvidences(data.items);
    } catch {
      setEvidences([]);
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    fetchEvidence();
  }, [fetchEvidence, refreshKey]);

  // Build readable request text
  const formatRequest = (ev: PocEvidence): string => {
    const lines: string[] = [];
    const method = ev.request_method || 'GET';
    const url = ev.request_url || '';
    lines.push(`${method} ${url}`);
    if (ev.request_headers) {
      for (const [k, v] of Object.entries(ev.request_headers)) {
        lines.push(`${k}: ${v}`);
      }
    }
    lines.push('');
    if (ev.request_body) {
      lines.push(ev.request_body);
    }
    return lines.join('\n');
  };

  // Build readable response text
  const formatResponse = (ev: PocEvidence): string => {
    const lines: string[] = [];
    if (ev.response_status) {
      lines.push(`HTTP ${ev.response_status}`);
    }
    if (ev.response_headers) {
      for (const [k, v] of Object.entries(ev.response_headers)) {
        lines.push(`${k}: ${v}`);
      }
    }
    lines.push('');
    if (ev.response_body) {
      // Truncate very long bodies for display
      const body = ev.response_body;
      if (body.length > 2000) {
        lines.push(body.substring(0, 2000));
        lines.push(`\n...（已截断，共 ${body.length} 个字符）`);
      } else {
        lines.push(body);
      }
    }
    return lines.join('\n');
  };

  const hasEvidence = evidences.length > 0;
  const showPanel =
    findingStatus === 'verified' ||
    findingStatus === 'latent' ||
    findingStatus === 'false_positive' ||
    hasEvidence;

  if (!showPanel) {
    // Only show for findings that have been through PoC or could have evidence
    return null;
  }

  return (
    <div>
      <Divider orientation="left" style={{ fontSize: '13px' }}>
        动态验证证据
        <Button
          type="text"
          size="small"
          icon={<ReloadOutlined />}
          onClick={fetchEvidence}
          loading={loading}
          style={{ marginLeft: 8 }}
        />
      </Divider>

      <Spin spinning={loading}>
        {!hasEvidence && !loading ? (
          <Empty
            description={
              findingStatus === 'verified'
                ? '暂无证据数据（可能验证记录未保存）'
                : findingStatus === 'unverified'
                  ? '该漏洞尚未进行动态验证'
                  : '该漏洞未通过动态验证，无有效证据'
            }
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        ) : (
          <div>
            {evidences.map((ev, idx) => (
              <div
                key={ev.id}
                style={{
                  border: '1px solid #e1e4e8',
                  borderRadius: 6,
                  padding: '12px 16px',
                  marginBottom: 12,
                  background: '#fafbfc',
                }}
              >
                {/* Evidence header */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 8,
                  }}
                >
                  <Space>
                    <Text strong style={{ fontSize: '13px' }}>
                      证据 #{idx + 1}
                    </Text>
                    <Tag>{pickLabel(ev.poc_type, pocTypeLabels)}</Tag>
                    <HttpStatusBadge status={ev.response_status} />
                    {ev.matched ? (
                      <Tag
                        icon={<CheckCircleOutlined />}
                        color="green"
                      >
                        特征匹配
                      </Tag>
                    ) : (
                      <Tag
                        icon={<CloseCircleOutlined />}
                        color="red"
                      >
                        特征不匹配
                      </Tag>
                    )}
                    <Tag color={VALIDATION_COLOR[ev.validation_status] || 'default'}>
                      {VALIDATION_LABEL[ev.validation_status] || ev.validation_status}
                    </Tag>
                  </Space>
                  <Tooltip title={`执行时间: ${formatTime(ev.executed_at)}`}>
                    <Text
                      type="secondary"
                      style={{ fontSize: '11px' }}
                    >
                      <ClockCircleOutlined />{' '}
                      {formatTime(ev.executed_at)}
                    </Text>
                  </Tooltip>
                </div>

                {/* Expected vs Actual features */}
                <div
                  style={{
                    display: 'flex',
                    gap: 16,
                    marginBottom: 8,
                    flexWrap: 'wrap',
                  }}
                >
                  <div style={{ flex: '1 1 300px' }}>
                    <Text
                      strong
                      style={{ fontSize: '12px', color: '#666' }}
                    >
                      预期特征:
                    </Text>
                    <Paragraph
                      style={{
                        fontSize: '12px',
                        margin: '2px 0 0',
                        color: '#333',
                        background: '#f0f5ff',
                        padding: '4px 8px',
                        borderRadius: 4,
                      }}
                    >
                      {ev.expected_feature || '-'}
                    </Paragraph>
                  </div>
                  <div style={{ flex: '1 1 300px' }}>
                    <Text
                      strong
                      style={{ fontSize: '12px', color: '#666' }}
                    >
                      实际特征:
                    </Text>
                    <Paragraph
                      style={{
                        fontSize: '12px',
                        margin: '2px 0 0',
                        color: '#333',
                        background: ev.matched ? '#f6ffed' : '#fff2f0',
                        padding: '4px 8px',
                        borderRadius: 4,
                      }}
                    >
                      {ev.actual_feature || '-'}
                    </Paragraph>
                  </div>
                </div>

                {/* Request and Response */}
                <div
                  style={{
                    display: 'flex',
                    gap: 12,
                    flexWrap: 'wrap',
                  }}
                >
                  <div style={{ flex: '1 1 400px', minWidth: 300 }}>
                    <CodeBlock
                      label="请求报文"
                      lang="HTTP"
                      content={formatRequest(ev)}
                    />
                  </div>
                  <div style={{ flex: '1 1 400px', minWidth: 300 }}>
                    <CodeBlock
                      label="响应报文"
                      lang="HTTP"
                      content={formatResponse(ev)}
                    />
                  </div>
                </div>

                {/* Error message if any */}
                {ev.error_message && (
                  <div style={{ marginTop: 4 }}>
                    <Text
                      strong
                      style={{ fontSize: '12px', color: '#cf1322' }}
                    >
                      异常信息:
                    </Text>
                    <Paragraph
                      style={{
                        fontSize: '12px',
                        margin: '2px 0 0',
                        color: '#cf1322',
                        background: '#fff2f0',
                        padding: '4px 8px',
                        borderRadius: 4,
                      }}
                    >
                      {ev.error_message}
                    </Paragraph>
                  </div>
                )}

                {/* Verified timestamp */}
                {ev.verified_at && (
                  <div style={{ marginTop: 4 }}>
                    <Text
                      type="secondary"
                      style={{ fontSize: '11px' }}
                    >
                      验证完成时间: {formatTime(ev.verified_at)}
                    </Text>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Spin>
    </div>
  );
};

export default PocEvidencePanel;
