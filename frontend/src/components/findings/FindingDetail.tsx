import React, { useState, useCallback } from 'react';
import { Descriptions, Divider, Typography, Tag } from 'antd';
import type { Finding } from '../../api/findings';
import SeverityTag from '../common/SeverityTag';
import { detectedByLabel } from '../../utils/labels';
import TaintPath from './TaintPath';
import PocEvidencePanel from './PocEvidencePanel';
import PatchPanel from './PatchPanel';

const { Text, Paragraph } = Typography;

interface FindingDetailProps {
  finding: Finding;
  onStatusChange?: () => void;
}

/** Render source/sink code snippet block without source file labels. */
function CodeBlock({ label, code }: {
  label: string;
  code: string | null;
}) {
  return (
    <div style={{ marginBottom: 12 }}>
      <Text strong style={{ fontSize: '13px' }}>
        {label}
      </Text>
      {code ? (
        <pre
          style={{
            background: '#f6f8fa',
            padding: '8px 12px',
            borderRadius: 4,
            fontSize: '12px',
            margin: '4px 0 0',
            overflowX: 'auto',
            whiteSpace: 'pre-wrap',
            border: '1px solid #e1e4e8',
          }}
        >
          {code}
        </pre>
      ) : (
        <div style={{ color: '#999', fontSize: '12px', marginTop: 4 }}>
          无数据
        </div>
      )}
    </div>
  );
}

/** Expanded finding detail: metadata + source/sink + taint path + snippet + remediation + PoC evidence. */
const FindingDetail: React.FC<FindingDetailProps> = ({
  finding,
  onStatusChange,
}) => {
  const [pocRefreshKey, setPocRefreshKey] = useState(0);
  const [patchRefreshKey, setPatchRefreshKey] = useState(0);

  // Called by parent or WS event to trigger evidence re-fetch
  const refreshEvidence = useCallback(() => {
    setPocRefreshKey((k) => k + 1);
  }, []);

  // Called by parent or WS event to trigger patch re-fetch
  const refreshPatch = useCallback(() => {
    setPatchRefreshKey((k) => k + 1);
  }, []);

  return (
    <div style={{ padding: '8px 0' }}>
      {/* Metadata row */}
      <Descriptions
        size="small"
        column={4}
        bordered
        style={{ marginBottom: 16 }}
      >
        <Descriptions.Item label="漏洞 ID" span={2}>
          <Text code style={{ fontSize: '11px' }}>
            {finding.id}
          </Text>
        </Descriptions.Item>
        <Descriptions.Item label="弱点编号">
          {finding.cwe_id || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="风险类别">
          {finding.owasp || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="严重等级">
          <SeverityTag
            severity={finding.severity}
            cvssScore={finding.cvss_score}
          />
        </Descriptions.Item>
        <Descriptions.Item label="风险向量" span={3}>
          {finding.cvss_vector ? (
            <Text
              code
              style={{ fontSize: '11px', wordBreak: 'break-all' }}
            >
              {finding.cvss_vector}
            </Text>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="置信度">
          {(finding.confidence * 100).toFixed(0)}%
        </Descriptions.Item>
        <Descriptions.Item label="检测工具">
          <Tag>{detectedByLabel(finding.detected_by)}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label="代码位置" span={2}>
          {finding.line_start ? `第 ${finding.line_start} 行` : '-'}
        </Descriptions.Item>
      </Descriptions>

      <Divider orientation="left" style={{ fontSize: '13px' }}>
        污点入口 → 危险汇聚点
      </Divider>

      {/* Source code */}
      <CodeBlock
        label="污点入口"
        code={finding.source_code}
      />

      {/* Sink code */}
      <CodeBlock
        label="危险汇聚点"
        code={finding.sink_code}
      />

      {/* Snippet */}
      {finding.snippet && (
        <CodeBlock
          label="命中代码片段"
          code={finding.snippet}
        />
      )}

      {/* Taint path */}
      <Divider orientation="left" style={{ fontSize: '13px' }}>
        污点传播路径
      </Divider>
      <TaintPath steps={finding.taint_path || []} />

      {/* Remediation */}
      {finding.remediation && (
        <>
          <Divider orientation="left" style={{ fontSize: '13px' }}>
            修复建议
          </Divider>
          <Paragraph style={{ fontSize: '13px', color: '#333' }}>
            {finding.remediation}
          </Paragraph>
        </>
      )}

      {/* PoC Evidence */}
      <PocEvidencePanel
        findingId={finding.id}
        findingStatus={finding.status}
        refreshKey={pocRefreshKey}
      />

      {/* AI Patch */}
      <PatchPanel
        findingId={finding.id}
        findingStatus={finding.status}
        refreshKey={patchRefreshKey}
        onStatusChange={onStatusChange}
      />
    </div>
  );
};

export default FindingDetail;
