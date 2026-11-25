import React, { useEffect, useState, useCallback } from 'react';
import {
  Button,
  Divider,
  Empty,
  Spin,
  Tag,
  Typography,
  Space,
  Tooltip,
  message,
  Alert,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import {
  createPatch,
  getPatch,
  getPatchByFinding,
  validatePatch,
  adoptPatch,
  rejectPatch,
  exportPatchZip,
  type FixPatch,
} from '../../api/patches';
import DiffViewer from '../common/DiffViewer';

const { Text, Paragraph } = Typography;

interface PatchPanelProps {
  findingId: string;
  findingStatus: string;
  onStatusChange?: () => void;
  /** External refresh trigger (e.g., from WS patch_ready event). */
  refreshKey: number;
}

/** Adopt status label and color. */
const ADOPT_LABEL: Record<string, string> = {
  pending: '待采纳',
  adopted: '已采纳',
  rejected: '已拒绝',
  superseded: '已替代',
};

const ADOPT_COLOR: Record<string, string> = {
  pending: 'default',
  adopted: 'green',
  rejected: 'red',
  superseded: 'gold',
};

/** Validation result badge. */
function ValidationBadge({ patch }: { patch: FixPatch }) {
  if (patch.validation_result === null || patch.validation_result === undefined) {
    return <Tag>未校验</Tag>;
  }

  const vr = patch.validation_result as Record<string, unknown>;
  const syntax = vr.syntax as Record<string, unknown> | undefined;
  const compile = vr.compile as Record<string, unknown> | undefined;
  const security = vr.security_regression as Record<string, unknown> | undefined;

  const syntaxPassed = syntax?.passed;
  const compilePassed = compile?.passed;
  const securityPassed = security?.passed ?? security?.skipped;

  const allPassed = syntaxPassed && (compilePassed ?? true) && (securityPassed ?? true);

  return (
    <Space size={4}>
      <Tag color={syntaxPassed ? 'green' : 'red'} style={{ fontSize: '11px' }}>
        语法{syntaxPassed ? '通过' : '失败'}
      </Tag>
      {compile && (
        <Tag
          color={compile.passed ? 'green' : 'red'}
          style={{ fontSize: '11px' }}
        >
          编译{compile.passed ? '通过' : '失败'}
        </Tag>
      )}
      {security && (
        <Tag
          color={security.skipped ? 'default' : security.passed ? 'green' : 'red'}
          style={{ fontSize: '11px' }}
        >
          {security.skipped ? '安全回归跳过' : security.passed ? '安全回归通过' : '安全回归失败'}
        </Tag>
      )}
      <Tag
        color={allPassed ? 'green' : 'red'}
        style={{ fontWeight: 600, fontSize: '11px' }}
      >
        {allPassed ? '全部通过' : '校验未通过'}
      </Tag>
    </Space>
  );
}

/** Patch panel — displays AI-generated fix patch with diff, validation, adopt/reject, and export. */
const PatchPanel: React.FC<PatchPanelProps> = ({
  findingId,
  findingStatus,
  onStatusChange,
  refreshKey,
}) => {
  const [patch, setPatch] = useState<FixPatch | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [validating, setValidating] = useState(false);
  const [adopting, setAdopting] = useState(false);
  const [exporting, setExporting] = useState(false);

  const fetchPatch = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getPatchByFinding(findingId);
      setPatch(data);
    } catch {
      setPatch(null);
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    fetchPatch();
  }, [fetchPatch, refreshKey]);

  // Only show panel for findings that are verified or adopted
  const showPanel =
    findingStatus !== 'false_positive' || patch !== null;

  if (!showPanel) {
    return null;
  }

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const data = await createPatch(findingId);
      setPatch(data);
      message.success('补丁已生成');
    } catch (e) {
      message.error('补丁生成失败: ' + (e as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const handleRegenerate = async () => {
    if (!patch) return;
    setGenerating(true);
    try {
      const data = await createPatch(findingId, true);
      setPatch(data);
      message.success('补丁已重新生成');
    } catch (e) {
      message.error('补丁重新生成失败: ' + (e as Error).message);
    } finally {
      setGenerating(false);
    }
  };

  const handleValidate = async () => {
    if (!patch) return;
    setValidating(true);
    try {
      const result = await validatePatch(patch.id);
      // Refresh patch to get updated validation_result
      const updated = await getPatch(patch.id);
      setPatch(updated);
      if (result.validated) {
        message.success('补丁校验通过');
      } else {
        message.warning('补丁校验未通过，请查看详情');
      }
    } catch (e) {
      message.error('校验失败: ' + (e as Error).message);
    } finally {
      setValidating(false);
    }
  };

  const handleAdopt = async () => {
    if (!patch) return;
    setAdopting(true);
    try {
      const updated = await adoptPatch(patch.id);
      setPatch(updated);
      onStatusChange?.();
      message.success('补丁已采纳');
    } catch (e) {
      message.error('采纳失败: ' + (e as Error).message);
    } finally {
      setAdopting(false);
    }
  };

  const handleReject = async () => {
    if (!patch) return;
    setAdopting(true);
    try {
      const updated = await rejectPatch(patch.id, '不符合业务逻辑');
      setPatch(updated);
      onStatusChange?.();
      message.success('补丁已拒绝');
    } catch (e) {
      message.error('拒绝失败: ' + (e as Error).message);
    } finally {
      setAdopting(false);
    }
  };

  const handleExport = async () => {
    if (!patch) return;
    setExporting(true);
    try {
      const blob = await exportPatchZip(patch.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `patch_${patch.id}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      message.success('补丁已导出为压缩包');
    } catch (e) {
      message.error('导出失败: ' + (e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div>
      <Divider orientation="left" style={{ fontSize: '13px' }}>
        智能修复补丁
        <Button
          type="text"
          size="small"
          icon={<ReloadOutlined />}
          onClick={fetchPatch}
          loading={loading}
          style={{ marginLeft: 8 }}
        />
      </Divider>

      <Spin spinning={loading || generating}>
        {!patch && !generating ? (
          <div style={{ textAlign: 'center', padding: '16px 0' }}>
            <Empty
              description={
                findingStatus === 'verified'
                  ? '该漏洞已验证但尚未生成修复补丁'
                  : findingStatus === 'latent'
                  ? '该漏洞为潜在隐患，尚未生成修复补丁'
                  : findingStatus === 'adopted'
                  ? '该漏洞尚未生成修复补丁'
                  : '该漏洞尚未生成修复补丁'
              }
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            >
              {findingStatus !== 'false_positive' && (
                <Button
                  type="primary"
                  icon={<ThunderboltOutlined />}
                  onClick={handleGenerate}
                  loading={generating}
                >
                  生成修复补丁
                </Button>
              )}
            </Empty>
          </div>
        ) : patch ? (
          <div
            style={{
              border: '1px solid #e1e4e8',
              borderRadius: 6,
              padding: '12px 16px',
              background: '#fafbfc',
            }}
          >
            {/* Header: patch info + status */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 8,
                flexWrap: 'wrap',
                gap: 8,
              }}
            >
              <Space wrap>
                <Text strong style={{ fontSize: '13px' }}>
                  <SafetyCertificateOutlined /> 修复补丁
                </Text>
                <Tag color={ADOPT_COLOR[patch.adopt_status] || 'default'}>
                  {ADOPT_LABEL[patch.adopt_status] || patch.adopt_status}
                </Tag>
                {patch.llm_model && (
                  <Tooltip title={`提示词用量: ${patch.token_usage || 0}`}>
                    <Tag style={{ fontSize: '11px' }}>
                      {patch.llm_model}
                    </Tag>
                  </Tooltip>
                )}
              </Space>
              <Space>
                <Button
                  size="small"
                  icon={<ReloadOutlined />}
                  onClick={handleRegenerate}
                  loading={generating}
                >
                  重新生成
                </Button>
                <Button
                  size="small"
                  icon={<SafetyCertificateOutlined />}
                  onClick={handleValidate}
                  loading={validating}
                >
                  校验
                </Button>
                <Button
                  size="small"
                  type="primary"
                  icon={<CheckCircleOutlined />}
                  onClick={handleAdopt}
                  loading={adopting}
                  disabled={patch.adopt_status === 'adopted'}
                >
                  采纳
                </Button>
                <Button
                  size="small"
                  danger
                  icon={<CloseCircleOutlined />}
                  onClick={handleReject}
                  loading={adopting}
                  disabled={patch.adopt_status === 'rejected'}
                >
                  拒绝
                </Button>
                <Button
                  size="small"
                  icon={<DownloadOutlined />}
                  onClick={handleExport}
                  loading={exporting}
                >
                  导出压缩包
                </Button>
              </Space>
            </div>

            {/* Description */}
            {patch.description && (
              <Alert
                message={patch.description}
                type="info"
                style={{ marginBottom: 8, fontSize: '12px' }}
                showIcon
              />
            )}

            {/* Validation badges */}
            {patch.validation_result && (
              <div style={{ marginBottom: 8 }}>
                <ValidationBadge patch={patch} />
              </div>
            )}

            {/* Diff viewer */}
            <div style={{ marginBottom: 8 }}>
              <Text strong style={{ fontSize: '12px' }}>
                修复差异
              </Text>
              <DiffViewer
                diff={patch.diff_content || ''}
                maxHeight={300}
              />
            </div>

            {/* Original vs Patched code */}
            <div
              style={{
                display: 'flex',
                gap: 12,
                flexWrap: 'wrap',
                marginBottom: 8,
              }}
            >
              <div style={{ flex: '1 1 400px', minWidth: 300 }}>
                <Text
                  strong
                  style={{ fontSize: '12px', color: '#cf222e' }}
                >
                  原始代码
                </Text>
                <pre
                  style={{
                    background: '#ffebe9',
                    color: '#1f2328',
                    padding: '8px 12px',
                    borderRadius: 4,
                    fontSize: '12px',
                    margin: '4px 0 0',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    border: '1px solid #ffcecb',
                  }}
                >
                  {patch.original_code || '无数据'}
                </pre>
              </div>
              <div style={{ flex: '1 1 400px', minWidth: 300 }}>
                <Text
                  strong
                  style={{ fontSize: '12px', color: '#1a7f37' }}
                >
                  修复后代码
                </Text>
                <pre
                  style={{
                    background: '#dafbe1',
                    color: '#1f2328',
                    padding: '8px 12px',
                    borderRadius: 4,
                    fontSize: '12px',
                    margin: '4px 0 0',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    border: '1px solid #b4e0c5',
                  }}
                >
                  {patch.patched_code || '无数据'}
                </pre>
              </div>
            </div>

            {/* Timestamps */}
            <div
              style={{
                display: 'flex',
                gap: 16,
                flexWrap: 'wrap',
                fontSize: '11px',
                color: '#8c959f',
              }}
            >
              {patch.created_at && (
                <Text type="secondary" style={{ fontSize: '11px' }}>
                  生成时间: {new Date(patch.created_at).toLocaleString('zh-CN')}
                </Text>
              )}
              {patch.updated_at && patch.updated_at !== patch.created_at && (
                <Text type="secondary" style={{ fontSize: '11px' }}>
                  更新时间: {new Date(patch.updated_at).toLocaleString('zh-CN')}
                </Text>
              )}
            </div>
          </div>
        ) : null}
      </Spin>
    </div>
  );
};

export default PatchPanel;
