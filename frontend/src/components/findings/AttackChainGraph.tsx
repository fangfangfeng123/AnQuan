import React, { useMemo } from 'react';
import {
  ArrowRightOutlined,
  BugOutlined,
  CodeOutlined,
  DatabaseOutlined,
  FileSearchOutlined,
  NodeIndexOutlined,
  SafetyCertificateOutlined,
  UploadOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Card, Collapse, Empty, Tag, Tooltip, Typography } from 'antd';
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  type Edge as FlowEdge,
  type Node as FlowNode,
  type NodeProps,
} from 'reactflow';
import 'reactflow/dist/style.css';
import type { AttackChain as AttackChainType } from '../../api/attackChains';
import {
  pickLabel,
  privilegeLevelLabels,
  riskLabels,
  vulnTypeLabels,
} from '../../utils/labels';

const { Text } = Typography;

const NODE_WIDTH = 238;
const NODE_HEIGHT = 132;
const LAYER_GAP_X = 86;
const NODE_GAP_Y = 34;
const CANVAS_PADDING = 36;

const TYPE_COLORS: Record<string, string> = {
  sql_injection: '#2563eb',
  command_injection: '#d4380d',
  file_upload: '#7c3aed',
  broken_access: '#db2777',
  idor: '#db2777',
  sensitive_data: '#d97706',
  sensitive_info: '#d97706',
  path_traversal: '#0e7490',
  deserialization: '#7c3aed',
  xss: '#a21caf',
  ssrf: '#4f46e5',
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  sql_injection: <DatabaseOutlined />,
  command_injection: <CodeOutlined />,
  file_upload: <UploadOutlined />,
  broken_access: <SafetyCertificateOutlined />,
  idor: <SafetyCertificateOutlined />,
  sensitive_data: <FileSearchOutlined />,
  sensitive_info: <FileSearchOutlined />,
  path_traversal: <FileSearchOutlined />,
  deserialization: <BugOutlined />,
  xss: <WarningOutlined />,
  ssrf: <NodeIndexOutlined />,
};

interface ChainNodeData {
  label: string;
  vulnType: string;
  asset: string | null;
  privilegeText: string;
}

function getNodeKind(vulnType: string) {
  return pickLabel(vulnType, vulnTypeLabels);
}

function getTypeColor(vulnType: string) {
  return TYPE_COLORS[vulnType] || '#57606a';
}

function getTypeIcon(vulnType: string) {
  return TYPE_ICONS[vulnType] || <BugOutlined />;
}

function privilegeSummary(value: string | null) {
  if (!value) return '权限状态未知';
  const parts = value
    .split('->')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => pickLabel(part, privilegeLevelLabels));
  if (!parts.length) return '权限状态未知';
  return parts.join(' → ');
}

function getSeverityColor(severity: string) {
  const map: Record<string, string> = {
    critical: '#cf222e',
    high: '#fb8c00',
    medium: '#d4a017',
    low: '#0969da',
    info: '#6b7280',
  };
  return map[severity] || '#6b7280';
}

function getSeveritySoft(severity: string) {
  const map: Record<string, string> = {
    critical: '#fff1f2',
    high: '#fff7ed',
    medium: '#fffbeb',
    low: '#eff6ff',
    info: '#f5f5f5',
  };
  return map[severity] || '#f5f5f5';
}

function removePythonFileLabel(value: string | null) {
  if (!value) return value || '';
  return value.replace(/\s+-\s+\S+?\.py\b/gi, '').trim();
}

interface LayoutResult {
  nodes: FlowNode<ChainNodeData>[];
  edges: FlowEdge[];
  canvasHeight: number;
}

function buildFlow(chain: AttackChainType): LayoutResult {
  const sourceMap = new Map<string, string[]>();
  const inDegree = new Map<string, number>();
  const nodeMap = new Map(chain.nodes.map((node) => [node.id, node]));

  for (const node of chain.nodes) {
    sourceMap.set(node.id, []);
    inDegree.set(node.id, 0);
  }

  const validEdges = chain.edges.filter(
    (edge) => nodeMap.has(edge.source_node_id) && nodeMap.has(edge.target_node_id),
  );

  for (const edge of validEdges) {
    sourceMap.get(edge.source_node_id)?.push(edge.target_node_id);
    inDegree.set(edge.target_node_id, (inDegree.get(edge.target_node_id) || 0) + 1);
  }

  const layerMap = new Map<string, number>();
  const queue = chain.nodes
    .filter((node) => (inDegree.get(node.id) || 0) === 0)
    .sort((a, b) => a.node_order - b.node_order)
    .map((node) => node.id);

  queue.forEach((nodeId) => layerMap.set(nodeId, 0));

  let cursor = 0;
  while (cursor < queue.length) {
    const current = queue[cursor];
    cursor += 1;
    const currentLayer = layerMap.get(current) ?? 0;
    for (const next of sourceMap.get(current) || []) {
      const nextLayer = Math.max(layerMap.get(next) ?? 0, currentLayer + 1);
      layerMap.set(next, nextLayer);
      const remaining = (inDegree.get(next) || 0) - 1;
      inDegree.set(next, remaining);
      if (remaining === 0) {
        queue.push(next);
      }
    }
  }

  for (const node of chain.nodes) {
    if (!layerMap.has(node.id)) {
      layerMap.set(node.id, 0);
    }
  }

  const layerGroups = new Map<number, string[]>();
  for (const node of chain.nodes) {
    const layer = layerMap.get(node.id) ?? 0;
    if (!layerGroups.has(layer)) layerGroups.set(layer, []);
    layerGroups.get(layer)?.push(node.id);
  }

  const maxLayer = Math.max(...Array.from(layerGroups.keys()), 0);
  const maxLayerSize = Math.max(
    ...Array.from(layerGroups.values()).map((group) => group.length),
    1,
  );
  const canvasHeight = Math.max(
    420,
    CANVAS_PADDING * 2 +
      maxLayerSize * NODE_HEIGHT +
      Math.max(0, maxLayerSize - 1) * NODE_GAP_Y,
  );
  const canvasWidth =
    CANVAS_PADDING * 2 +
    (maxLayer + 1) * NODE_WIDTH +
    maxLayer * LAYER_GAP_X;

  const nodes: FlowNode<ChainNodeData>[] = [];
  layerGroups.forEach((groupNodeIds, layer) => {
    const groupHeight =
      groupNodeIds.length * NODE_HEIGHT +
      Math.max(0, groupNodeIds.length - 1) * NODE_GAP_Y;
    const startY = Math.max(24, (canvasHeight - groupHeight) / 2);

    groupNodeIds.forEach((nodeId, index) => {
      const source = nodeMap.get(nodeId);
      if (!source) return;
      const color = getTypeColor(source.vuln_type);
      nodes.push({
        id: source.id,
        type: 'attackNode',
        position: {
          x: CANVAS_PADDING + layer * (NODE_WIDTH + LAYER_GAP_X),
          y: startY + index * (NODE_HEIGHT + NODE_GAP_Y),
        },
        data: {
          label: removePythonFileLabel(source.label) || getNodeKind(source.vuln_type),
          vulnType: source.vuln_type,
          asset: source.asset,
          privilegeText: privilegeSummary(source.privilege_level),
        },
        style: {
          width: NODE_WIDTH,
          borderColor: color,
        },
        draggable: false,
      });
    });
  });

  const severityColor = getSeverityColor(chain.overall_severity);
  const edges: FlowEdge[] = validEdges.map((edge, index) => ({
    id: `${chain.id}-edge-${index}`,
    source: edge.source_node_id,
    target: edge.target_node_id,
    type: 'smoothstep',
    animated: true,
    label: String(edge.step),
    labelStyle: {
      fill: severityColor,
      fontSize: 13,
      fontWeight: 800,
    },
    labelBgStyle: {
      fill: '#ffffff',
      fillOpacity: 0.95,
    },
    labelBgPadding: [7, 3],
    labelBgBorderRadius: 10,
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 18,
      height: 18,
      color: severityColor,
    },
    style: {
      stroke: severityColor,
      strokeWidth: 2.2,
    },
  }));

  return {
    nodes,
    edges,
    canvasHeight,
  };
}

const AttackNodeCard: React.FC<NodeProps<ChainNodeData>> = ({ data }) => {
  const color = getTypeColor(data.vulnType);
  const kind = getNodeKind(data.vulnType);
  const icon = getTypeIcon(data.vulnType);
  const asset = data.asset && !/\.py$/i.test(data.asset) ? data.asset : null;

  return (
    <div
      className="chain-node-card"
      style={{
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        borderColor: color,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="chain-node-handle"
        style={{ background: color, borderColor: color }}
      />
      <div
        className="chain-node-head"
        style={{
          color,
          background: `${color}0f`,
          borderBottomColor: `${color}22`,
        }}
      >
        <span className="chain-node-icon" style={{ color }}>
          {icon}
        </span>
        <span className="chain-node-kind">{kind}</span>
      </div>
      <div className="chain-node-title">{data.label}</div>
      {asset && (
        <Tooltip title={asset}>
          <div className="chain-node-asset">{asset}</div>
        </Tooltip>
      )}
      <div className="chain-node-foot">
        <span className="chain-node-privilege">{data.privilegeText}</span>
        <ArrowRightOutlined className="chain-node-arrow" style={{ color }} />
      </div>
      <Handle
        type="source"
        position={Position.Right}
        className="chain-node-handle"
        style={{ background: color, borderColor: color }}
      />
    </div>
  );
};

const nodeTypes = {
  attackNode: AttackNodeCard,
};

function FlowCanvas({ chain }: { chain: AttackChainType }) {
  const { nodes, edges, canvasHeight } = useMemo(() => buildFlow(chain), [chain]);
  const severityColor = getSeverityColor(chain.overall_severity);
  const severitySoft = getSeveritySoft(chain.overall_severity);

  return (
    <div
      className="chain-flow-shell"
      style={{ borderColor: `${severityColor}33`, background: severitySoft }}
    >
      <div
        className="chain-flow-stage"
        style={{ height: canvasHeight }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          minZoom={0.35}
          maxZoom={1.6}
          nodesConnectable={false}
          elementsSelectable
          panOnScroll
          zoomOnScroll
          zoomOnDoubleClick={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={18}
            size={1.4}
            color={`${severityColor}2e`}
          />
          <Controls position="top-right" showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="chain-flow-footer">
        <span>可滚动缩放 / 拖动画布查看完整路径</span>
        <span>
          {chain.node_count} 个漏洞节点 · {chain.edge_count} 条攻击边
        </span>
      </div>
    </div>
  );
}

function StepPath({ chain }: { chain: AttackChainType }) {
  if (!chain.edges.length) {
    return (
      <div className="chain-step-path chain-step-path-single">
        <Text strong>单点攻击</Text>
        <span>{chain.final_impact || '该漏洞已构成独立可利用路径'}</span>
      </div>
    );
  }

  return (
    <div className="chain-step-path">
      {chain.edges.map((edge) => (
        <div className="chain-step-item" key={edge.id}>
          <span className="chain-step-number">{edge.step}</span>
          <div className="chain-step-copy">
            <Text strong>{edge.action || '发起下一步攻击'}</Text>
            <Text type="secondary">{edge.condition}</Text>
          </div>
          {edge.privilege_escalation && (
            <Tag className="chain-step-privilege">
              {privilegeSummary(edge.privilege_escalation)}
            </Tag>
          )}
        </div>
      ))}
    </div>
  );
}

function ChainHeader({ chain }: { chain: AttackChainType }) {
  const color = getSeverityColor(chain.overall_severity);
  const soft = getSeveritySoft(chain.overall_severity);

  return (
    <div
      className="chain-panel-head"
      style={{
        background: soft,
        borderColor: `${color}22`,
      }}
    >
      <div className="chain-panel-title">
        <Text strong className="chain-panel-name">
          {removePythonFileLabel(chain.name) || '攻击链路径'}
        </Text>
        <div className="chain-panel-tags">
          <Tag
            color={color}
            style={{ fontWeight: 700, border: 0, marginRight: 0 }}
          >
            {riskLabels[chain.overall_severity] || chain.overall_severity}
            {chain.overall_cvss != null
              ? ` · CVSS ${chain.overall_cvss.toFixed(1)}`
              : ''}
          </Tag>
          <Tag bordered={false} className="chain-panel-tag-light">
            {chain.is_single_node ? '单点路径' : '多步路径'}
          </Tag>
        </div>
      </div>
      <div className="chain-panel-impact">
        <span className="chain-impact-dot" style={{ background: color }} />
        <Text type="secondary" ellipsis={{ tooltip: chain.final_impact || '' }}>
          {chain.final_impact || '暂无危害描述'}
        </Text>
      </div>
    </div>
  );
}

interface AttackChainGraphProps {
  chains: AttackChainType[];
  loading?: boolean;
}

const AttackChainGraph: React.FC<AttackChainGraphProps> = ({
  chains,
  loading = false,
}) => {
  if (loading) {
    return (
      <Card title="攻击链拓扑" loading style={{ marginBottom: 16 }}>
        <div style={{ height: 220 }} />
      </Card>
    );
  }

  if (!chains || chains.length === 0) {
    return (
      <Card title="攻击链拓扑" style={{ marginBottom: 16 }}>
        <Empty
          description="暂无攻击链数据（需完成路径推演阶段）"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </Card>
    );
  }

  return (
    <Card
      title={
        <span className="chain-card-title">
          <NodeIndexOutlined />
          攻击链拓扑
        </span>
      }
      extra={
        <Tag color="blue" bordered={false}>
          {chains.length} 条推演路径
        </Tag>
      }
      style={{ marginBottom: 16 }}
    >
      <Collapse
        ghost
        defaultActiveKey={chains.map((_, index) => `chain-${index}`)}
        items={chains.map((chain, index) => ({
          key: `chain-${index}`,
          label: <ChainHeader chain={chain} />,
          children: (
            <div className="chain-body">
              <FlowCanvas chain={chain} />
              <StepPath chain={chain} />
            </div>
          ),
        }))}
      />
    </Card>
  );
};

export default AttackChainGraph;
