import React, { useEffect, useRef } from 'react';
import { Tag } from 'antd';
import type { TaskLog } from '../../api/tasks';
import { phaseLabels } from '../../utils/labels';

interface LogPanelProps {
  logs: TaskLog[];
  wsEvents: Record<string, unknown>[];
}

const levelColor: Record<string, string> = {
  debug: '#8c8c8c',
  info: '#1677ff',
  warning: '#faad14',
  error: '#ff4d4f',
  critical: '#cf1322',
};

const levelLabels: Record<string, string> = {
  debug: '调试',
  info: '信息',
  warning: '警告',
  error: '错误',
  critical: '严重',
};

const agentLabels: Record<string, string> = {
  recon_agent: '环境侦察智能体',
  code_audit_agent: '代码审计智能体',
  poc_verify_agent: '动态验证智能体',
  exploit_chain_agent: '攻击链推演智能体',
  report_gen_agent: '报告生成智能体',
  orchestrator: '编排引擎',
  sandbox_service: '沙箱服务',
};

const LogPanel: React.FC<LogPanelProps> = ({ logs, wsEvents }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  // 自动滚动到底部
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, wsEvents]);

  const wsEventLines = wsEvents.map((evt, i) => {
    const event = evt.event as string;
    const phase = (evt.payload as Record<string, unknown>)?.phase as string | undefined;
    const message = (evt.payload as Record<string, unknown>)?.message as string | undefined;
    const text = `[事件] ${event}${phase ? ` (${phase})` : ''}${message ? `: ${message}` : ''}`;
    return (
      <div key={`ws-${i}`} style={{ color: '#722ed1', fontSize: '12px' }}>
        <span style={{ color: '#b37feb' }}>[实时通道]</span>{' '}
        {text}
      </div>
    );
  });

  const dbLogLines = logs.map((log) => (
    <div key={log.id} style={{ fontSize: '12px', fontFamily: 'monospace' }}>
      <span style={{ color: '#8c8c8c' }}>
        {new Date(log.created_at).toLocaleTimeString('zh-CN')}
      </span>{' '}
      <Tag style={{ fontSize: '10px', padding: '0 4px' }} color={levelColor[log.level] || '#8c8c8c'}>
        {levelLabels[log.level] || log.level}
      </Tag>{' '}
      <span style={{ color: '#1677ff' }}>[{phaseLabels[log.phase] || log.phase}]</span>{' '}
      <span style={{ color: '#52c41a' }}>{agentLabels[log.agent] || log.agent}</span>{' '}
      {log.message}
    </div>
  ));

  return (
    <div
      ref={containerRef}
      style={{
        height: '400px',
        overflowY: 'auto',
        background: '#1e1e1e',
        color: '#d4d4d4',
        padding: '12px',
        borderRadius: '4px',
        fontFamily: 'Consolas, Monaco, "Courier New", monospace',
        lineHeight: '1.8',
      }}
    >
      {dbLogLines}
      {wsEventLines}
      {logs.length === 0 && wsEvents.length === 0 && (
        <div style={{ color: '#666', textAlign: 'center', paddingTop: '100px' }}>
          暂无日志，任务启动后将实时显示...
        </div>
      )}
    </div>
  );
};

export default LogPanel;
