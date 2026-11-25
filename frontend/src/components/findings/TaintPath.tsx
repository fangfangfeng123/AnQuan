import React from 'react';
import { Steps } from 'antd';
import {
  LoginOutlined,
  ArrowRightOutlined,
  CodeOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import type { TaintStep } from '../../api/findings';
import { pickLabel, taintStepLabels } from '../../utils/labels';

/** Map taint step type to antd Steps status icon. */
const STEP_ICON: Record<string, React.ReactNode> = {
  source: <LoginOutlined />,
  transfer: <ArrowRightOutlined />,
  sink: <CodeOutlined />,
  sanitizer: <SafetyOutlined />,
};

interface TaintPathProps {
  steps: TaintStep[];
}

/** Render the source-to-sink taint propagation path as a vertical step list. */
const TaintPath: React.FC<TaintPathProps> = ({ steps }) => {
  if (!steps || steps.length === 0) {
    return (
      <div style={{ color: '#999', padding: '12px 0' }}>
        暂无污点传播路径数据
      </div>
    );
  }

  return (
    <Steps
      direction="vertical"
      size="small"
      current={steps.length - 1}
      items={steps.map((s) => ({
        title: (
          <span>
            <strong>{pickLabel(s.type, taintStepLabels)}</strong>
            {' - '}
            <code style={{ fontSize: '12px' }}>第 {s.line} 行</code>
          </span>
        ),
        description: (
          <div>
            <pre
              style={{
                background: '#f5f5f5',
                padding: '6px 8px',
                borderRadius: 4,
                fontSize: '12px',
                margin: '4px 0',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
              }}
            >
              {s.code}
            </pre>
            {s.detail && (
              <div style={{ color: '#666', fontSize: '12px' }}>
                {s.detail}
              </div>
            )}
          </div>
        ),
        icon: STEP_ICON[s.type] || <ArrowRightOutlined />,
      }))}
    />
  );
};

export default TaintPath;
