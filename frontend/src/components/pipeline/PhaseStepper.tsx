import React from 'react';
import { Steps } from 'antd';
import { PHASE_LABELS, PHASE_ORDER } from '../../stores/task';

interface PhaseStepperProps {
  phaseStatus: Record<string, string>;
  currentPhase: string | null;
}

const statusMap: Record<string, 'wait' | 'process' | 'finish' | 'error'> = {
  pending: 'wait',
  running: 'process',
  completed: 'finish',
  failed: 'error',
};

const PhaseStepper: React.FC<PhaseStepperProps> = ({ phaseStatus }) => {
  const items = PHASE_ORDER.map((phase) => {
    const status = phaseStatus[phase] || 'pending';
    return {
      title: PHASE_LABELS[phase] || phase,
      status: statusMap[status] || 'wait',
    };
  });

  return (
    <Steps
      size="default"
      current={PHASE_ORDER.findIndex((p) => phaseStatus[p] === 'running')}
      items={items}
      style={{ padding: '12px 0' }}
    />
  );
};

export default PhaseStepper;
