import React, { useEffect, useRef, useState } from 'react';
import {
  Button,
  Card,
  Progress,
  Tag,
  Space,
  Descriptions,
  message,
  Spin,
  Typography,
} from 'antd';
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import { useParams } from 'react-router-dom';
import { useTaskStore, PHASE_LABELS, PHASE_ORDER } from '../stores/task';
import { useAuthStore } from '../stores/auth';
import { getProject } from '../api/projects';
import {
  riskLabels,
  taskStatusLabels,
} from '../utils/labels';
import { wsManager } from '../stores/websocket';
import PhaseStepper from '../components/pipeline/PhaseStepper';
import LogPanel from '../components/pipeline/LogPanel';
import ResourceGauge from '../components/pipeline/ResourceGauge';
import ReconResultCard from '../components/pipeline/ReconResultCard';
import StatusBadge from '../components/common/StatusBadge';
import { getSandboxStatus, getSandboxStats } from '../api/sandbox';
import { listFindings, type Finding } from '../api/findings';
import { listAttackChains, type AttackChain } from '../api/attackChains';
import FindingTable from '../components/findings/FindingTable';
import AttackChainGraph from '../components/findings/AttackChainGraph';

const { Text } = Typography;

const TaskWorkbenchPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [attackChainsLoading, setAttackChainsLoading] = useState(false);
  const [projectName, setProjectName] = useState('');
  const role = useAuthStore((state) => state.user?.role);
  const canControlTask = role !== 'developer';

  const loadFindings = async (taskId: string) => {
    setFindingsLoading(true);
    try {
      const data = await listFindings(taskId);
      setFindings(data.items);
    } catch {
      setFindings([]);
    } finally {
      setFindingsLoading(false);
    }
  };

  const loadAttackChains = async (taskId: string) => {
    setAttackChainsLoading(true);
    try {
      const data = await listAttackChains(taskId);
      setAttackChains(data.items);
    } catch {
      setAttackChains([]);
    } finally {
      setAttackChainsLoading(false);
    }
  };
  const {
    currentTask,
    logs,
    loading,
    latestSnapshotId,
    wsConnected,
    wsEvents,
    sandboxStatus,
    sandboxStats,
    sandboxLoading,
    reconSummary,
    reconLoading,
    create,
    start,
    stop,
    fetch,
    fetchLogs,
    fetchSandboxStatus,
    fetchSandboxStats,
    fetchReconSummary,
    initializeProject,
    setWsConnected,
    addWsEvent,
  } = useTaskStore();

  // 轮询定时器引用
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!id) return;
    setFindings([]);
    setFindingsLoading(false);
    setAttackChains([]);
    setAttackChainsLoading(false);
    setProjectName('');
    initializeProject(id);
    getProject(id)
      .then((project) => setProjectName(project.project_name))
      .catch(() => setProjectName(''));
  }, [id]);

  // WebSocket 连接（当任务 running 时）
  useEffect(() => {
    const taskId = currentTask?.id;
    if (!taskId) return;

    const unsub = wsManager.subscribe((msg) => {
      addWsEvent(msg as unknown as Record<string, unknown>);
      const evt = msg.event;
      if (
        evt === 'phase_started' ||
        evt === 'phase_completed' ||
        evt === 'task_completed' ||
        evt === 'task_stopped' ||
        evt === 'error'
      ) {
        fetch(taskId);
        fetchLogs(taskId);
        loadFindings(taskId);
      }
      if (evt === 'finding_new') {
        loadFindings(taskId);
      }
      // PoC 验证事件触发漏洞列表和证据刷新
      if (
        evt === 'poc_start' ||
        evt === 'poc_verified' ||
        evt === 'poc_failed' ||
        evt === 'poc_evidence_saved'
      ) {
        loadFindings(taskId);
      }
      // 补丁事件触发漏洞列表刷新（status 可能变为 adopted）
      if (
        evt === 'patch_ready' ||
        evt === 'patch_validated' ||
        evt === 'patch_adopted' ||
        evt === 'patch_rejected'
      ) {
        loadFindings(taskId);
      }
      // 攻击链事件触发拓扑图刷新
      if (
        evt === 'attack_chain_generated' ||
        evt === 'exploit_chain_progress'
      ) {
        loadAttackChains(taskId);
      }
      // 沙箱事件触发状态刷新
      if (
        evt === 'sandbox_created' ||
        evt === 'sandbox_ready' ||
        evt === 'sandbox_destroying' ||
        evt === 'sandbox_destroyed' ||
        evt === 'sandbox_exec_start' ||
        evt === 'sandbox_exec_done'
      ) {
        fetchSandboxStatus(taskId);
        fetchSandboxStats(taskId);
        fetchLogs(taskId);
      }
      // Recon 事件触发摘要刷新
      if (
        evt === 'recon_progress' ||
        evt === 'recon_completed' ||
        evt === 'phase_completed'
      ) {
        fetchReconSummary(taskId);
      }
    });

    wsManager.connect(taskId);
    fetchLogs(taskId);
    loadFindings(taskId);
    loadAttackChains(taskId);
    fetchSandboxStatus(taskId);
    fetchReconSummary(taskId);
    setWsConnected(true);

    return () => {
      unsub();
      wsManager.disconnect();
      setWsConnected(false);
    };
  }, [currentTask?.id]);

  // 任务运行时轮询沙箱状态和资源指标
  useEffect(() => {
    const taskId = currentTask?.id;
    const isRunning = currentTask?.status === 'running';

    if (!taskId || !isRunning) {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }

    // 立即拉取一次
    fetchSandboxStatus(taskId);
    fetchSandboxStats(taskId);

    // 每 5 秒轮询
    pollRef.current = setInterval(() => {
      fetchSandboxStatus(taskId);
      fetchSandboxStats(taskId);
    }, 5000);

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [currentTask?.id, currentTask?.status]);

  const handleCreateTask = async () => {
    if (!id) return;
    try {
      const task = await create(id, latestSnapshotId);
      message.success('任务已创建');
      fetch(task.id);
    } catch (e) {
      message.error((e as Error).message);
    }
  };

  const handleStart = async () => {
    if (!currentTask) return;
    try {
      await start(currentTask.id);
      message.success('任务已启动');
    } catch (e) {
      message.error((e as Error).message);
    }
  };

  const handleStop = async () => {
    if (!currentTask) return;
    try {
      await stop(currentTask.id);
      message.success('任务已停止，沙箱已销毁');
      fetchSandboxStatus(currentTask.id);
    } catch (e) {
      message.error((e as Error).message);
    }
  };

  const handleRefreshSandbox = async () => {
    if (!currentTask) return;
    try {
      const status = await getSandboxStatus(currentTask.id);
      useTaskStore.setState({ sandboxStatus: status });
      if (status.db_status === 'ready' || status.db_status === 'running') {
        const stats = await getSandboxStats(currentTask.id);
        useTaskStore.setState({ sandboxStats: stats });
      }
    } catch (e) {
      message.error((e as Error).message);
    }
  };

  const taskStatus = currentTask?.status || 'unknown';
  const isRunning = taskStatus === 'running';
  const isCreated = taskStatus === 'created';
  const isStopped = taskStatus === 'stopped';

  const phaseStatusMap: Record<string, string> =
    currentTask?.phase_status || {};
  const currentStepIndex = PHASE_ORDER.findIndex(
    (phase) => phaseStatusMap[phase] === 'running'
  );

  const sbStatus = sandboxStatus?.db_status || 'none';
  const dockerStatus = sandboxStatus?.docker_status || 'none';
  const hasSandbox = sbStatus !== 'none' && sbStatus !== 'destroyed';

  if (loading && !currentTask) {
    return (
      <div style={{ textAlign: 'center', padding: '80px 0' }}>
        <Spin size="large" tip="正在加载项目评估数据..." />
      </div>
    );
  }

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
          <h2 style={{ margin: 0 }}>评估工作台</h2>
          {projectName && (
            <Text type="secondary" style={{ fontSize: 13 }}>
              当前项目：{projectName}
            </Text>
          )}
        </div>
        <Space>
          {!currentTask && canControlTask && (
            <Button type="primary" onClick={handleCreateTask}>
              创建任务
            </Button>
          )}
          {currentTask && canControlTask && (isCreated || isStopped) && (
            <Button
              type="primary"
              icon={<PlayCircleOutlined />}
              onClick={handleStart}
              loading={loading}
            >
              启动
            </Button>
          )}
          {isRunning && canControlTask && (
            <Button
              danger
              icon={<PauseCircleOutlined />}
              onClick={handleStop}
            >
              停止
            </Button>
          )}
        </Space>
      </div>

      {currentTask ? (
        <>
          {/* 任务概览 */}
          <Card style={{ marginBottom: 16 }}>
            <Descriptions column={4} size="small">
              <Descriptions.Item label="任务 ID">
                <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                  {currentTask.id}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag
                  color={
                    taskStatus === 'running'
                      ? 'processing'
                      : taskStatus === 'completed'
                      ? 'success'
                      : taskStatus === 'failed'
                      ? 'error'
                      : taskStatus === 'stopped'
                      ? 'warning'
                      : 'default'
                  }
                >
                  {taskStatusLabels[taskStatus] || taskStatus}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="当前阶段">
                {currentTask.current_phase
                  ? PHASE_LABELS[currentTask.current_phase] ||
                    currentTask.current_phase
                  : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="整体风险">
                <Tag
                  color={
                    currentTask.overall_risk === 'critical'
                      ? 'red'
                      : currentTask.overall_risk === 'high'
                      ? 'orange'
                      : 'green'
                  }
                >
                  {riskLabels[currentTask.overall_risk || ''] ||
                    currentTask.overall_risk ||
                    '-'}
                </Tag>
              </Descriptions.Item>
            </Descriptions>
            <Progress
              percent={currentTask.overall_progress}
              style={{ marginTop: 12 }}
              status={
                taskStatus === 'failed'
                  ? 'exception'
                  : isRunning
                  ? 'active'
                  : 'normal'
              }
            />
          </Card>

          {/* 沙箱状态卡片 */}
          <Card
            title="沙箱状态"
            style={{ marginBottom: 16 }}
            extra={
              <Space>
                <StatusBadge status={sbStatus} prefix="沙箱" />
                <Tag color={dockerStatus === 'running' ? 'green' : 'default'}>
                  容器:{' '}
                  {dockerStatus === 'running'
                    ? '运行中'
                    : dockerStatus === 'ready'
                    ? '就绪'
                    : dockerStatus === 'none'
                    ? '未创建'
                    : dockerStatus}
                </Tag>
                <Button
                  size="small"
                  icon={<ReloadOutlined />}
                  onClick={handleRefreshSandbox}
                >
                  刷新
                </Button>
              </Space>
            }
          >
            {hasSandbox ? (
              <>
                <Descriptions column={3} size="small" style={{ marginBottom: 16 }}>
                  <Descriptions.Item label="沙箱 ID">
                    <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {sandboxStatus?.sandbox_id?.slice(0, 12)}...
                    </span>
                  </Descriptions.Item>
                  <Descriptions.Item label="容器 ID">
                    <span style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {sandboxStatus?.container_id?.slice(0, 12) || '-'}
                    </span>
                  </Descriptions.Item>
                  <Descriptions.Item label="镜像">
                    <Tag>{sandboxStatus?.image || '-'}</Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="创建时间">
                    {sandboxStatus?.created_at
                      ? new Date(sandboxStatus.created_at).toLocaleString('zh-CN')
                      : '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="就绪时间">
                    {sandboxStatus?.ready_at
                      ? new Date(sandboxStatus.ready_at).toLocaleString('zh-CN')
                      : '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="销毁时间">
                    {sandboxStatus?.destroyed_at
                      ? new Date(sandboxStatus.destroyed_at).toLocaleString('zh-CN')
                      : '-'}
                  </Descriptions.Item>
                </Descriptions>
                <ResourceGauge stats={sandboxStats} loading={sandboxLoading} />
              </>
            ) : sbStatus === 'destroyed' ? (
              <div style={{ textAlign: 'center', padding: '24px', color: '#999' }}>
                沙箱已销毁，容器日志和任务数据已保留
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '24px', color: '#999' }}>
                {isRunning
                  ? '正在创建沙箱容器...'
                  : '任务未运行，无沙箱实例'}
              </div>
            )}
          </Card>

          {/* 环境侦察结果卡片 */}
          <ReconResultCard
            summary={reconSummary}
            loading={reconLoading}
          />

          <Card title="漏洞列表" style={{ marginBottom: 16 }}>
            <FindingTable
              findings={findings}
              loading={findingsLoading}
              onNeedRefresh={() => {
                if (currentTask?.id) loadFindings(currentTask.id);
              }}
            />
          </Card>

          {/* 攻击链拓扑 */}
          <AttackChainGraph
            chains={attackChains}
            loading={attackChainsLoading}
          />

          {/* 五阶段流水线 */}
          <Card title="五阶段流水线" style={{ marginBottom: 16 }}>
            <PhaseStepper
              phaseStatus={phaseStatusMap}
              currentPhase={currentTask.current_phase}
            />
          </Card>

          {/* 实时日志 */}
          <Card
            title="实时日志"
            extra={
              <Tag color={wsConnected ? 'green' : 'red'}>
                {wsConnected ? 'WS 已连接' : 'WS 断开'}
              </Tag>
            }
          >
            <LogPanel logs={logs} wsEvents={wsEvents} />
          </Card>
        </>
      ) : (
        <Card>
          <div
            style={{
              textAlign: 'center',
              padding: '48px 0',
              color: '#999',
            }}
          >
            尚未创建任务，点击右上角"创建任务"开始评估
          </div>
        </Card>
      )}
    </div>
  );
};

export default TaskWorkbenchPage;
