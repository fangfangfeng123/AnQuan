# Event Protocol — WebSocket 实时事件协议

> 传输方式：WebSocket
>
> 端点：`WS /api/v1/ws/tasks/{taskId}`
>
> 消息格式：JSON
>
> 编码：UTF-8

---

## 1. 连接机制

### 1.1 建立连接

```
ws://localhost:8000/api/v1/ws/tasks/task_01HXY9
```

连接成功后，服务端立即发送 `connected` 事件确认。之后服务端按事件推送，客户端不需要轮询。

### 1.2 心跳

客户端每 30 秒发送：

```json
{"type": "ping"}
```

服务端回复：

```json
{"type": "pong", "timestamp": "2026-09-07T12:00:00Z"}
```

超过 90 秒未收到心跳，服务端可断开连接。

### 1.3 客户端订阅

客户端可在连接时指定关注的事件类型（可选）：

```json
{"type": "subscribe", "events": ["phase_change", "finding_new", "log_append"]}
```

不指定则默认接收全部事件。

---

## 2. 事件总表

| 事件类型 | 触发时机 | 对应蓝图章节 |
|----------|----------|-------------|
| connected | 连接建立 | — |
| task_started | 任务启动 | §3.1 |
| task_completed | 任务完成 | §3.1 |
| task_failed | 任务失败 | §3.1 |
| task_stopped | 用户停止 | §3.1 |
| sandbox_created | 沙箱创建 | §3.2 |
| sandbox_ready | 沙箱就绪 | §3.2 |
| sandbox_destroyed | 沙箱销毁 | §3.2 |
| phase_change | 阶段状态变更 | §3.3 |
| agent_start | Agent 开始执行 | §3.4 |
| agent_end | Agent 执行结束 | §3.4 |
| log_append | 新增日志 | §3.5 |
| resource_update | 资源指标更新 | §3.6 |
| finding_new | 新漏洞入库 | §3.7 |
| finding_status_change | 漏洞状态变更 | §3.8 |
| poc_start | PoC 验证开始 | §3.9 |
| poc_verified | PoC 验证成功 | §3.9 |
| poc_failed | PoC 验证失败 | §3.9 |
| attack_chain_generated | 攻击链生成 | §3.10 |
| report_generated | 报告生成完成 | §3.11 |
| progress_update | 整体进度更新 | §3.12 |

---

## 3. 事件消息结构

### 3.1 任务生命周期事件

#### task_started

```json
{
  "type": "task_started",
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "running",
  "timestamp": "2026-09-07T12:01:00Z"
}
```

#### task_completed

```json
{
  "type": "task_completed",
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "completed",
  "stats": {
    "totalFindings": 8,
    "verified": 5,
    "latent": 3,
    "attackChains": 1
  },
  "endedAt": "2026-09-07T12:30:00Z",
  "timestamp": "2026-09-07T12:30:00Z"
}
```

#### task_failed

```json
{
  "type": "task_failed",
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "failed",
  "errorPhase": "poc_verify",
  "errorMessage": "沙箱容器启动超时",
  "endedAt": "2026-09-07T12:15:00Z",
  "timestamp": "2026-09-07T12:15:00Z"
}
```

#### task_stopped

```json
{
  "type": "task_stopped",
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "stopped",
  "currentPhase": "poc_verify",
  "message": "沙箱已销毁，已保留阶段性漏洞数据",
  "stoppedAt": "2026-09-07T12:20:00Z",
  "timestamp": "2026-09-07T12:20:00Z"
}
```

### 3.2 沙箱事件

#### sandbox_created

```json
{
  "type": "sandbox_created",
  "taskId": "task_01HXY9",
  "sandboxId": "sbx_01HXY9",
  "image": "python:3.12-slim",
  "timestamp": "2026-09-07T12:01:05Z"
}
```

#### sandbox_ready

```json
{
  "type": "sandbox_ready",
  "taskId": "task_01HXY9",
  "sandboxId": "sbx_01HXY9",
  "sourceMountPath": "/workspace/source",
  "writablePath": "/workspace/tmp",
  "networkMode": "restricted",
  "timestamp": "2026-09-07T12:01:10Z"
}
```

#### sandbox_destroyed

```json
{
  "type": "sandbox_destroyed",
  "taskId": "task_01HXY9",
  "sandboxId": "sbx_01HXY9",
  "reason": "task_completed",
  "timestamp": "2026-09-07T12:30:05Z"
}
```

### 3.3 阶段状态事件

#### phase_change

```json
{
  "type": "phase_change",
  "taskId": "task_01HXY9",
  "phase": "code_audit",
  "phaseStatus": "running",
  "previousPhase": "recon",
  "previousPhaseStatus": "completed",
  "agentName": "CodeAuditAgent",
  "summary": "识别技术栈: Python/FastAPI/PostgreSQL，入口: /api/v1/login",
  "timestamp": "2026-09-07T12:03:00Z"
}
```

阶段枚举：`recon` / `code_audit` / `poc_verify` / `exploit_chain` / `report_gen`

阶段状态枚举：`pending` / `running` / `completed` / `failed`

### 3.4 Agent 事件

#### agent_start

```json
{
  "type": "agent_start",
  "taskId": "task_01HXY9",
  "phase": "recon",
  "agentName": "ReconAgent",
  "inputSummary": "源码路径: /workspace/source, 技术栈: 未知",
  "timestamp": "2026-09-07T12:01:15Z"
}
```

#### agent_end

```json
{
  "type": "agent_end",
  "taskId": "task_01HXY9",
  "phase": "recon",
  "agentName": "ReconAgent",
  "outputSummary": "识别完成: Python/FastAPI/PostgreSQL, 入口3个, 服务端口8080",
  "duration": 105,
  "result": "success",
  "timestamp": "2026-09-07T12:03:00Z"
}
```

| 字段 | 说明 |
|------|------|
| result | `success` / `failed` / `partial` |
| duration | 耗时秒数 |

### 3.5 日志事件

#### log_append

```json
{
  "type": "log_append",
  "taskId": "task_01HXY9",
  "logId": "log_42",
  "phase": "recon",
  "agent": "ReconAgent",
  "level": "info",
  "message": "开始扫描 app/ 目录结构...",
  "timestamp": "2026-09-07T12:01:20Z"
}
```

日志级别枚举：`debug` / `info` / `warn` / `error`

> 前端按 `level` 着色：debug=灰、info=蓝、warn=橙、error=红
>
> 按 `agent` 过滤：前端维护一个 activeAgent 集合，不在集合内的事件直接跳过

### 3.6 资源事件

#### resource_update

```json
{
  "type": "resource_update",
  "taskId": "task_01HXY9",
  "sandboxId": "sbx_01HXY9",
  "metrics": {
    "cpuPercent": 45.2,
    "memoryMB": 512,
    "diskMB": 1024,
    "elapsedSecs": 180
  },
  "timestamp": "2026-09-07T12:04:00Z"
}
```

> 推送频率：每 5 秒一次，沙箱销毁后停止。

### 3.7 漏洞事件

#### finding_new

```json
{
  "type": "finding_new",
  "taskId": "task_01HXY9",
  "findingId": "find_01",
  "vulnType": "SQL Injection",
  "cweId": "CWE-89",
  "status": "unverified",
  "severity": "high",
  "file": "app/api/orders.py",
  "line": 42,
  "source": "app/api/orders.py:40",
  "sink": "app/api/orders.py:42",
  "detectedBy": "Semgrep",
  "confidence": 0.85,
  "timestamp": "2026-09-07T12:05:00Z"
}
```

> 前端收到后：在漏洞列表插入新行并高亮，更新大盘统计数字。

### 3.8 漏洞状态变更事件

#### finding_status_change

```json
{
  "type": "finding_status_change",
  "taskId": "task_01HXY9",
  "findingId": "find_01",
  "oldStatus": "unverified",
  "newStatus": "verified",
  "reason": "PoC 验证成功: 布尔注入特征匹配",
  "timestamp": "2026-09-07T12:10:00Z"
}
```

状态流转：`unverified` → `verified`（PoC 成功）/ `unverified` → `latent`（PoC 失败但有风险模式）

### 3.9 PoC 验证事件

#### poc_start

```json
{
  "type": "poc_start",
  "taskId": "task_01HXY9",
  "findingId": "find_01",
  "pocType": "boolean_based",
  "pocEvidenceId": "poc_01",
  "timestamp": "2026-09-07T12:09:00Z"
}
```

#### poc_verified

```json
{
  "type": "poc_verified",
  "taskId": "task_01HXY9",
  "findingId": "find_01",
  "pocEvidenceId": "poc_01",
  "pocType": "boolean_based",
  "expectedFeature": "布尔条件为真时返回正常订单数据",
  "observedFeature": "返回了完整订单数据，与预期一致",
  "timestamp": "2026-09-07T12:10:00Z"
}
```

#### poc_failed

```json
{
  "type": "poc_failed",
  "taskId": "task_01HXY9",
  "findingId": "find_01",
  "pocEvidenceId": "poc_02",
  "pocType": "time_based",
  "reason": "响应时间无显著差异 (1.02s vs 1.05s)",
  "latent": true,
  "timestamp": "2026-09-07T12:11:00Z"
}
```

| 字段 | 说明 |
|------|------|
| latent | `true` 表示该漏洞转为潜在隐患（latent），`false` 表示直接标记为误报不保留 |

### 3.10 攻击链事件

#### attack_chain_generated

```json
{
  "type": "attack_chain_generated",
  "taskId": "task_01HXY9",
  "attackChainId": "chain_01",
  "nodeCount": 3,
  "edgeCount": 2,
  "finalImpact": "远程代码执行（RCE）",
  "overallSeverity": "critical",
  "nodes": [
    {"nodeId": "node_01", "label": "SQL注入点", "findingId": "find_01"},
    {"nodeId": "node_02", "label": "管理员凭证获取", "findingId": "find_02"},
    {"nodeId": "node_03", "label": "文件上传RCE", "findingId": "find_03"}
  ],
  "edges": [
    {"source": "node_01", "target": "node_02", "step": 1},
    {"source": "node_02", "target": "node_03", "step": 2}
  ],
  "timestamp": "2026-09-07T12:25:00Z"
}
```

> 前端收到后立即渲染攻击链拓扑图（使用 React Flow 或 Cytoscape），节点点击跳转漏洞详情。

### 3.11 报告事件

#### report_generated

```json
{
  "type": "report_generated",
  "taskId": "task_01HXY9",
  "reportId": "rpt_01",
  "version": "v1.0",
  "summary": {
    "totalFindings": 8,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 2,
    "verifiedCount": 5,
    "latentCount": 3,
    "attackChains": 1,
    "overallRisk": "critical"
  },
  "exportFormats": ["markdown", "html", "pdf"],
  "timestamp": "2026-09-07T12:30:00Z"
}
```

### 3.12 进度事件

#### progress_update

```json
{
  "type": "progress_update",
  "taskId": "task_01HXY9",
  "overallProgress": 40,
  "phaseProgress": {
    "recon": {"status": "completed", "progress": 100},
    "code_audit": {"status": "running", "progress": 60},
    "poc_verify": {"status": "pending", "progress": 0},
    "exploit_chain": {"status": "pending", "progress": 0},
    "report_gen": {"status": "pending", "progress": 0}
  },
  "timestamp": "2026-09-07T12:05:00Z"
}
```

> overallProgress = 各阶段进度加权平均（recon 15% + code_audit 30% + poc_verify 25% + exploit_chain 20% + report_gen 10%）

---

## 4. 事件时序示例（端到端演示场景）

以蓝图 §14.1 电商 SQL 注入 + 文件上传 → RCE 组合攻击为例：

```
t=0s    connected          连接建立
t=1s    task_started       任务启动
t=2s    sandbox_created    沙箱创建
t=3s    sandbox_ready      沙箱就绪
t=4s    agent_start        ReconAgent 开始
        log_append         "开始环境侦察..."
t=120s  agent_end          ReconAgent 完成 (duration=116s)
        phase_change       recon → completed, code_audit → running
t=121s  agent_start        CodeAuditAgent 开始
        log_append          "开始 SAST 扫描 app/..."
t=180s  finding_new        SQL注入 find_01 (unverified, high)
t=240s  finding_new        文件上传 find_03 (unverified, high)
t=300s  agent_end          CodeAuditAgent 完成
        phase_change       code_audit → completed, poc_verify → running
t=301s  agent_start        PoCVerifyAgent 开始
t=310s  poc_start          find_01 布尔注入验证
t=315s  poc_verified        find_01 验证成功
        finding_status_change  find_01: unverified → verified
t=320s  poc_start          find_03 文件上传验证
t=330s  poc_verified        find_03 验证成功
        finding_status_change  find_03: unverified → verified
t=335s  agent_end          PoCVerifyAgent 完成
        phase_change       poc_verify → completed, exploit_chain → running
t=336s  agent_start        ExploitChainAgent 开始
t=360s  attack_chain_generated  攻击链生成 (3节点2边, RCE)
t=365s  agent_end          ExploitChainAgent 完成
        phase_change       exploit_chain → completed, report_gen → running
t=366s  agent_start        ReportAgent 开始
t=390s  report_generated   报告生成完成
        agent_end          ReportAgent 完成
t=391s  task_completed     任务完成
        sandbox_destroyed  沙箱销毁
```

---

## 5. 错误处理

### 5.1 无效任务 ID

```json
{
  "type": "error",
  "code": "TASK_NOT_FOUND",
  "message": "任务不存在: task_xxx",
  "timestamp": "2026-09-07T12:00:00Z"
}
```

### 5.2 连接关闭

服务端主动关闭时发送 Close frame（code=1000），消息体：

```json
{
  "type": "connection_closed",
  "reason": "task_completed",
  "message": "任务已完成，连接将自动关闭",
  "timestamp": "2026-09-07T12:30:05Z"
}
```

任务完成后服务端保持连接 60 秒，之后自动关闭。

### 5.3 重连策略

前端断线后自动重连策略（指数退避）：

| 次数 | 延迟 | 说明 |
|------|------|------|
| 1 | 1s | 立即重试 |
| 2 | 2s | — |
| 3 | 4s | — |
| 4 | 8s | — |
| 5 | 16s | — |
| 6+ | 30s | 最大间隔 |

重连成功后，前端通过 `GET /api/v1/tasks/{taskId}/pipeline` 拉取完整状态快照补齐遗漏的事件。

---

## 6. 前端事件处理对照表

| 事件类型 | 前端动作 | 目标组件 |
|----------|----------|----------|
| task_started | 更新任务状态徽章 | 流水线监控区 |
| phase_change | 更新五阶段步进器 | 流水线步进器 |
| agent_start | 高亮当前 Agent | Agent 状态卡片 |
| agent_end | 取消高亮，写入 summary | Agent 状态卡片 |
| log_append | 追加日志行 | 终端日志面板 |
| resource_update | 更新仪表数字 | 资源指标卡片 |
| finding_new | 插入漏洞列表行 | 漏洞列表 |
| finding_status_change | 更新行状态徽章 + 颜色 | 漏洞列表 |
| poc_verified | 标记漏洞为已验证 | 漏洞列表 + 漏洞详情 |
| poc_failed | 标记为 latent 或移除 | 漏洞列表 |
| attack_chain_generated | 渲染拓扑图 | 攻击链图区 |
| report_generated | 启用导出按钮 | 报告中心 |
| progress_update | 更新进度条 | 全局进度条 |
| task_completed | 显示完成提示 | 全局通知 |
| task_failed | 显示错误提示 | 全局通知 |
| task_stopped | 显示停止提示 | 全局通知 |
