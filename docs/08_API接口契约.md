# API Contract — 自动化安全评估系统

> 所有路由前缀：`/api/v1`
>
> 认证方式：Bearer Token（MVP 阶段用静态 token，后续扩展 OAuth2）
>
> 时间格式：ISO 8601 UTC（如 `2026-09-07T12:00:00Z`）

---

## 1. 项目管理

### 1.1 创建项目

```
POST /api/v1/projects
```

**Request Body**

```json
{
  "projectName": "电商后台靶场",
  "sourceType": "git",
  "sourceInput": "https://github.com/user/repo.git",
  "branch": "main"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| projectName | string | 是 | 项目名称 |
| sourceType | string | 是 | `git` 或 `archive` |
| sourceInput | string | 是 | Git URL 或上传后的文件路径标识 |
| branch | string | 否 | Git 分支，默认 `main` |

**Response 201**

```json
{
  "projectId": "proj_01HXY9",
  "projectName": "电商后台靶场",
  "sourceType": "git",
  "sourceRef": "snapshot_a1b2c3",
  "sourceSnapshotId": "snap_01HXY9",
  "status": "created",
  "createdAt": "2026-09-07T12:00:00Z"
}
```

### 1.2 上传压缩包源码

```
POST /api/v1/projects/upload
Content-Type: multipart/form-data
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| file | binary | 是 | .zip / .tar.gz / .tar.bz2 |
| projectName | string | 是 | 项目名称 |

**Response 201** — 同 1.1，`sourceType` 为 `archive`。

### 1.3 获取项目列表

```
GET /api/v1/projects?page=1&pageSize=20
```

**Response 200**

```json
{
  "total": 5,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "projectId": "proj_01HXY9",
      "projectName": "电商后台靶场",
      "sourceType": "git",
      "techStack": ["Python", "FastAPI", "PostgreSQL"],
      "status": "active",
      "lastTaskStatus": "completed",
      "lastTaskId": "task_01HXY9",
      "createdAt": "2026-09-07T12:00:00Z",
      "updatedAt": "2026-09-07T13:00:00Z"
    }
  ]
}
```

### 1.4 获取项目详情

```
GET /api/v1/projects/{projectId}
```

**Response 200**

```json
{
  "projectId": "proj_01HXY9",
  "projectName": "电商后台靶场",
  "sourceType": "git",
  "sourceRef": "snapshot_a1b2c3",
  "sourceSnapshotId": "snap_01HXY9",
  "commitId": "abc1234",
  "techStack": ["Python", "FastAPI", "PostgreSQL"],
  "status": "active",
  "createdAt": "2026-09-07T12:00:00Z",
  "updatedAt": "2026-09-07T13:00:00Z"
}
```

### 1.5 删除项目

```
DELETE /api/v1/projects/{projectId}
```

**Response 204** — 无 Body。同时级联删除关联的任务、漏洞、证据和报告数据。

---

## 2. 评估任务

### 2.1 启动评估

```
POST /api/v1/projects/{projectId}/tasks
```

**Request Body**

```json
{
  "sandboxImage": "python:3.12-slim",
  "networkMode": "restricted",
  "timeoutSecs": 1800,
  "llmMode": "openai",
  "maxConcurrentAgents": 4
}
```

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| sandboxImage | string | 否 | `python:3.12-slim` | 沙箱 Docker 镜像 |
| networkMode | string | 否 | `restricted` | `isolated`（断网）/ `restricted`（受限内网） |
| timeoutSecs | int | 否 | 1800 | 任务超时秒数 |
| llmMode | string | 否 | `demo` | `openai` / `ollama` / `demo` |
| maxConcurrentAgents | int | 否 | 4 | Agent 并发上限 |

**Response 201**

```json
{
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "created",
  "currentPhase": null,
  "sandboxId": null,
  "createdAt": "2026-09-07T12:00:00Z"
}
```

### 2.2 启动评估执行

```
POST /api/v1/tasks/{taskId}/start
```

**Response 200**

```json
{
  "taskId": "task_01HXY9",
  "status": "running",
  "currentPhase": "recon",
  "sandboxId": "sbx_01HXY9",
  "startedAt": "2026-09-07T12:01:00Z"
}
```

> 说明：创建任务后需单独调用 start 触发实际执行。编排引擎将按 `recon → code_audit → poc_verify → exploit_chain → report_gen` 顺序推进。

### 2.3 停止评估

```
POST /api/v1/tasks/{taskId}/stop
```

**Response 200**

```json
{
  "taskId": "task_01HXY9",
  "status": "stopped",
  "currentPhase": "poc_verify",
  "stoppedAt": "2026-09-07T12:30:00Z",
  "message": "沙箱已销毁，已保留阶段性漏洞数据"
}
```

### 2.4 获取任务详情

```
GET /api/v1/tasks/{taskId}
```

**Response 200**

```json
{
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
  "status": "running",
  "currentPhase": "code_audit",
  "sandboxId": "sbx_01HXY9",
  "phaseStatus": {
    "recon": "completed",
    "code_audit": "running",
    "poc_verify": "pending",
    "exploit_chain": "pending",
    "report_gen": "pending"
  },
  "startedAt": "2026-09-07T12:01:00Z",
  "endedAt": null,
  "errorMessage": null,
  "resourceUsage": {
    "cpuPercent": 45.2,
    "memoryMB": 512,
    "diskMB": 1024,
    "elapsedSecs": 180
  }
}
```

### 2.5 获取任务列表

```
GET /api/v1/projects/{projectId}/tasks?page=1&pageSize=20
```

**Response 200**

```json
{
  "total": 3,
  "page": 1,
  "pageSize": 20,
  "items": [
    {
      "taskId": "task_01HXY9",
      "status": "completed",
      "currentPhase": "report_gen",
      "startedAt": "2026-09-07T12:01:00Z",
      "endedAt": "2026-09-07T12:30:00Z"
    }
  ]
}
```

### 2.6 获取任务流水线快照

```
GET /api/v1/tasks/{taskId}/pipeline
```

**Response 200**

```json
{
  "taskId": "task_01HXY9",
  "phases": [
    {
      "phase": "recon",
      "status": "completed",
      "startedAt": "2026-09-07T12:01:00Z",
      "endedAt": "2026-09-07T12:03:00Z",
      "agentName": "ReconAgent",
      "summary": "识别技术栈: Python/FastAPI/PostgreSQL，入口: /api/v1/login"
    },
    {
      "phase": "code_audit",
      "status": "running",
      "startedAt": "2026-09-07T12:03:00Z",
      "endedAt": null,
      "agentName": "CodeAuditAgent",
      "summary": null
    }
  ]
}
```

### 2.7 获取任务日志

```
GET /api/v1/tasks/{taskId}/logs?agent=&level=&page=1&pageSize=100
```

| 参数 | 类型 | 说明 |
|------|------|------|
| agent | string | 过滤 Agent 名称（如 `ReconAgent`） |
| level | string | 过滤日志级别（`info` / `warn` / `error`） |
| page | int | 页码 |
| pageSize | int | 每页条数 |

**Response 200**

```json
{
  "total": 256,
  "page": 1,
  "pageSize": 100,
  "items": [
    {
      "logId": "log_01",
      "taskId": "task_01HXY9",
      "phase": "recon",
      "agent": "ReconAgent",
      "level": "info",
      "message": "开始环境侦察...",
      "timestamp": "2026-09-07T12:01:05Z"
    }
  ]
}
```

---

## 3. 漏洞数据

### 3.1 获取漏洞列表

```
GET /api/v1/tasks/{taskId}/findings?status=&severity=&page=1&pageSize=50
```

| 参数 | 说明 |
|------|------|
| status | `unverified` / `verified` / `latent` |
| severity | `critical` / `high` / `medium` / `low` |

**Response 200**

```json
{
  "total": 8,
  "page": 1,
  "pageSize": 50,
  "items": [
    {
      "findingId": "find_01",
      "taskId": "task_01HXY9",
      "vulnType": "SQL Injection",
      "cweId": "CWE-89",
      "status": "verified",
      "severity": "high",
      "cvssScore": 7.5,
      "cvssVector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "file": "app/api/orders.py",
      "line": 42,
      "sinkFile": "app/api/orders.py",
      "sinkLine": 45
    }
  ]
}
```

### 3.2 获取漏洞详情

```
GET /api/v1/findings/{findingId}
```

**Response 200**

```json
{
  "findingId": "find_01",
  "taskId": "task_01HXY9",
  "vulnType": "SQL Injection",
  "cweId": "CWE-89",
  "status": "verified",
  "severity": "high",
  "cvssScore": 7.5,
  "cvssVector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "source": {
    "file": "app/api/orders.py",
    "line": 40,
    "code": "order_id = request.args.get('id')"
  },
  "sink": {
    "file": "app/api/orders.py",
    "line": 42,
    "code": "cursor.execute(f\"SELECT * FROM orders WHERE id={order_id}\")"
  },
  "taintPath": [
    {"file": "app/api/orders.py", "line": 40, "desc": "request.args.get('id') 接收外部输入"},
    {"file": "app/api/orders.py", "line": 42, "desc": "未经过滤直接拼接到 SQL 语句"}
  ],
  "codeContext": "def get_order():\n    order_id = request.args.get('id')\n    cursor.execute(f\"SELECT * FROM orders WHERE id={order_id}\")\n    ...",
  "pocEvidence": [
    {
      "pocEvidenceId": "poc_01",
      "pocType": "boolean_based",
      "requestPayload": "id=1 AND 1=1 -- ",
      "verified": true,
      "verifiedAt": "2026-09-07T12:10:00Z"
    }
  ],
  "fixPatch": {
    "patchId": "patch_01",
    "diffContent": "--- a/app/api/orders.py\n+++ b/app/api/orders.py\n@@ -42 +42 @@\n-    cursor.execute(f\"SELECT * FROM orders WHERE id={order_id}\")\n+    cursor.execute(\"SELECT * FROM orders WHERE id=%s\", (order_id,))",
    "validationStatus": "passed",
    "adoptStatus": "not_adopted"
  }
}
```

### 3.3 获取漏洞 PoC 证据

```
GET /api/v1/findings/{findingId}/evidence
```

**Response 200**

```json
{
  "findingId": "find_01",
  "evidences": [
    {
      "pocEvidenceId": "poc_01",
      "pocType": "boolean_based",
      "requestPayload": "id=1 AND 1=1 -- ",
      "requestData": "GET /api/v1/orders?id=1%20AND%201%3D1%20--%20 HTTP/1.1\\r\\nHost: target:8080",
      "responseData": "HTTP/1.1 200 OK\\r\\nContent-Length: 1234\\r\\n\\r\\n[{\"id\":1,...}]",
      "expectedFeature": "布尔条件为真时返回正常订单数据",
      "observedFeature": "返回了完整订单数据，与预期一致",
      "verified": true,
      "verifiedAt": "2026-09-07T12:10:00Z"
    }
  ]
}
```

---

## 4. 攻击链

### 4.1 获取攻击链图

```
GET /api/v1/tasks/{taskId}/attack-chain
```

**Response 200**

```json
{
  "taskId": "task_01HXY9",
  "attackChainId": "chain_01",
  "nodes": [
    {
      "nodeId": "node_01",
      "label": "SQL注入点",
      "findingId": "find_01",
      "asset": "订单查询接口 /api/orders?id=",
      "preCondition": "无认证可访问",
      "postCapability": "读取数据库任意表",
      "privilegeLevel": "anonymous"
    },
    {
      "nodeId": "node_02",
      "label": "管理员凭证获取",
      "findingId": "find_02",
      "asset": "users 表",
      "preCondition": "数据库读取能力",
      "postCapability": "管理员登录凭证",
      "privilegeLevel": "authenticated"
    },
    {
      "nodeId": "node_03",
      "label": "文件上传RCE",
      "findingId": "find_03",
      "asset": "后台上传接口 /admin/upload",
      "preCondition": "管理员凭证",
      "postCapability": "服务器命令执行",
      "privilegeLevel": "admin"
    }
  ],
  "edges": [
    {
      "edgeId": "edge_01",
      "source": "node_01",
      "target": "node_02",
      "trigger": "读取 users 表获取管理员 hash",
      "privilegeEscalation": "anonymous → authenticated",
      "step": 1
    },
    {
      "edgeId": "edge_02",
      "source": "node_02",
      "target": "node_03",
      "trigger": "使用管理员凭证登录后台并上传 webshell",
      "privilegeEscalation": "authenticated → admin",
      "step": 2
    }
  ],
  "finalImpact": "远程代码执行（RCE）",
  "overallSeverity": "critical"
}
```

---

## 5. 报告

### 5.1 获取报告摘要

```
GET /api/v1/tasks/{taskId}/report
```

**Response 200**

```json
{
  "reportId": "rpt_01",
  "taskId": "task_01HXY9",
  "projectId": "proj_01HXY9",
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
  "sections": ["概览", "漏洞清单", "攻击链分析", "修复建议", "附录"],
  "exportFormats": ["markdown", "html", "pdf"],
  "generatedAt": "2026-09-07T12:30:00Z"
}
```

### 5.2 导出报告

```
POST /api/v1/tasks/{taskId}/report/export
```

**Request Body**

```json
{
  "format": "pdf"
}
```

| 字段 | 说明 |
|------|------|
| format | `markdown` / `html` / `pdf` |

**Response 200**

```json
{
  "downloadUrl": "/api/v1/reports/rpt_01/download/pdf",
  "format": "pdf",
  "expiresAt": "2026-09-07T13:00:00Z"
}
```

### 5.3 下载报告文件

```
GET /api/v1/reports/{reportId}/download/{format}
```

**Response 200** — 文件流（`Content-Type` 按 format 决定）。

---

## 6. 沙箱与环境配置

### 6.1 获取沙箱配置

```
GET /api/v1/sandbox/config
```

**Response 200**

```json
{
  "defaultImage": "python:3.12-slim",
  "availableImages": [
    {"image": "python:3.12-slim", "label": "Python 3.12"},
    {"image": "node:20-slim", "label": "Node.js 20"},
    {"image": "openjdk:21-slim", "label": "Java 21"},
    {"image": "golang:1.22-alpine", "label": "Go 1.22"}
  ],
  "networkModes": ["isolated", "restricted"],
  "defaultTimeoutSecs": 1800,
  "maxConcurrentTasks": 4,
  "resourceLimits": {
    "cpuCores": 2,
    "memoryMB": 2048,
    "diskMB": 4096
  }
}
```

### 6.2 更新沙箱配置

```
PUT /api/v1/sandbox/config
```

**Request Body** — 同 6.1 Response 结构中的可修改字段。

### 6.3 获取模型配置

```
GET /api/v1/llm/config
```

**Response 200**

```json
{
  "currentMode": "openai",
  "modes": {
    "openai": {
      "model": "gpt-4o",
      "baseUrl": "https://api.openai.com/v1",
      "maxTokens": 4096,
      "temperature": 0.2
    },
    "ollama": {
      "model": "qwen2.5-coder:7b",
      "baseUrl": "http://localhost:11434/v1",
      "maxTokens": 4096
    },
    "demo": {
      "description": "使用模板和示例数据模拟 Agent，不需要 API Key"
    }
  },
  "tokenBudgetPerTask": 50000,
  "estimatedCostPerTask": "$0.05"
}
```

### 6.4 更新模型配置

```
PUT /api/v1/llm/config
```

**Request Body**

```json
{
  "currentMode": "openai",
  "openai": {
    "apiKey": "sk-xxx",
    "model": "gpt-4o",
    "baseUrl": "https://api.openai.com/v1",
    "maxTokens": 4096,
    "temperature": 0.2
  },
  "tokenBudgetPerTask": 50000
}
```

> ⚠️ API Key 仅在请求中传入，不入库存储，由后端写入内存或加密的 .env。

### 6.5 获取系统审计日志

```
GET /api/v1/audit-logs?page=1&pageSize=50&level=&startTime=&endTime=
```

**Response 200**

```json
{
  "total": 120,
  "page": 1,
  "pageSize": 50,
  "items": [
    {
      "logId": "audit_01",
      "action": "sandbox_created",
      "taskId": "task_01HXY9",
      "operator": "system",
      "detail": "创建沙箱 sbx_01, 镜像 python:3.12-slim",
      "timestamp": "2026-09-07T12:01:00Z"
    }
  ]
}
```

---

## 7. 概览大盘

### 7.1 获取全局统计

```
GET /api/v1/dashboard/stats
```

**Response 200**

```json
{
  "totalProjects": 5,
  "totalTasks": 12,
  "runningTasks": 1,
  "totalFindings": 47,
  "findingsBySeverity": {
    "critical": 3,
    "high": 8,
    "medium": 15,
    "low": 21
  },
  "findingsByStatus": {
    "verified": 30,
    "unverified": 12,
    "latent": 5
  },
  "recentTasks": [
    {
      "taskId": "task_01HXY9",
      "projectName": "电商后台靶场",
      "status": "running",
      "currentPhase": "code_audit",
      "startedAt": "2026-09-07T12:01:00Z"
    }
  ]
}
```

---

## 8. WebSocket 端点

```
WS /api/v1/ws/tasks/{taskId}
```

连接后自动接收任务实时事件，消息格式参见 `EVENT_PROTOCOL.md`。

---

## 9. 统一错误格式

所有错误响应使用统一结构：

```json
{
  "error": {
    "code": "TASK_NOT_FOUND",
    "message": "任务不存在",
    "detail": "taskId=task_xxx 未找到对应记录"
  }
}
```

### 常见错误码

| HTTP 状态码 | code | 说明 |
|-------------|------|------|
| 400 | INVALID_INPUT | 请求参数校验失败 |
| 401 | UNAUTHORIZED | 未认证或 token 无效 |
| 404 | NOT_FOUND | 资源不存在 |
| 409 | CONFLICT | 状态冲突（如任务已在运行中） |
| 422 | VALIDATION_ERROR | 业务校验失败 |
| 500 | INTERNAL_ERROR | 服务端内部错误 |
| 503 | SANDBOX_UNAVAILABLE | 沙箱创建失败或 Docker 不可用 |
