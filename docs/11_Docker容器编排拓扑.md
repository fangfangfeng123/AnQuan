# Docker Topology — 容器编排拓扑

> 编排工具：Docker Compose v2
>
> 运行环境：本地开发 / 演示
>
> 目标：一键 `docker compose up -d` 启动全系统

---

## 1. 服务总览

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Compose                        │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ frontend  │  │ backend  │  │ postgres │  │  redis   │   │
│  │  :5173    │  │  :8000   │  │  :5432   │  │  :6379   │   │
│  │ (Vite)    │  │ (FastAPI)│  │  (PG16)  │  │ (cache)  │   │
│  └────┬─────┘  └──┬───┬───┘  └────▲─────┘  └────▲─────┘   │
│       │           │   │            │             │          │
│       │           │   └────────────┼─────────────┘          │
│       │           │                │                        │
│       │    ┌──────┴───────┐  ┌────┴──────────┐               │
│       │    │  sandbox     │  │  pgadmin      │               │
│       └───▶│  runner      │  │  :5050        │               │
│            │  (DinD)      │  │  (可选)       │               │
│            └──────────────┘  └───────────────┘               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 服务定义

### 2.1 postgres — 数据库

| 属性 | 值 |
|------|-----|
| 镜像 | `postgres:16-alpine` |
| 端口 | `5432:5432` |
| 数据卷 | `pg_data:/var/lib/postgresql/data` |
| 数据库名 | `sec_eval` |
| 用户 | `sec_user` |
| 密码 | 从 `.env` 读取 |
| 健康检查 | `pg_isready -U sec_user -d sec_eval` |
| 启动策略 | 先于 backend 启动 |

**依赖关系**：无，最先启动。

### 2.2 redis — 缓存与消息通道

| 属性 | 值 |
|------|-----|
| 镜像 | `redis:7-alpine` |
| 端口 | `6379:6379` |
| 数据卷 | `redis_data:/data` |
| 健康检查 | `redis-cli ping` |
| 用途 | WebSocket pubsub 通道、任务队列、沙箱状态缓存 |

**依赖关系**：无。

### 2.3 backend — 后端 API 服务

| 属性 | 值 |
|------|-----|
| 构建上下文 | `./backend` |
| Dockerfile | `./backend/Dockerfile` |
| 端口 | `8000:8000` |
| 环境变量 | 见 `.env` |
| 数据卷 | `./data:/app/data`（源码快照、报告导出） |
| 健康检查 | `curl -f http://localhost:8000/api/v1/health` |

**依赖关系**：
- depends_on: postgres (condition: service_healthy)
- depends_on: redis (condition: service_healthy)

### 2.4 frontend — 前端开发服务

| 属性 | 值 |
|------|-----|
| 构建上下文 | `./frontend` |
| Dockerfile | `./frontend/Dockerfile` |
| 端口 | `5173:5173` |
| 环境变量 | `VITE_API_BASE_URL=http://localhost:8000/api/v1` |
| 开发模式 | Vite dev server + HMR |
| 生产模式 | 构建后由 nginx 静态托管，端口 80 |

**依赖关系**：
- depends_on: backend (condition: service_healthy)

### 2.5 sandbox-runner — 沙箱执行器（DinD）

| 属性 | 值 |
|------|-----|
| 镜像 | `docker:25-dind` |
| 端口 | 无外部暴露 |
| 特权模式 | `privileged: true`（DinD 必需） |
| 数据卷 | `sandbox_volumes:/var/lib/docker`、`./data:/data` |
| 环境变量 | `DOCKER_TLS_CERTDIR=""`（开发环境关闭 TLS） |

> ⚠️ sandbox-runner 使用 Docker-in-Docker，后端通过 Docker SDK 远程连接此容器创建/销毁分析沙箱。
>
> 生产环境应替换为独立的 Docker Host 或 Kubernetes 集群，避免 DinD。

**依赖关系**：
- depends_on: backend (condition: service_healthy)

### 2.6 pgadmin — 数据库管理（可选，开发用）

| 属性 | 值 |
|------|-----|
| 镜像 | `dpage/pgadmin4:latest` |
| 端口 | `5050:80` |
| 环境变量 | `PGADMIN_DEFAULT_EMAIL=admin@local / PGADMIN_DEFAULT_PASSWORD=admin` |
| profiles | `["dev"]`（仅 `docker compose --profile dev up` 启动） |

---

## 3. docker-compose.yml 完整定义

```yaml
# docker-compose.yml
version: "3.9"

services:
  # ─── 数据库 ───
  postgres:
    image: postgres:16-alpine
    container_name: sec_eval_pg
    restart: unless-stopped
    environment:
      POSTGRES_DB: sec_eval
      POSTGRES_USER: sec_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-sec_password}
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sec_user -d sec_eval"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - sec_net

  # ─── 缓存 ───
  redis:
    image: redis:7-alpine
    container_name: sec_eval_redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks:
      - sec_net

  # ─── 后端 ───
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: sec_eval_backend
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql+asyncpg://sec_user:${POSTGRES_PASSWORD:-sec_password}@postgres:5432/sec_eval
      REDIS_URL: redis://redis:6379/0
      DOCKER_HOST: tcp://sandbox-runner:2375
      SANDBOX_IMAGE_DEFAULT: python:3.12-slim
      LLM_MODE: ${LLM_MODE:-demo}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      OPENAI_BASE_URL: ${OPENAI_BASE_URL:-https://api.openai.com/v1}
      OPENAI_MODEL: ${OPENAI_MODEL:-gpt-4o}
      SECRET_KEY: ${SECRET_KEY:-change-me-in-production}
      CORS_ORIGINS: http://localhost:5173
      LOG_LEVEL: ${LOG_LEVEL:-info}
    volumes:
      - ./backend:/app
      - ./data:/app/data
      - ./agents:/app/agents
      - ./scanners:/app/scanners
      - ./report-templates:/app/report-templates
      - ./targets:/app/targets
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8000/api/v1/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 15s
    networks:
      - sec_net

  # ─── 前端 ───
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: ${FRONTEND_MODE:-development}
    container_name: sec_eval_frontend
    restart: unless-stopped
    ports:
      - "5173:5173"
    environment:
      VITE_API_BASE_URL: http://localhost:8000/api/v1
      VITE_WS_BASE_URL: ws://localhost:8000/api/v1/ws
    volumes:
      - ./frontend/src:/app/src
      - ./frontend/public:/app/public
    depends_on:
      backend:
        condition: service_healthy
    networks:
      - sec_net

  # ─── 沙箱执行器 (DinD) ───
  sandbox-runner:
    image: docker:25-dind
    container_name: sec_eval_sandbox
    restart: unless-stopped
    privileged: true
    environment:
      DOCKER_TLS_CERTDIR: ""
    volumes:
      - sandbox_volumes:/var/lib/docker
      - ./data:/data
    networks:
      - sec_net

  # ─── 数据库管理 (可选) ───
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: sec_eval_pgadmin
    restart: unless-stopped
    profiles:
      - dev
    ports:
      - "5050:80"
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@local
      PGADMIN_DEFAULT_PASSWORD: admin
    volumes:
      - pgadmin_data:/var/lib/pgadmin
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - sec_net

volumes:
  pg_data:
  redis_data:
  sandbox_volumes:
  pgadmin_data:

networks:
  sec_net:
    driver: bridge
```

---

## 4. .env.example

```ini
# ─── 数据库 ───
POSTGRES_PASSWORD=sec_password

# ─── LLM 配置 ───
LLM_MODE=demo                    # openai / ollama / demo
OPENAI_API_KEY=                   # 仅 LLM_MODE=openai 时需要
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o

# ─── 安全 ───
SECRET_KEY=change-me-in-production

# ─── 前端构建模式 ───
FRONTEND_MODE=development         # development / production

# ─── 日志 ───
LOG_LEVEL=info                    # debug / info / warn / error
```

---

## 5. 网络拓扑

```
外部访问:
  http://localhost:5173  →  frontend (Vite dev server)
  http://localhost:8000  →  backend (FastAPI)
  http://localhost:5050  →  pgadmin (仅 dev profile)
  http://localhost:5432  →  postgres (仅开发调试)

内部网络 sec_net (bridge):
  frontend   ←→  backend:8000      (API 请求)
  backend    ←→  postgres:5432     (数据库)
  backend    ←→  redis:6379        (缓存/pubsub)
  backend    ←→  sandbox-runner:2375 (Docker SDK 创建沙箱)
  sandbox-runner  ←→  /data        (源码快照共享)
```

---

## 6. 启动顺序与依赖链

```
postgres ──(healthy)──→ backend ──(healthy)──→ frontend
redis    ──(healthy)──→ backend
backend  ──(healthy)──→ sandbox-runner (可独立启动，无阻塞)
```

实际启动顺序：

1. postgres + redis 同时启动
2. 等待两者 healthcheck 通过
3. backend 启动，等待 healthcheck 通过
4. frontend 启动
5. sandbox-runner 启动（与 backend 并行，无启动阻塞）

---

## 7. 端口映射表

| 服务 | 容器端口 | 主机端口 | 协议 | 说明 |
|------|----------|----------|------|------|
| frontend | 5173 | 5173 | HTTP | Vite dev server |
| backend | 8000 | 8000 | HTTP + WS | FastAPI + WebSocket |
| postgres | 5432 | 5432 | TCP | PostgreSQL |
| redis | 6379 | 6379 | TCP | Redis |
| sandbox-runner | 2375 | — | TCP | Docker daemon（仅内部） |
| pgadmin | 80 | 5050 | HTTP | 仅 dev profile |

---

## 8. 数据流说明

### 8.1 源码接入流程

```
用户上传 Git URL / 压缩包
  → backend 接收，存入 ./data/snapshots/{projectId}/
  → 创建 source_snapshots 记录
  → 启动任务时，backend 指示 sandbox-runner 创建容器
  → 容器挂载 ./data/snapshots/{projectId}/ → /workspace/source (只读)
  → Agent 在容器内分析源码
```

### 8.2 沙箱执行流程

```
backend 调用 Docker SDK
  → 连接 sandbox-runner:2375 (Docker daemon)
  → 创建临时容器 (python:3.12-slim)
  → 挂载源码只读 + 临时可写目录
  → 设置网络: restricted (仅容器间通信) 或 isolated (无网络)
  → 设置资源限制: CPU 2核, 内存 2GB, 磁盘 4GB
  → 执行 Agent 命令
  → 回收 stdout/stderr 日志
  → 任务完成/停止时销毁容器
```

### 8.3 报告导出流程

```
ReportAgent 生成报告
  → Markdown 模板渲染 → 写入 ./data/reports/{taskId}/report.md
  → HTML 转换 → 写入 ./data/reports/{taskId}/report.html
  → PDF 转换 (wkhtmltopdf 或 Playwright) → 写入 ./data/reports/{taskId}/report.pdf
  → 更新 reports 表的文件路径
  → 用户通过 API 下载
```

---

## 9. 前端 Dockerfile

### 开发模式

```dockerfile
# frontend/Dockerfile
FROM node:20-slim AS development
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM node:20-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### nginx 反代配置（生产）

```nginx
# frontend/nginx.conf
server {
    listen 80;
    server_name _;

    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/v1/ws/ {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 10. 后端 Dockerfile

```dockerfile
# backend/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git gcc g++ libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制代码
COPY . .

EXPOSE 8000

# 开发模式：热重载
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

---

## 11. 预构建沙箱镜像

系统需要为不同技术栈准备扫描镜像。第一版至少提供 Python 和 Node.js：

### Python 扫描镜像

```dockerfile
# sandbox/images/python-scanner.Dockerfile
FROM python:3.12-slim

# 安装扫描工具
RUN pip install semgrep bandit pip-audit safety
# 安装 git (克隆源码用)
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# 非 root 用户
RUN useradd -m scanner
USER scanner

WORKDIR /workspace
```

### Node.js 扫描镜像

```dockerfile
# sandbox/images/node-scanner.Dockerfile
FROM node:20-slim

# 安装扫描工具
RUN npm install -g eslint eslint-plugin-security npm-audit-html

# 非 root 用户
RUN useradd -m scanner
USER scanner

WORKDIR /workspace
```

构建命令：

```bash
# 在项目根目录执行
docker build -f sandbox/images/python-scanner.Dockerfile -t sec-eval/python-scanner:latest .
docker build -f sandbox/images/node-scanner.Dockerfile -t sec-eval/node-scanner:latest .
```

---

## 12. 一键启动流程

```bash
# 1. 克隆仓库
git clone https://github.com/user/sec-eval.git
cd sec-eval

# 2. 复制配置
cp .env.example .env
# 编辑 .env，填入 OpenAI API Key（可选，demo 模式不需要）

# 3. 构建沙箱镜像
docker build -f sandbox/images/python-scanner.Dockerfile -t sec-eval/python-scanner:latest .
docker build -f sandbox/images/node-scanner.Dockerfile -t sec-eval/node-scanner:latest .

# 4. 启动所有服务
docker compose up -d

# 5. 初始化数据库（首次启动）
docker exec sec_eval_backend python -m app.init_db

# 6. 访问
# 前端: http://localhost:5173
# 后端 API: http://localhost:8000/api/v1
# API 文档: http://localhost:8000/docs
# pgAdmin: http://localhost:5050 (仅 --profile dev)
```

---

## 13. 安全注意事项

| 风险 | 应对措施 | 状态 |
|------|----------|------|
| DinD 特权模式 | 仅用于开发/演示环境；生产用独立 Docker Host | M1 可接受 |
| 源码泄露 | 在线 LLM 模式需用户确认；提供 demo 模式 | 已设计 |
| 沙箱逃逸 | 非 root 用户、最小 capability、只读根文件系统 | M2 实现 |
| API 无认证 | MVP 用静态 token；M3 扩展 OAuth2 | M1 可接受 |
| 密钥管理 | .env 不提交；API Key 不入库 | 已设计 |
| 端口暴露 | postgres/redis 仅开发调试暴露；生产环境绑定 127.0.0.1 | 已设计 |
