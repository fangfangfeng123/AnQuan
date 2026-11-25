# 自动化安全评估系统

基于多智能体协同、SAST/污点分析、Docker 沙箱和动态 PoC 验证的代码工程安全评估平台。

## 当前状态

项目处于持续开发阶段，核心模块正在按阶段完善。

## 主要模块

- 项目与源码快照管理
- Docker 沙箱隔离与命令执行
- 环境侦察与技术栈识别
- Semgrep/Bandit 静态审计与污点追踪
- 漏洞管理与 WebSocket 实时事件
- 前端评估工作台

## 演示账号

系统登录页不会直接显示账号和密码，请使用下方演示账号手动登录。

| 角色 | 账号 | 密码 |
|------|------|------|
| 安全工程师 / 审计人员 | `admingcs` | `admingcs` |
| 研发人员 | `adminyf` | `adminyf` |
| 系统管理员 | `admingly` | `admingly` |

如果使用本地 Ollama 生成补丁，可先执行：

```powershell
D:\ranjian\Ollom\ollama.exe serve
```

## 本地开发

先复制环境变量示例：

```powershell
Copy-Item .env.example .env
Copy-Item backend/.env.example backend/.env
```

安装后端和前端依赖：

```powershell
cd backend
pip install -r requirements.txt

cd ../frontend
npm install
```

启动数据库和 Redis：

```powershell
docker compose -f docker-compose.dev.yml up postgres redis -d
```

初始化数据库：

```powershell
python scripts/init_db.py
```

启动开发服务：

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001

cd ../frontend
npm run dev
```

说明：如果本机 8000 已被其他程序占用，请继续使用 8001；前端代理也已默认指向 8001。
