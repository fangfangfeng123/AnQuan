"""自动化安全评估系统 - 后端主包。

本包是整个后端应用的根包，包含以下子包：
- core：基础设施层（数据库、Redis、配置、异常、认证）
- models：SQLAlchemy ORM 模型层
- schemas：Pydantic 请求/响应模型层（独立于 ORM）
- routers：FastAPI 路由层（HTTP 接口）
- websockets：WebSocket 实时推送层
- services：业务逻辑层（所有 DB 操作集中于此）
- workers：后台任务消费者（Redis 队列驱动）
- agents：多 Agent 编排层（只做决策和调度，不直接操作 DB）
- sandbox：Docker 沙箱管理层
- scanners：静态扫描器适配层（Semgrep / Bandit / CodeQL / Joern）
- taint：污点传播分析引擎
- poc：PoC 验证层（探针发送 + 结果比对）
- exploit：攻击链 DAG 构建层
- scoring：CVSS 3.1 评分计算
- reports：报告生成与导出层
- patches：AI 修复补丁生成与校验层
- llm：大语言模型客户端封装层
"""
