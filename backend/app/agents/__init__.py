"""多 Agent 编排层包。

本包定义系统的五个 Agent，每个 Agent 负责一个评估阶段。
Agent 只做编排和决策，不直接操作数据库——所有 DB 操作通过 services 层。
- base.py：Agent 基类（生命周期管理）
- recon.py：环境侦察 Agent（阶段一）
- code_audit.py：静态代码审计 Agent（阶段二）
- poc_verify.py：PoC 验证 Agent（阶段三）
- exploit_chain.py：攻击链推演 Agent（阶段四）
- report_gen.py：报告生成 Agent（阶段五）
- orchestrator.py：编排引擎（五阶段状态机）
"""
