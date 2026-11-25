"""pytest 测试配置和 fixtures 模块。

本模块定义所有测试共享的 fixtures：
- test_db：测试用异步数据库引擎（SQLite in-memory）
- test_client：FastAPI TestClient
- mock_llm_client：模拟 LLM 客户端（返回固定响应）
- mock_sandbox_manager：模拟沙箱管理器（不实际创建容器）
- sample_project：预置测试项目
- sample_task：预置测试任务
- sample_finding：预置测试漏洞
- clean_db：每个测试后清理数据库
"""
# TODO: 测试数据库引擎 / 测试客户端 / Mock LLM / Mock SandboxManager
