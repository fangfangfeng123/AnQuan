"""污点传播分析引擎包。

本包实现自研的轻量级污点分析引擎，用于检测注入类漏洞：
- source.py：Source 规则（外部输入入口）
- sink.py：Sink 规则（敏感操作函数）
- sanitizer.py：Sanitizer 规则（安全过滤函数）
- engine.py：污点传播引擎（AST 遍历 + 数据流追踪）
- result.py：分析结果模型
- facade.py：统一入口（供 Agent 调用）
"""
