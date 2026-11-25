"""Agent 基类模块。

本模块定义所有 Agent 的公共接口和生命周期：
- AgentBase 抽象基类：
  - __init__(task_id, sandbox_id, llm_client, services)：注入依赖
  - run() → AgentResult：执行入口（子类实现）
  - emit_result(result)：通过 WebSocket 广播执行结果
  - emit_log(level, message)：记录日志并广播
- AgentResult 枚举：success / partial / failed / skipped
- 所有具体 Agent 继承 AgentBase 并实现 run() 方法
- Agent 内部调用 services 层完成实际操作，不直接操作 DB
"""
# TODO: AgentBase: init / run / emit_result 生命周期
#       封装 LLM 调用、日志写入、事件推送、沙箱命令执行
