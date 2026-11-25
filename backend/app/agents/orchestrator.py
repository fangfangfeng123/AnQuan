"""编排引擎模块。

本模块是五阶段编排的状态机核心：
- 五阶段顺序执行：recon → code_audit → poc_verify → exploit_chain → report
- 每个阶段对应一个 Agent
- 阶段间状态流转：
  - not_started → in_progress → done / failed / skipped
- 支持阶段跳过（如无 verified 漏洞则跳过 exploit_chain）
- 支持失败重试（单阶段最多重试 3 次）
- 支持中途暂停和恢复
- 编排逻辑由 task_executor 调用，不直接操作 DB
"""
# TODO: 五阶段顺序状态机 recon -> code_audit -> poc_verify ->
#       exploit_chain -> report_gen，管理 Agent 实例化和异常
