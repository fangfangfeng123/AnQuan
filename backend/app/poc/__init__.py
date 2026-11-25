"""PoC 验证层包。

本包仅保留 PoC 验证的**无状态工具**，不存放业务逻辑或 DB 写入：

- payloads.py：探针模板库（按漏洞类型预置安全载荷）
- executor.py：PoC 执行器（在沙箱内发送探针）
- verifier.py：PoC 结果验证器（比对响应与预期特征）

业务编排（启动目标服务 / 执行探针 / 保存证据 / 更新 finding 状态）
统一在 services/poc_service.py；证据 CRUD 在 services/poc_evidence_service.py。
"""