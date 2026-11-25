"""AI 修复补丁层包。

本包负责 AI 驱动的漏洞修复补丁生成和校验：
- generator.py：补丁生成器（LLM 驱动）
- validator.py：补丁校验器（语法 / 编译 / 安全回归）
- repository.py：补丁持久化（CRUD）
"""
