"""静态扫描器适配层包。

本包为多种安全扫描工具提供统一适配接口：
- base.py：扫描器基类（统一输出格式）
- semgrep.py：Semgrep 适配器（规则扫描）
- bandit.py：Bandit 适配器（Python 安全扫描）
- codeql.py：CodeQL 适配器（预留）
- joern.py：Joern 适配器（预留）
- dependency_check.py：依赖漏洞扫描适配器（预留）
"""
