"""Alembic 数据库迁移环境配置。

本文件由 Alembic 框架自动调用，负责：
- 读取 application 的 Settings（数据库连接 URL）
- 将 SQLAlchemy 模型的 Base.metadata 绑定到迁移上下文
- 支持离线模式（生成 SQL）和在线模式（直接执行）
- 同时兼容同步和异步引擎
"""
# TODO: 关联 models Base.metadata，支持异步引擎
