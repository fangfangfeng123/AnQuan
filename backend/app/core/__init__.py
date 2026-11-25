"""核心基础设施层包。

本包包含系统运行的基础设施组件：
- config.py：全局配置（.env 环境变量读取）
- database.py：SQLAlchemy 异步引擎和会话工厂
- redis.py：Redis 异步连接池
- errors.py：统一异常类型定义
- security.py：认证与授权中间件
"""
