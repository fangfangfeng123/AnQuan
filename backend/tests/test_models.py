"""ORM 模型 CRUD 测试模块。

本模块测试所有 ORM 模型的数据库操作：
- 测试 Project 的增删改查
- 测试 Task 与 Project 的外键关系
- 测试 Finding 与 Task 的一对多关系
- 测试 PocEvidence 与 Finding 的一对一关系
- 测试级联删除行为
- 测试 JSONB 字段的读写
- 测试时间戳自动填充
"""
# TODO: 创建项目 -> 创建任务 -> 创建漏洞 -> 验证关系和级联删除
