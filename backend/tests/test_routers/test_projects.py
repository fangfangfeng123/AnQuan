"""项目管理路由测试模块。

本模块测试项目管理 API：
- 测试 POST /projects 创建项目
- 测试 POST /projects/upload 上传 ZIP
- 测试 GET /projects 分页列表
- 测试 GET /projects/{id} 详情
- 测试 DELETE /projects/{id} 归档
- 测试 POST /projects/{id}/restore 恢复
- 测试认证拦截（无 Token 返回 401）
"""
# TODO
