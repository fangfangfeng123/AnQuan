"""攻击链路由模块。

本模块定义攻击链数据的 HTTP 接口：
- GET /tasks/{id}/attack-chain：获取任务的攻击链 DAG
  返回节点列表 + 边列表 + 最终影响 + 整体严重等级
  前端用此数据渲染有向无环图可视化
"""
# TODO: GET /tasks/{id}/attack-chain
