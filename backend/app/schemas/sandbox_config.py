"""沙箱配置请求/响应模型。

本模块定义沙箱配置管理的 API 请求和响应模型：
- SandboxConfigResponse：沙箱配置响应
  （default_image / network_mode / memory_limit / cpu_limit / timeout）
- SandboxConfigUpdateRequest：更新配置请求
- AvailableImage：可用镜像（name / tag / size / description）
- SandboxStatusResponse：沙箱运行状态（container_id / status / created_at / ports）
"""
# TODO: SandboxConfigResponse / SandboxConfigUpdateRequest / AvailableImage /
#       ResourceLimits
