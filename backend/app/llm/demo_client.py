"""演示模式客户端模块。"""

from app.llm.base import LlmClientBase


class DemoClient(LlmClientBase):
    """不调用外部模型，用于未配置大模型时的功能演示。"""

    def chat(self, messages: list[dict]) -> str:
        return "demo-mode response"
