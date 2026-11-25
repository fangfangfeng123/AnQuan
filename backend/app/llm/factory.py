"""LLM 工厂模块。"""

from app.core.config import get_settings
from app.llm.base import LlmClientBase
from app.llm.demo_client import DemoClient
from app.llm.ollama_client import OllamaClient
from app.llm.openai_client import OpenAIClient


class LlmFactory:
    """根据当前配置创建 LLM 客户端。"""

    _clients: dict[str, LlmClientBase] = {}

    @classmethod
    def get_client(cls, mode: str | None = None) -> LlmClientBase:
        settings = get_settings()
        selected = mode or settings.LLM_MODE
        if selected not in cls._clients:
            if selected == "ollama":
                client: LlmClientBase = OllamaClient()
            elif selected == "openai":
                client = OpenAIClient()
            else:
                client = DemoClient()
            cls._clients[selected] = client
        return cls._clients[selected]
