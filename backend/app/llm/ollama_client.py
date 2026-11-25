"""Ollama 本地模型客户端模块。"""

import httpx

from app.core.config import get_settings
from app.llm.base import LlmClientBase


class OllamaClient(LlmClientBase):
    """通过 Ollama HTTP API 调用本地模型。"""

    def __init__(self) -> None:
        settings = get_settings()
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.LLM_TIMEOUT
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS

    def chat(self, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        return data.get("message", {}).get("content", "")

    def chat_with_usage(self, messages: list[dict]) -> tuple[str, int]:
        import json

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        content = data.get("message", {}).get("content", "")
        usage = data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
        if not usage and content:
            usage = max(0, len(json.dumps(payload, ensure_ascii=False)) // 4)
        return content, usage
