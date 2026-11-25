"""OpenAI API 客户端模块。"""

from openai import OpenAI

from app.core.config import get_settings
from app.llm.base import LlmClientBase


class OpenAIClient(LlmClientBase):
    """通过 OpenAI 兼容接口调用云端模型。"""

    def __init__(self) -> None:
        settings = get_settings()
        self.client = OpenAI(
            api_key=settings.OPENAI_API_KEY or "not-configured",
            base_url=settings.OPENAI_BASE_URL or None,
        )
        self.model = settings.OPENAI_MODEL
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS

    def chat(self, messages: list[dict]) -> str:
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return completion.choices[0].message.content or ""

    def chat_with_usage(self, messages: list[dict]) -> tuple[str, int]:
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        usage = completion.usage
        token_usage = (usage.prompt_tokens + usage.completion_tokens) if usage else 0
        return completion.choices[0].message.content or "", token_usage
