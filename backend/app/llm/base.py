"""LLM 客户端基类模块。"""


class LlmClientBase:
    """大语言模型客户端基类。"""

    def chat(self, messages: list[dict]) -> str:
        raise NotImplementedError

    def chat_with_usage(self, messages: list[dict]) -> tuple[str, int]:
        response = self.chat(messages)
        return response, self.estimate_tokens(response)

    def estimate_tokens(self, text: str) -> int:
        return max(0, len(text) // 4)
