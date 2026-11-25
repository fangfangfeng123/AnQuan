"""大语言模型客户端封装层包。

本包为系统提供统一的 LLM 调用接口，支持多种后端：
- base.py：LLM 客户端基类（含 token 预算控制）
- openai_client.py：OpenAI API 客户端
- ollama_client.py：Ollama 本地模型客户端
- demo_client.py：演示模式客户端（无 API Key 时使用）
- factory.py：LLM 工厂（根据模式选择客户端）
"""
