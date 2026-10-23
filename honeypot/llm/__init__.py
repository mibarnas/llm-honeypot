"""LLM backends."""

from __future__ import annotations

from .base import Completion, LLMError, LLMProvider, LLMResponse, ReplyFormatError, parse_response


def create_provider(provider: str, api_key: str, model: str, timeout: float) -> LLMProvider:
    if provider == "anthropic":
        from .claude import AnthropicProvider

        return AnthropicProvider(api_key, model, timeout)
    if provider == "openai":
        from .openai_compat import OpenAIProvider

        return OpenAIProvider(api_key, model, timeout)
    if provider == "openrouter":
        from .openai_compat import OpenRouterProvider

        return OpenRouterProvider(api_key, model, timeout)
    raise ValueError(f"unknown provider: {provider}")


__all__ = [
    "Completion", "LLMError", "LLMProvider", "LLMResponse", "ReplyFormatError",
    "create_provider", "parse_response",
]
