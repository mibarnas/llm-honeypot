"""Claude backend (Anthropic Messages API)."""

from __future__ import annotations

import anthropic

from .base import Completion, LLMError, LLMProvider, RESPONSE_SCHEMA

# Models that accept output_config.effort.
_EFFORT_PREFIXES = ("claude-opus-5", "claude-sonnet-5", "claude-haiku-5", "claude-fable-5")
# Models that accept the server-side refusal fallback (`fallbacks: "default"`).
_FALLBACK_MODELS = ("claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5")


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float):
        super().__init__(api_key, model, timeout)
        self._client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=1)

    async def complete(self, system: str, messages: list[dict]) -> Completion:
        output_config: dict = {"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}}
        if self.model.startswith(_EFFORT_PREFIXES):
            # Terminal replies are short and latency matters more than depth.
            output_config["effort"] = "low"

        params = dict(
            model=self.model,
            max_tokens=16000,
            system=system,
            messages=messages,
            output_config=output_config,
        )
        try:
            if self.model in _FALLBACK_MODELS:
                response = await self._client.beta.messages.create(
                    betas=["server-side-fallback-2026-07-01"], fallbacks="default", **params
                )
            else:
                response = await self._client.messages.create(**params)
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"connection error: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"API error {exc.status_code}: {exc.message}") from exc

        if response.stop_reason == "refusal":
            raise LLMError("model declined the request")

        text = next((b.text for b in response.content if b.type == "text"), "")
        if not text:
            raise LLMError(f"empty reply (stop_reason={response.stop_reason})")

        usage = response.usage
        return Completion(
            text=text,
            usage={"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens},
        )

    async def aclose(self) -> None:
        await self._client.close()
