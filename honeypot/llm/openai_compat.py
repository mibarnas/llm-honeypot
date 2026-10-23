"""ChatGPT (OpenAI) and OpenRouter backends, both via the OpenAI SDK."""

from __future__ import annotations

import openai

from .base import Completion, LLMError, LLMProvider, RESPONSE_SCHEMA

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: float, base_url: str | None = None):
        super().__init__(api_key, model, timeout)
        self._client = openai.AsyncOpenAI(
            api_key=api_key, base_url=base_url, timeout=timeout, max_retries=1
        )

    def _request_params(self) -> dict:
        return {
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "terminal_response", "strict": True, "schema": RESPONSE_SCHEMA},
            },
            "max_completion_tokens": 4000,
        }

    async def complete(self, system: str, messages: list[dict]) -> Completion:
        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, *messages],
                **self._request_params(),
            )
        except openai.APIConnectionError as exc:
            raise LLMError(f"connection error: {exc}") from exc
        except openai.APIStatusError as exc:
            raise LLMError(f"API error {exc.status_code}: {exc.message}") from exc

        if not response.choices:
            raise LLMError("reply had no choices")
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            raise LLMError("model declined the request")
        if not message.content:
            raise LLMError(f"empty reply (finish_reason={response.choices[0].finish_reason})")

        usage = {}
        if response.usage:
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }
        return Completion(text=message.content, usage=usage)

    async def aclose(self) -> None:
        await self._client.close()


class OpenRouterProvider(OpenAIProvider):
    name = "openrouter"

    def __init__(self, api_key: str, model: str, timeout: float):
        super().__init__(api_key, model, timeout, base_url=OPENROUTER_BASE_URL)

    def _request_params(self) -> dict:
        # Plain JSON mode is supported by far more OpenRouter models than strict schemas.
        return {"response_format": {"type": "json_object"}, "max_tokens": 4000}
