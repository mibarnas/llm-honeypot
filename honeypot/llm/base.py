"""Provider interface and response parsing shared by all LLM backends."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "output": {"type": "string"},
        "user": {"type": "string"},
        "cwd": {"type": "string"},
        "action": {"type": "string", "enum": ["none", "password_prompt"]},
        "password_target": {"type": "string", "enum": ["none", "root", "admin"]},
        "prompt": {"type": "string"},
    },
    "required": ["output", "user", "cwd", "action", "password_target", "prompt"],
    "additionalProperties": False,
}

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class LLMError(Exception):
    """The provider failed to produce a usable reply."""


class ReplyFormatError(LLMError):
    """The model replied, but not in the expected JSON format."""


@dataclass
class Completion:
    text: str
    usage: dict = field(default_factory=dict)


@dataclass
class LLMResponse:
    output: str
    user: str
    cwd: str
    action: str = "none"
    password_target: str = "none"
    prompt: str = ""
    raw: str = ""

    @property
    def wants_password(self) -> bool:
        return self.action == "password_prompt" and self.password_target in ("root", "admin")

    def to_json(self) -> str:
        return json.dumps(
            {
                "output": self.output,
                "user": self.user,
                "cwd": self.cwd,
                "action": self.action,
                "password_target": self.password_target,
                "prompt": self.prompt,
            },
            ensure_ascii=False,
        )


def _looks_like_json(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith(("{", "[", "```")) or '"output"' in text


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        return data

    # Malformed or wrapped JSON: take the first embedded object that decodes
    # and looks like a reply.
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "output" in obj:
            return obj
    return None


def parse_response(text: str, user: str, cwd: str) -> LLMResponse:
    """Parse a model reply, falling back to the current state for bad fields.

    Plain-text replies are treated as terminal output. Replies that look like
    broken JSON raise ReplyFormatError so they are never shown to the visitor.
    """
    data = _extract_json(text)
    if data is None:
        if _looks_like_json(text):
            raise ReplyFormatError("model reply was malformed JSON")
        log.warning("model reply was not JSON; using it as raw output")
        return LLMResponse(output=text, user=user, cwd=cwd, raw=text)

    # Some models nest the whole reply inside "output".
    while isinstance(data.get("output"), dict):
        data = data["output"]

    output = data.get("output")
    new_user = data.get("user")
    new_cwd = data.get("cwd")
    action = data.get("action")
    target = data.get("password_target")
    prompt = data.get("prompt")

    if not isinstance(new_user, str) or not _USERNAME_RE.match(new_user):
        new_user = user
    if not isinstance(new_cwd, str) or not new_cwd.startswith("/") or "\x00" in new_cwd:
        new_cwd = cwd
    if action not in ("none", "password_prompt"):
        action = "none"
    if target not in ("none", "root", "admin"):
        target = "none"

    return LLMResponse(
        output=output if isinstance(output, str) else "",
        user=new_user,
        cwd=new_cwd,
        action=action,
        password_target=target,
        prompt=prompt if isinstance(prompt, str) else "",
        raw=text,
    )


class LLMProvider(ABC):
    """A chat backend that returns the model's reply text for a conversation."""

    name: str = "base"

    def __init__(self, api_key: str, model: str, timeout: float):
        self.model = model
        self.timeout = timeout

    @abstractmethod
    async def complete(self, system: str, messages: list[dict]) -> Completion:
        """Return the reply to ``messages`` (alternating user/assistant dicts)."""

    async def aclose(self) -> None:
        """Release network resources."""
