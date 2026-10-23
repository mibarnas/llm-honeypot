from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from honeypot.config import Config
from honeypot.llm import Completion, LLMProvider


def reply(output="", user="admin", cwd="/home/admin", action="none", target="none", prompt="",
          program_prompt=""):
    return json.dumps(
        {"output": output, "user": user, "cwd": cwd, "action": action,
         "password_target": target, "prompt": prompt, "program_prompt": program_prompt}
    )


class FakeProvider(LLMProvider):
    """Returns scripted replies and records every request."""

    name = "fake"

    def __init__(self, replies=None):
        super().__init__("key", "fake-model", 5)
        self.replies = list(replies or [])
        self.requests: list[tuple[str, list[dict]]] = []

    async def complete(self, system, messages):
        self.requests.append((system, [dict(m) for m in messages]))
        if not self.replies:
            return Completion(text=reply())
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return Completion(text=item, usage={"input_tokens": 1, "output_tokens": 1})


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        llm_provider="anthropic",
        llm_api_key="key",
        llm_model="fake-model",
        root_password="r00t-secret",
        admin_password=None,
        listen_host="127.0.0.1",
        listen_port=0,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        hostname="testhost",
        max_sessions=5,
        max_commands=50,
        idle_timeout=30,
        llm_timeout=5,
        history_turns=10,
        log_level="INFO",
    )


@pytest.fixture
def with_admin_password(config):
    return replace(config, admin_password="adm1n-secret")
