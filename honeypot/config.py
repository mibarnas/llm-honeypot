"""Configuration loading from the environment / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROVIDERS = ("openai", "anthropic", "openrouter")

DEFAULT_MODELS = {
    "openai": "gpt-5-mini",
    "anthropic": "claude-opus-5-5",
    "openrouter": "openai/gpt-5-mini",
}


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    llm_provider: str
    llm_api_key: str
    llm_model: str
    root_password: str
    admin_password: str | None
    listen_host: str
    listen_port: int
    data_dir: Path
    log_dir: Path
    hostname: str
    max_sessions: int
    max_commands: int
    idle_timeout: int
    llm_timeout: int
    history_turns: int
    log_level: str

    @property
    def host_key_path(self) -> Path:
        return self.data_dir / "ssh_host_ed25519_key"


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def load_config(env_file: str | os.PathLike | None = None) -> Config:
    """Load configuration from an env file and the process environment.

    The env file is taken from ``env_file``, then ``$HONEYPOT_ENV_FILE``, then
    ``./.env``. Variables already present in the environment win, so systemd
    ``Environment=`` lines can override the file.
    """
    path = env_file or os.environ.get("HONEYPOT_ENV_FILE") or ".env"
    if Path(path).is_file():
        load_dotenv(path, override=False)
    elif env_file or os.environ.get("HONEYPOT_ENV_FILE"):
        raise ConfigError(f"env file not found: {path}")

    provider = _str("LLM_PROVIDER").lower()
    if provider not in PROVIDERS:
        raise ConfigError(
            f"LLM_PROVIDER must be one of {', '.join(PROVIDERS)}, got {provider!r}"
        )

    api_key = _str("LLM_API_KEY")
    if not api_key:
        raise ConfigError("LLM_API_KEY is required")

    root_password = os.environ.get("ROOT_PASSWORD", "")
    if not root_password:
        raise ConfigError("ROOT_PASSWORD is required")

    port = _int("LISTEN_PORT", 2222, minimum=1)
    if port > 65535:
        raise ConfigError(f"LISTEN_PORT must be <= 65535, got {port}")

    return Config(
        llm_provider=provider,
        llm_api_key=api_key,
        llm_model=_str("LLM_MODEL", DEFAULT_MODELS[provider]),
        root_password=root_password,
        admin_password=os.environ.get("ADMIN_PASSWORD") or None,
        listen_host=_str("LISTEN_HOST", "0.0.0.0"),
        listen_port=port,
        data_dir=Path(_str("DATA_DIR", "./data")).resolve(),
        log_dir=Path(_str("LOG_DIR", "./logs")).resolve(),
        hostname=_str("HONEYPOT_HOSTNAME", "srv-prod-01"),
        max_sessions=_int("MAX_SESSIONS", 10, minimum=1),
        max_commands=_int("MAX_COMMANDS", 200, minimum=1),
        idle_timeout=_int("IDLE_TIMEOUT", 600, minimum=10),
        llm_timeout=_int("LLM_TIMEOUT", 30, minimum=1),
        history_turns=_int("HISTORY_TURNS", 30, minimum=1),
        log_level=_str("LOG_LEVEL", "INFO").upper(),
    )
