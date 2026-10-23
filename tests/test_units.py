from __future__ import annotations

import json

import pytest

from honeypot import config as config_mod
from honeypot.config import ConfigError, load_config
from honeypot.llm import ReplyFormatError, parse_response
from honeypot.recorder import SessionRecorder
from honeypot.session import ShellState, check_password

ENV_KEYS = ["LLM_PROVIDER", "LLM_API_KEY", "ROOT_PASSWORD", "ADMIN_PASSWORD", "LLM_MODEL",
            "LISTEN_PORT", "HONEYPOT_ENV_FILE", "DATA_DIR", "LOG_DIR"]


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    return monkeypatch


def write_env(tmp_path, body):
    path = tmp_path / "test.env"
    path.write_text(body)
    return path


class TestConfig:
    def test_minimal(self, clean_env, tmp_path):
        env = write_env(tmp_path, "LLM_PROVIDER=openrouter\nLLM_API_KEY=k\nROOT_PASSWORD=r\n")
        cfg = load_config(env)
        assert cfg.llm_provider == "openrouter"
        assert cfg.llm_model == config_mod.DEFAULT_MODELS["openrouter"]
        assert cfg.admin_password is None
        assert cfg.listen_port == 2222

    def test_admin_password_optional_and_set(self, clean_env, tmp_path):
        env = write_env(tmp_path, "LLM_PROVIDER=openai\nLLM_API_KEY=k\nROOT_PASSWORD=r\nADMIN_PASSWORD=a\n")
        assert load_config(env).admin_password == "a"

    @pytest.mark.parametrize("body, message", [
        ("LLM_PROVIDER=gemini\nLLM_API_KEY=k\nROOT_PASSWORD=r\n", "LLM_PROVIDER"),
        ("LLM_PROVIDER=openai\nROOT_PASSWORD=r\n", "LLM_API_KEY"),
        ("LLM_PROVIDER=openai\nLLM_API_KEY=k\n", "ROOT_PASSWORD"),
        ("LLM_PROVIDER=openai\nLLM_API_KEY=k\nROOT_PASSWORD=r\nLISTEN_PORT=abc\n", "LISTEN_PORT"),
    ])
    def test_invalid(self, clean_env, tmp_path, body, message):
        with pytest.raises(ConfigError, match=message):
            load_config(write_env(tmp_path, body))

    def test_missing_explicit_file(self, clean_env, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(tmp_path / "nope.env")


class TestParseResponse:
    def test_valid(self):
        text = json.dumps({"output": "hi\n", "user": "root", "cwd": "/root", "action": "none",
                           "password_target": "none", "prompt": ""})
        r = parse_response(text, "admin", "/home/admin")
        assert (r.output, r.user, r.cwd, r.wants_password) == ("hi\n", "root", "/root", False)

    def test_code_fence_and_surrounding_text(self):
        r = parse_response('```json\n{"output": "x", "user": "admin", "cwd": "/tmp"}\n```', "admin", "/")
        assert r.output == "x" and r.cwd == "/tmp"

    def test_not_json_becomes_output(self):
        r = parse_response("total 0\n", "admin", "/home/admin")
        assert r.output == "total 0\n" and r.user == "admin"

    def test_bad_fields_fall_back(self):
        text = json.dumps({"output": 5, "user": "Bad User!", "cwd": "relative",
                           "action": "rm", "password_target": "bob"})
        r = parse_response(text, "admin", "/home/admin")
        assert (r.output, r.user, r.cwd, r.action, r.password_target) == ("", "admin", "/home/admin", "none", "none")

    def test_malformed_wrapped_reply_from_real_session(self):
        # Seen from nvidia/nemotron via OpenRouter: wrapped and missing a brace.
        text = ('{"output":{"output": "", "user": "admin", "cwd": "/home/admin/Documents", '
                '"action": "none", "password_target": "none", "prompt": ""}')
        r = parse_response(text, "admin", "/home/admin/Documents")
        assert r.output == "" and r.cwd == "/home/admin/Documents"

    def test_nested_reply_is_unwrapped(self):
        inner = {"output": "a\n", "user": "admin", "cwd": "/tmp", "action": "none",
                 "password_target": "none", "prompt": ""}
        r = parse_response(json.dumps({"output": inner}), "admin", "/")
        assert r.output == "a\n" and r.cwd == "/tmp"

    @pytest.mark.parametrize("text", ['{"output": "x", "user": ', '```json\n{"output"', '[1, 2'])
    def test_unrecoverable_json_raises(self, text):
        with pytest.raises(ReplyFormatError):
            parse_response(text, "admin", "/")

    def test_password_prompt(self):
        text = json.dumps({"output": "", "user": "admin", "cwd": "/", "action": "password_prompt",
                           "password_target": "root", "prompt": "Password: "})
        assert parse_response(text, "admin", "/").wants_password


class TestPasswords:
    def test_root(self, config):
        assert check_password(config, "root", "r00t-secret")
        assert not check_password(config, "root", "wrong")

    def test_admin_any_when_unset(self, config):
        assert check_password(config, "admin", "anything")

    def test_admin_enforced_when_set(self, with_admin_password):
        assert check_password(with_admin_password, "admin", "adm1n-secret")
        assert not check_password(with_admin_password, "admin", "anything")


def test_prompt_rendering():
    s = ShellState(user="admin", cwd="/home/admin/src", hostname="h")
    assert s.prompt() == "admin@h:~/src$ "
    s.user, s.cwd = "root", "/etc"
    assert s.prompt() == "root@h:/etc# "


def test_recorder(tmp_path):
    rec = SessionRecorder(tmp_path, "abc", "1.2.3.4")
    rec.event("command", command="ls")
    rec.close()
    rec.event("ignored")
    lines = rec.path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["command"] == "ls"


@pytest.mark.parametrize("command, expected", [
    ("sudo -i", ["-i"]),
    ("sudo su -", ["su", "-"]),
    ("sudo -u root bash", ["-u", "root", "bash"]),
    ("sudo", None),
    ("sudo -h", None),
    ("sudo -V", None),
    ("cd / && sudo -i", None),
    ("echo pw | sudo -S id", None),
    ("sudoedit /etc/hosts", None),
    ("ls", None),
])
def test_plain_sudo_args(command, expected):
    from honeypot.session import plain_sudo_args
    assert plain_sudo_args(command) == expected
