# LLM SSH Honeypot

An SSH server whose shell is entirely simulated by an LLM (ChatGPT, Claude or
OpenRouter). Nothing a visitor types is executed: each command is sent to the
model, and the model's reply is printed as terminal output. Every session is
recorded.

- Log in as `admin`. Any password works unless `ADMIN_PASSWORD` is set.
- After login, a normal-looking Ubuntu login banner with a few odd details
  hints that something is off with the server, without saying it is a honeypot.
- `su`/`sudo` password prompts are handled by the server. The model asks for a
  password, the server reads it with echo off and checks it against
  `ROOT_PASSWORD` / `ADMIN_PASSWORD`, and the model is told only whether the
  check succeeded. Passwords never reach the LLM.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp .env.example .env        # fill in LLM_PROVIDER, LLM_API_KEY, ROOT_PASSWORD
```

**Write the system prompt.** `SYSTEM_PROMPT` in
[honeypot/prompts.py](honeypot/prompts.py) ships empty, and the honeypot
refuses to start until you fill it in. The module docstring describes the JSON
reply format the code expects and the `{hostname}` placeholder. Don't put
either password in the prompt.

```bash
.venv/bin/llm-honeypot                 # or: python -m honeypot --env-file .env
ssh -p 2222 admin@localhost
```

## Configuration (`.env`)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `LLM_PROVIDER` | yes | | `openai`, `anthropic` or `openrouter` |
| `LLM_API_KEY` | yes | | API key for that provider |
| `ROOT_PASSWORD` | yes | | Password accepted for `su` / root |
| `ADMIN_PASSWORD` | no | empty | If set, required for SSH login and sudo prompts; if empty, any password works |
| `LLM_MODEL` | no | per provider | `claude-opus-5-5`, `gpt-5-mini`, `openai/gpt-5-mini` |
| `LISTEN_HOST` / `LISTEN_PORT` | no | `0.0.0.0` / `2222` | |
| `DATA_DIR` | no | `./data` | Host key location |
| `LOG_DIR` | no | `./logs` | Session recordings |
| `HONEYPOT_HOSTNAME` | no | `srv-prod-01` | Shown in the prompt |
| `MAX_SESSIONS` | no | `10` | Concurrent connections |
| `MAX_COMMANDS` | no | `200` | Commands per session |
| `IDLE_TIMEOUT` | no | `600` | Seconds before auto-logout |
| `LLM_TIMEOUT` | no | `30` | Seconds per LLM request |
| `HISTORY_TURNS` | no | `30` | Past commands sent as context |
| `LOG_LEVEL` | no | `INFO` | |

The env file is read from `--env-file`, then `$HONEYPOT_ENV_FILE`, then
`./.env`. Variables already set in the environment take precedence.

## Session recordings

One JSONL file per connection in `LOG_DIR`, named
`<utc-time>_<ip>_<session-id>.jsonl`. Events: `connect`, `auth`,
`session_start`, `command`, `response` (with token usage), `password_prompt`
(target and success only, never the password), `user_change`, `program_start` / `input` / `program_exit` (interactive programs such as
`python3`), `error`,
`idle_timeout`, `command_limit`, `disconnect`.

```bash
jq -r 'select(.event=="command") | .command' logs/*.jsonl
```

## Running as a systemd service

```bash
sudo ./deploy/install.sh
sudoedit /etc/llm-honeypot/honeypot.env
sudo systemctl enable --now llm-honeypot
journalctl -u llm-honeypot -f
```

This installs to `/opt/llm-honeypot`, runs as the unprivileged
`llm-honeypot` user with systemd sandboxing, keeps the host key in
`/var/lib/llm-honeypot` and recordings in `/var/log/llm-honeypot`. To listen
on port 22, set `LISTEN_PORT=22` and uncomment the two capability lines in
[deploy/llm-honeypot.service](deploy/llm-honeypot.service). (Move the real
sshd to another port first.) Re-run `install.sh` to upgrade; it leaves the env
file alone.

## Tests

```bash
.venv/bin/pytest
```

The integration tests start the real SSH server and connect with an asyncssh
client against a scripted fake LLM, so they need no API key.

## Layout

```
honeypot/
  __main__.py        entry point, signal handling
  config.py          .env loading and validation
  server.py          asyncssh server, host key, auth
  session.py         shell loop, state, password prompts
  prompts.py         system prompt (you write it) and message formatting
  recorder.py        JSONL session logs
  llm/
    base.py          provider interface, response schema and parsing
    claude.py        Anthropic (structured JSON output)
    openai_compat.py OpenAI and OpenRouter
deploy/              systemd unit and install script
tests/
```
