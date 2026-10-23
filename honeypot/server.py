"""SSH server: host key, authentication and session dispatch."""

from __future__ import annotations

import hmac
import logging
import os
import uuid

import asyncssh

from .config import Config
from .llm import LLMProvider
from .recorder import SessionRecorder
from .session import Session

log = logging.getLogger(__name__)

SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
LOGIN_USER = "admin"


def load_host_key(config: Config) -> asyncssh.SSHKey:
    path = config.host_key_path
    if path.exists():
        return asyncssh.read_private_key(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.export_private_key())
    log.info("generated new host key at %s", path)
    return key


class HoneypotServer(asyncssh.SSHServer):
    """One instance per incoming connection."""

    active = 0

    def __init__(self, config: Config):
        self.config = config
        self.conn: asyncssh.SSHServerConnection | None = None
        self.recorder: SessionRecorder | None = None
        self.peer_ip = "unknown"
        self.counted = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        self.peer_ip, peer_port = peer[0], peer[1]
        conn.set_extra_info(honeypot_server=self)

        if HoneypotServer.active >= self.config.max_sessions:
            log.warning("rejecting %s: session limit reached", self.peer_ip)
            conn.close()
            return
        HoneypotServer.active += 1
        self.counted = True

        self.recorder = SessionRecorder(self.config.log_dir, uuid.uuid4().hex[:12], self.peer_ip)
        self.recorder.event(
            "connect",
            peer_ip=self.peer_ip,
            peer_port=peer_port,
            client_version=conn.get_extra_info("client_version"),
        )
        log.info("connection from %s:%s (%s)", self.peer_ip, peer_port, self.recorder.session_id)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.counted:
            HoneypotServer.active -= 1
            self.counted = False
        if self.recorder:
            self.recorder.event("disconnect", reason=str(exc) if exc else "closed")
            self.recorder.close()
        log.info("connection from %s closed", self.peer_ip)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if username != LOGIN_USER:
            ok = False
        elif self.config.admin_password is None:
            ok = True
        else:
            ok = hmac.compare_digest(password.encode(), self.config.admin_password.encode())
        if self.recorder:
            self.recorder.event("auth", username=username, success=ok)
        return ok


async def start_server(config: Config, provider: LLMProvider) -> asyncssh.SSHAcceptor:
    host_key = load_host_key(config)

    async def handle_process(process: asyncssh.SSHServerProcess) -> None:
        server: HoneypotServer = process.get_extra_info("honeypot_server")
        session = Session(process, config, provider, server.recorder)
        server.recorder.event(
            "session_start",
            mode="exec" if process.command is not None else "shell",
            term=process.get_terminal_type(),
            command=process.command,
        )
        try:
            await session.run()
        except (asyncssh.Error, ConnectionError, BrokenPipeError):
            pass
        except Exception:
            log.exception("session crashed")
            server.recorder.event("error", source="session", detail="unhandled exception")
            process.exit(1)

    return await asyncssh.create_server(
        lambda: HoneypotServer(config),
        config.listen_host,
        config.listen_port,
        server_host_keys=[host_key],
        server_version=SERVER_VERSION,
        process_factory=handle_process,
        encoding="utf-8",
        line_editor=True,
        allow_scp=False,
        agent_forwarding=False,
        x11_forwarding=False,
        keepalive_interval=60,
        login_timeout=60,
    )
