"""End-to-end tests: a real SSH client against the server with a fake LLM."""

from __future__ import annotations

import asyncio
import json

import asyncssh
import pytest

from honeypot.server import HoneypotServer, start_server

from .conftest import FakeProvider, reply


async def start(config, provider):
    HoneypotServer.active = 0
    server = await start_server(config, provider)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def read_until(process, marker, timeout=5):
    buf = ""
    while marker not in buf:
        chunk = await asyncio.wait_for(process.stdout.read(1024), timeout)
        if not chunk:
            break
        buf += chunk
    return buf


def records(config):
    files = list(config.log_dir.glob("*.jsonl"))
    assert len(files) == 1
    return [json.loads(line) for line in files[0].read_text().splitlines()]


async def connect(port, username="admin", password="whatever"):
    return await asyncssh.connect(
        "127.0.0.1", port, username=username, password=password,
        known_hosts=None, preferred_auth="password",
    )


async def test_banner_command_and_secrets_never_sent(config):
    provider = FakeProvider([reply(output="uid=1000(admin) gid=1000(admin)\n")])
    server, port = await start(config, provider)
    try:
        async with await connect(port) as conn:
            proc = await conn.create_process(term_type="xterm")
            out = await read_until(proc, "admin@testhost:~$ ")
            assert "HONEYPOT" in out and "RECORDED" in out
            proc.stdin.write("id\n")
            out = await read_until(proc, "admin@testhost:~$ ")
            assert "uid=1000(admin)" in out
            proc.stdin.write("exit\n")
            await proc.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

    system, messages = provider.requests[0]
    assert "COMMAND: id" in messages[-1]["content"]
    assert config.root_password not in system + json.dumps(provider.requests)
    events = [r["event"] for r in records(config)]
    assert events[:2] == ["connect", "auth"]
    assert "command" in events and "response" in events and events[-1] == "disconnect"


async def test_wrong_username_rejected(config):
    server, port = await start(config, FakeProvider())
    try:
        with pytest.raises(asyncssh.PermissionDenied):
            await connect(port, username="root")
    finally:
        server.close()
        await server.wait_closed()


async def test_admin_password_enforced_when_set(with_admin_password):
    server, port = await start(with_admin_password, FakeProvider())
    try:
        with pytest.raises(asyncssh.PermissionDenied):
            await connect(port, password="wrong")
        async with await connect(port, password="adm1n-secret"):
            pass
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("password, ok", [("r00t-secret", True), ("guess", False)])
async def test_su_checks_root_password_on_server(config, password, ok):
    provider = FakeProvider([
        reply(action="password_prompt", target="root", prompt="Password: "),
        # The fake model claims root either way; the server must not allow it on failure.
        reply(output="" if ok else "su: Authentication failure\n", user="root", cwd="/root"),
    ])
    server, port = await start(config, provider)
    try:
        async with await connect(port) as conn:
            proc = await conn.create_process(term_type="xterm")
            await read_until(proc, "$ ")
            proc.stdin.write("su -\n")
            await read_until(proc, "Password: ")
            proc.stdin.write(password + "\n")
            out = await read_until(proc, "# " if ok else "$ ")
            assert password not in out  # echo is off
            if ok:
                assert "root@testhost:~# " in out
                proc.stdin.write("exit\n")
                out = await read_until(proc, "$ ")
                assert "admin@testhost:~$ " in out
            proc.stdin.write("exit\n")
            await proc.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

    auth_msg = provider.requests[1][1][-1]["content"]
    assert ("SUCCEEDED" if ok else "FAILED") in auth_msg
    assert password not in json.dumps(provider.requests)
    recs = records(config)
    pw = [r for r in recs if r["event"] == "password_prompt"]
    assert pw == [pw[0]] and pw[0]["success"] is ok and "password" not in pw[0]
    assert any(r["event"] == "user_change" and r["user"] == "root" for r in recs) is ok


@pytest.mark.parametrize("second, expected", [
    (reply(output="file.txt\n"), "file.txt"),
    ('{"output": "still broken', "ls: command not found"),
])
async def test_malformed_reply_is_retried_and_never_shown(config, second, expected):
    provider = FakeProvider(['{"output": {"output": "", "user": "admin"', second])
    server, port = await start(config, provider)
    try:
        async with await connect(port) as conn:
            result = await conn.run("ls", check=False)
    finally:
        server.close()
        await server.wait_closed()
    assert expected in result.stdout
    assert "{" not in result.stdout
    assert len(provider.requests) == 2
    # The failed attempt must not leak into the conversation history.
    assert provider.requests[0][1] == provider.requests[1][1]


async def test_llm_failure_falls_back(config):
    from honeypot.llm import LLMError

    server, port = await start(config, FakeProvider([LLMError("boom")]))
    try:
        async with await connect(port) as conn:
            result = await conn.run("whoami", check=False)
            assert "whoami: command not found" in result.stdout
            assert "HONEYPOT" in result.stderr
    finally:
        server.close()
        await server.wait_closed()
    assert any(r["event"] == "error" for r in records(config))


async def shell(port, inputs, end_marker="$ ", password="whatever"):
    """Run an interactive session, sending each input after the matching marker."""
    out = ""
    async with await connect(port, password=password) as conn:
        proc = await conn.create_process(term_type="xterm")
        out += await read_until(proc, end_marker)
        for text, marker in inputs:
            proc.stdin.write(text + "\n")
            out += await read_until(proc, marker)
        proc.stdin.write("exit\n")
        await proc.wait_closed()
    return out


async def test_plain_sudo_is_denied_locally(config):
    provider = FakeProvider()
    server, port = await start(config, provider)
    try:
        out = await shell(port, [("sudo -i", "password for admin: "), ("anything", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "admin is not in the sudoers file.  This incident will be reported." in out
    assert "root@" not in out
    assert provider.requests == []
    events = [r["event"] for r in records(config)]
    assert "sudo_denied" in events and "user_change" not in events


async def test_sudo_wrong_password_three_times(with_admin_password):
    server, port = await start(with_admin_password, FakeProvider())
    try:
        out = await shell(port, [("sudo su", ": "), ("x", ": "), ("y", ": "), ("z", "$ ")],
                        password="adm1n-secret")
    finally:
        server.close()
        await server.wait_closed()
    assert out.count("Sorry, try again.") == 2
    assert "sudo: 3 incorrect password attempts" in out


async def test_sudo_list_message(config):
    server, port = await start(config, FakeProvider())
    try:
        out = await shell(port, [("sudo -l", ": "), ("pw", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "Sorry, user admin may not run sudo on testhost." in out


async def test_sudo_in_compound_command_cannot_switch_user(config):
    # The model wrongly grants root; the server must refuse the switch.
    provider = FakeProvider([reply(user="root", cwd="/root")])
    server, port = await start(config, provider)
    try:
        out = await shell(port, [("cd /tmp && sudo -i", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "root@" not in out
    assert len(provider.requests) == 1
    assert "sudo_denied" in [r["event"] for r in records(config)]


async def test_sudo_help_goes_to_model(config):
    provider = FakeProvider([reply(output="usage: sudo -h | -K | -k | -V\n")])
    server, port = await start(config, provider)
    try:
        out = await shell(port, [("sudo -h", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "usage: sudo" in out and len(provider.requests) == 1


async def test_missing_trailing_newline_is_added(config):
    provider = FakeProvider([reply(output="admin")])
    server, port = await start(config, provider)
    try:
        out = await shell(port, [("whoami", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "admin\r\nadmin@testhost:~$ " in out


async def test_interactive_program_keeps_reading_input(config):
    provider = FakeProvider([
        reply(output="Python 3.11.2\n", program_prompt=">>> "),
        reply(output="2\n", program_prompt=">>> "),
        reply(output="", program_prompt=""),
    ])
    server, port = await start(config, provider)
    try:
        out = await shell(port, [("python3", ">>> "), ("1+1", ">>> "), ("exit()", "$ ")])
    finally:
        server.close()
        await server.wait_closed()
    assert "Python 3.11.2\r\n>>> " in out and "2\r\n>>> " in out
    assert "PROGRAM: python3\nINPUT: 1+1" in provider.requests[1][1][-1]["content"]
    events = [r["event"] for r in records(config)]
    assert "program_start" in events and "program_exit" in events


async def test_ctrl_d_quits_interactive_program(config):
    provider = FakeProvider([reply(output="Python 3.11.2\n", program_prompt=">>> ")])
    server, port = await start(config, provider)
    try:
        async with await connect(port) as conn:
            proc = await conn.create_process(term_type="xterm")
            await read_until(proc, "$ ")
            proc.stdin.write("python3\n")
            await read_until(proc, ">>> ")
            proc.stdin.write("\x04")
            out = await read_until(proc, "$ ")
            assert "admin@testhost:~$ " in out
            proc.stdin.write("exit\n")
            await proc.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
    assert len(provider.requests) == 1
