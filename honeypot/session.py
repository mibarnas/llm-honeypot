"""Per-connection fake shell: reads commands and answers them via the LLM."""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
import shlex
from dataclasses import dataclass, field

import asyncssh

from . import prompts
from .config import Config
from .llm import LLMError, LLMProvider, LLMResponse, ReplyFormatError, parse_response
from .recorder import SessionRecorder

log = logging.getLogger(__name__)

BANNER = (
    "********************************************************************\n"
    "*  NOTICE: This system is an LLM-powered HONEYPOT.                 *\n"
    "*  Nothing here is real. All commands and keystrokes are RECORDED. *\n"
    "********************************************************************\n"
    "\n"
)

MAX_LINE = 2048
MAX_PASSWORD_ROUNDS = 3
FORMAT_RETRIES = 1
SUDO_ATTEMPTS = 3

# admin is not in sudoers. Plain `sudo ...` commands are answered locally;
# sudo inside compound commands goes to the model but can never switch users.
SUDO_WORD_RE = re.compile(r"(?:^|[\s;&|(`])sudo(?:\s|$)")
SHELL_OPERATOR_RE = re.compile(r"[;&|<>`$()]")
# sudo options that print information without asking for a password.
SUDO_INFO_ARGS = {"-h", "--help", "-V", "--version", "-k", "-K"}


def plain_sudo_args(command: str) -> list[str] | None:
    """Return sudo's arguments if ``command`` is a simple sudo invocation needing a password."""
    if SHELL_OPERATOR_RE.search(command):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        words = command.split()
    if not words or words[0] != "sudo":
        return None
    args = words[1:]
    if not args or set(args) <= SUDO_INFO_ARGS:
        return None
    return args


@dataclass
class ShellState:
    user: str
    cwd: str
    hostname: str
    # Shells entered via su/sudo; `exit` returns to the previous one.
    stack: list[tuple[str, str]] = field(default_factory=list)
    # Interactive program (python3, mysql, ...) currently reading input, and its prompt.
    program: str | None = None
    program_prompt: str = ""

    @property
    def home(self) -> str:
        return "/root" if self.user == "root" else f"/home/{self.user}"

    def prompt(self) -> str:
        if self.program:
            return self.program_prompt
        cwd = self.cwd
        if cwd == self.home or cwd.startswith(self.home + "/"):
            cwd = "~" + cwd[len(self.home):]
        sigil = "#" if self.user == "root" else "$"
        return f"{self.user}@{self.hostname}:{cwd}{sigil} "


def check_password(config: Config, target: str, attempt: str) -> bool:
    if target == "root":
        expected = config.root_password
    elif config.admin_password is None:
        return True
    else:
        expected = config.admin_password
    return hmac.compare_digest(attempt.encode(), expected.encode())


class Session:
    def __init__(
        self,
        process: asyncssh.SSHServerProcess,
        config: Config,
        provider: LLMProvider,
        recorder: SessionRecorder,
    ):
        self.process = process
        self.config = config
        self.provider = provider
        self.recorder = recorder
        self.state = ShellState(user="admin", cwd="/home/admin", hostname=config.hostname)
        self.history: list[dict] = []
        self.system_prompt = prompts.render_system_prompt(config.hostname)
        self.commands = 0
        self.interactive = process.get_terminal_type() is not None

    # -- I/O helpers -------------------------------------------------------

    def write(self, text: str) -> None:
        if text:
            self.process.stdout.write(text)

    def write_output(self, text: str) -> None:
        """Print model output, adding the trailing newline models tend to forget."""
        if text and not text.endswith("\n"):
            text += "\n"
        self.write(text)

    def _set_echo(self, echo: bool) -> None:
        if self.interactive:
            try:
                self.process.channel.set_echo(echo)
            except (AttributeError, AssertionError):
                pass

    async def read_line(self) -> str | None:
        """Read one input line. Returns None on EOF, "" after Ctrl-C."""
        while True:
            try:
                line = await asyncio.wait_for(
                    self.process.stdin.readline(), timeout=self.config.idle_timeout
                )
            except asyncssh.TerminalSizeChanged:
                continue
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                self.write("^C\n")
                try:
                    self.process.channel.clear_input()
                except (AttributeError, AssertionError):
                    pass
                return ""
            if not line:
                return None
            return line.rstrip("\r\n")[:MAX_LINE]

    async def read_password(self, prompt: str) -> str | None:
        self.write(prompt)
        self._set_echo(False)
        try:
            line = await self.read_line()
        finally:
            self._set_echo(True)
        return line

    # -- LLM ---------------------------------------------------------------

    def _trimmed_history(self) -> list[dict]:
        limit = self.config.history_turns * 2
        history = self.history[-limit:]
        while history and history[0]["role"] != "user":
            history = history[1:]
        return history

    async def ask(self, message: str) -> LLMResponse | None:
        messages = [*self._trimmed_history(), {"role": "user", "content": message}]
        for attempt in range(1 + FORMAT_RETRIES):
            try:
                completion = await asyncio.wait_for(
                    self.provider.complete(self.system_prompt, messages),
                    timeout=self.config.llm_timeout + 5,
                )
                response = parse_response(completion.text, self.state.user, self.state.cwd)
                break
            except ReplyFormatError as exc:
                log.warning("bad reply format (attempt %d): %s", attempt + 1, exc)
                self.recorder.event("error", source="llm", detail=str(exc), raw=completion.text)
            except (LLMError, asyncio.TimeoutError) as exc:
                log.warning("LLM request failed: %s", exc)
                self.recorder.event("error", source="llm", detail=str(exc) or type(exc).__name__)
                return None
            except Exception as exc:  # never let a provider bug kill the session
                log.exception("unexpected LLM failure")
                self.recorder.event("error", source="llm", detail=repr(exc))
                return None
        else:
            return None

        self.history.append({"role": "user", "content": message})
        self.history.append({"role": "assistant", "content": response.to_json()})
        self.recorder.event(
            "response",
            output=response.output,
            user=response.user,
            cwd=response.cwd,
            action=response.action,
            password_target=response.password_target,
            usage=completion.usage,
        )
        return response

    # -- command handling --------------------------------------------------

    def _change_user(self, user: str, cwd: str, command: str) -> None:
        if user != self.state.user:
            self.recorder.event("user_change", previous=self.state.user, user=user, command=command)
            self.state.stack.append((self.state.user, self.state.cwd))
            self.state.user = user
        self.state.cwd = cwd

    def _fallback_error(self, command: str) -> None:
        name = command.split()[0] if command.split() else command
        self.write(f"-bash: {name}: command not found\n")

    def _remember(self, command: str, output: str, message: str | None = None) -> None:
        """Add a locally answered command to the history so the model stays consistent."""
        if message is None:
            message = prompts.format_command(self.state.user, self.state.cwd, command)
        self.history.append({"role": "user", "content": message})
        self.history.append(
            {"role": "assistant",
             "content": LLMResponse(output=output, user=self.state.user, cwd=self.state.cwd).to_json()}
        )

    def _set_program(self, command: str, response: LLMResponse) -> None:
        prompt = response.program_prompt
        if prompt and self.interactive:
            if self.state.program is None:
                self.recorder.event("program_start", program=command, prompt=prompt)
                self.state.program = command
            self.state.program_prompt = prompt
        elif self.state.program is not None:
            self.recorder.event("program_exit", program=self.state.program)
            self.state.program = None
            self.state.program_prompt = ""

    async def deny_sudo(self, command: str, args: list[str]) -> None:
        """Answer a plain `sudo ...` like a real sudo for a user not in sudoers."""
        user = self.state.user
        for attempt in range(1, SUDO_ATTEMPTS + 1):
            password = await self.read_password(f"[sudo] password for {user}: ")
            if password is None:
                return
            ok = check_password(self.config, "admin", password)
            self.recorder.event("password_prompt", target="admin", success=ok, command=command)
            if ok:
                if "-l" in args or "--list" in args:
                    text = f"Sorry, user {user} may not run sudo on {self.state.hostname}.\n"
                else:
                    text = f"{user} is not in the sudoers file.  This incident will be reported.\n"
                break
            if attempt < SUDO_ATTEMPTS:
                self.write("Sorry, try again.\n")
        else:
            text = f"sudo: {SUDO_ATTEMPTS} incorrect password attempts\n"
        self.write(text)
        self.recorder.event("sudo_denied", command=command)
        self._remember(command, text)

    async def run_command(self, command: str) -> None:
        self.recorder.event("command", command=command, user=self.state.user, cwd=self.state.cwd)
        uses_sudo = self.state.user != "root" and SUDO_WORD_RE.search(command) is not None
        if uses_sudo:
            args = plain_sudo_args(command)
            if args is not None:
                await self.deny_sudo(command, args)
                return

        response = await self.ask(prompts.format_command(self.state.user, self.state.cwd, command))
        if response is None:
            self._fallback_error(command)
            return

        rounds = 0
        last_failed = False
        root_ok = False
        while True:
            self.write_output(response.output)
            if not response.wants_password or rounds >= MAX_PASSWORD_ROUNDS:
                if last_failed:
                    # A failed password never changes who the shell runs as.
                    response.user, response.cwd = self.state.user, self.state.cwd
                elif uses_sudo and not root_ok and response.user != self.state.user:
                    # sudo is never allowed to switch users; only su with the root password is.
                    self.recorder.event("sudo_denied", command=command)
                    response.user, response.cwd = self.state.user, self.state.cwd
                self._change_user(response.user, response.cwd, command)
                if not last_failed:
                    self._set_program(command, response)
                return

            rounds += 1
            target = response.password_target
            attempt = await self.read_password(response.prompt or "Password: ")
            if attempt is None:
                return
            ok = check_password(self.config, target, attempt)
            last_failed = not ok
            root_ok = root_ok or (ok and target == "root")
            self.recorder.event("password_prompt", target=target, success=ok, command=command)

            note = ""
            if ok and target == "admin" and uses_sudo:
                note = (f"However, {self.state.user} is not in the sudoers file: sudo must print "
                        f"`{self.state.user} is not in the sudoers file.  This incident will be "
                        f"reported.` and must not run anything.")
            response = await self.ask(
                prompts.format_auth_result(self.state.user, self.state.cwd, target, ok, command, note)
            )
            if response is None:
                if not ok:
                    self.write("su: Authentication failure\n" if target == "root" else "Sorry, try again.\n")
                return

    async def run_input(self, text: str) -> None:
        """Send a line typed inside an interactive program to the model."""
        program = self.state.program
        self.recorder.event("input", program=program, input=text, user=self.state.user,
                            cwd=self.state.cwd)
        response = await self.ask(prompts.format_input(self.state.user, self.state.cwd, program, text))
        if response is None:
            return
        # The program runs in a child process: it cannot change the shell's user or cwd,
        # and password prompts are only supported at the shell.
        self.write_output(response.output)
        self._set_program(program, response)

    def leave_program(self) -> None:
        """Ctrl-D inside an interactive program quits it, like it would for a real one."""
        program = self.state.program
        message = prompts.format_input(self.state.user, self.state.cwd, program, "<Ctrl-D>")
        self.write("\n")
        self.recorder.event("input", program=program, input="<Ctrl-D>", user=self.state.user,
                            cwd=self.state.cwd)
        self._set_program(program, LLMResponse(output="", user=self.state.user, cwd=self.state.cwd))
        self._remember(program, "\n", message)

    def handle_local(self, command: str) -> bool | None:
        """Handle builtins that must not reach the LLM.

        Returns True if handled, False if the session should end, None otherwise.
        """
        word = command.split()[0] if command.split() else ""
        if word in ("exit", "logout"):
            if self.state.stack:
                self.recorder.event("user_change", previous=self.state.user, command=command,
                                    user=self.state.stack[-1][0])
                self.state.user, self.state.cwd = self.state.stack.pop()
                self.write("logout\n" if word == "logout" else "exit\n")
                return True
            self.write("logout\n")
            return False
        if word == "clear" and self.interactive:
            self.write("\x1b[H\x1b[2J")
            return True
        return None

    # -- entry points ------------------------------------------------------

    async def run(self) -> None:
        try:
            if self.process.command is not None:
                await self._run_exec(self.process.command)
            else:
                await self._run_shell()
        finally:
            self.process.exit(0)

    async def _run_exec(self, command: str) -> None:
        self.process.stderr.write(BANNER)
        command = command[:MAX_LINE].strip()
        if not command:
            return
        try:
            await self.run_command(command)
        except asyncio.TimeoutError:
            self.recorder.event("idle_timeout")

    async def _run_shell(self) -> None:
        self.write(BANNER)
        try:
            await self._shell_loop()
        except asyncio.TimeoutError:
            self.write("\ntimed out waiting for input: auto-logout\n")
            self.recorder.event("idle_timeout")

    async def _shell_loop(self) -> None:
        while True:
            self.write(self.state.prompt())
            line = await self.read_line()
            if self.state.program:
                # Ctrl-D is a soft EOF: it quits the program, the connection stays open.
                if line is None:
                    self.leave_program()
                    continue
                # A blank line ends a Python block; elsewhere it only repeats the prompt.
                if not line.strip() and not self.state.program_prompt.startswith("..."):
                    continue
                self.commands += 1
                if self.commands > self.config.max_commands:
                    self.recorder.event("command_limit")
                    self.write("\nConnection closed by remote host.\n")
                    return
                await self.run_input(line)
                continue
            if line is None:
                self.write("logout\n")
                return
            command = line.strip()
            if not command:
                continue

            local = self.handle_local(command)
            if local is False:
                self.recorder.event("command", command=command, user=self.state.user, cwd=self.state.cwd)
                return
            if local:
                self.recorder.event("command", command=command, user=self.state.user, cwd=self.state.cwd)
                continue

            self.commands += 1
            if self.commands > self.config.max_commands:
                self.recorder.event("command_limit")
                self.write("Connection closed by remote host.\n")
                return
            await self.run_command(command)
