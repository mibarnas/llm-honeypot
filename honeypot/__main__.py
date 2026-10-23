"""Entry point: ``python -m honeypot`` or the ``llm-honeypot`` script."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from . import __version__, prompts
from .config import ConfigError, load_config
from .llm import create_provider
from .server import start_server

log = logging.getLogger("honeypot")


async def serve(env_file: str | None) -> int:
    try:
        config = load_config(env_file)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.getLogger().setLevel(config.log_level)

    if not prompts.SYSTEM_PROMPT.strip():
        print("configuration error: honeypot/prompts.py SYSTEM_PROMPT is empty", file=sys.stderr)
        return 2

    config.log_dir.mkdir(parents=True, exist_ok=True)
    provider = create_provider(
        config.llm_provider, config.llm_api_key, config.llm_model, config.llm_timeout
    )
    server = await start_server(config, provider)
    log.info(
        "listening on %s:%d (provider=%s, model=%s)",
        config.listen_host, config.listen_port, config.llm_provider, config.llm_model,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    await stop.wait()
    log.info("shutting down")
    server.close()
    await server.wait_closed()
    await provider.aclose()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="llm-honeypot", description="LLM-backed SSH honeypot")
    parser.add_argument("--env-file", help="path to the .env file (default: $HONEYPOT_ENV_FILE or ./.env)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    sys.exit(asyncio.run(serve(args.env_file)))


if __name__ == "__main__":
    main()
