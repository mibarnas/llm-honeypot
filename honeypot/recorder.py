"""Per-session JSONL recording."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-." else "_" for c in value)


class SessionRecorder:
    """Appends one JSON object per event to a session file, flushed immediately."""

    def __init__(self, log_dir: Path, session_id: str, peer_ip: str):
        log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.session_id = session_id
        self.path = log_dir / f"{stamp}_{_safe(peer_ip)}_{session_id}.jsonl"
        self._fh = open(self.path, "a", encoding="utf-8")

    def event(self, kind: str, **fields: Any) -> None:
        if self._fh.closed:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "session": self.session_id,
            "event": kind,
            **fields,
        }
        try:
            self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fh.flush()
        except OSError:
            log.exception("failed to write session record")

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()
