"""Structured, redacted deployment logging.

Every event goes to two sinks:
  * a human-readable line on stderr (plus a GitHub annotation for warnings/errors in CI)
  * a JSON line in ``deployments/<profile>/<version>/logs/<run-id>.jsonl`` - the
    machine-readable audit trail that is uploaded to the immutable S3 ledger.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from release_engine.redact import Redactor

_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ReleaseLogger:
    def __init__(
        self,
        redactor: Redactor,
        stream: TextIO | None = None,
        verbose: bool = False,
        github_actions: bool | None = None,
    ):
        self._redact = redactor
        self._stream = stream or sys.stderr
        self._min_level = _LEVELS["debug" if verbose else "info"]
        self._gha = (
            os.environ.get("GITHUB_ACTIONS") == "true" if github_actions is None else github_actions
        )
        self._jsonl: Path | None = None
        self._buffer: list[str] = []

    def attach_file(self, path: Path) -> None:
        """Start persisting JSON lines; flushes everything logged so far."""
        path.parent.mkdir(parents=True, exist_ok=True)
        self._jsonl = path
        with path.open("a", encoding="utf-8") as fh:
            for line in self._buffer:
                fh.write(line + "\n")
        self._buffer.clear()

    def event(self, level: str, msg: str, **fields: Any) -> None:
        record = {"ts": utcnow(), "level": level, "msg": msg, **fields}
        line = self._redact(json.dumps(record, default=str, sort_keys=False))
        if self._jsonl is not None:
            with self._jsonl.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            self._buffer.append(line)

        if _LEVELS[level] < self._min_level:
            return
        chain = fields.get("chain")
        prefix = f"[{chain}] " if chain else ""
        human = self._redact(f"{level.upper():<7} {prefix}{msg}")
        self._stream.write(human + "\n")
        if self._gha and level in ("warning", "error"):
            self._stream.write(f"::{level}::{self._redact(prefix + msg)}\n")
        self._stream.flush()

    def debug(self, msg: str, **fields: Any) -> None:
        self.event("debug", msg, **fields)

    def info(self, msg: str, **fields: Any) -> None:
        self.event("info", msg, **fields)

    def warning(self, msg: str, **fields: Any) -> None:
        self.event("warning", msg, **fields)

    def error(self, msg: str, **fields: Any) -> None:
        self.event("error", msg, **fields)
