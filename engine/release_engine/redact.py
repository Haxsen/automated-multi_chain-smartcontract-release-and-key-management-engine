"""Secret redaction for every byte the engine prints, logs or persists.

Each secret resolved at runtime is registered here. Registration:
  * scrubs the value (and its sensitive URL fragments) from all subsequent output, and
  * on GitHub Actions emits ``::add-mask::`` so the runner also masks it in raw step logs
    (e.g. output of a child process we did not capture).
"""

from __future__ import annotations

import os
import sys
import threading
from typing import TextIO
from urllib.parse import parse_qsl, urlsplit

MASK = "***"
_MIN_SECRET_LEN = 6
_MIN_FRAGMENT_LEN = 16


def _url_fragments(value: str) -> list[str]:
    """Provider keys usually live in the URL path or query (alchemy.com/v2/<KEY>)."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return []
    if parts.scheme not in ("http", "https", "ws", "wss") or not parts.netloc:
        return []
    fragments = [seg for seg in parts.path.split("/") if len(seg) >= _MIN_FRAGMENT_LEN]
    fragments += [v for _, v in parse_qsl(parts.query) if len(v) >= _MIN_FRAGMENT_LEN]
    if parts.password:
        fragments.append(parts.password)
    return fragments


class Redactor:
    def __init__(self, github_actions: bool | None = None, stdout: TextIO | None = None):
        if github_actions is None:
            github_actions = os.environ.get("GITHUB_ACTIONS") == "true"
        self._gha = github_actions
        self._stdout = stdout or sys.stdout
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def register(self, value: str | None) -> None:
        if not value or len(value) < _MIN_SECRET_LEN:
            return
        candidates = [value, *_url_fragments(value)]
        with self._lock:
            for candidate in candidates:
                if candidate in self._secrets:
                    continue
                self._secrets.add(candidate)
                if self._gha:
                    self._stdout.write(f"::add-mask::{candidate}\n")
                    self._stdout.flush()

    def redact(self, text: str) -> str:
        if not text:
            return text
        with self._lock:
            secrets = sorted(self._secrets, key=len, reverse=True)
        for secret in secrets:
            text = text.replace(secret, MASK)
        return text

    __call__ = redact
