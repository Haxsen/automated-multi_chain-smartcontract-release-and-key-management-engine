"""Etherscan API V2: one key, one endpoint, every supported chain (incl. Arbiscan/OP scans)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from release_engine.errors import VerificationError
from release_engine.redact import Redactor

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"


class Etherscan:
    def __init__(
        self,
        api_key: str,
        redactor: Redactor,
        base_url: str = ETHERSCAN_V2,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 20.0,
    ):
        self._key = api_key
        self._redact = redactor
        self._base = base_url
        self._opener = opener
        self._sleep = sleep
        self._timeout = timeout
        redactor.register(api_key)

    def _get(self, params: dict[str, str]) -> dict[str, Any]:
        query = urllib.parse.urlencode({**params, "apikey": self._key})
        request = urllib.request.Request(  # noqa: S310 - fixed https endpoint
            f"{self._base}?{query}", headers={"User-Agent": "release-engine/0.1"}
        )
        for attempt in range(4):
            try:
                with self._opener(request, timeout=self._timeout) as response:
                    payload = json.loads(response.read())
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == 3:
                    raise VerificationError(
                        f"explorer API unreachable: {self._redact(str(exc))}"
                    ) from None
                self._sleep(2**attempt)
                continue
            result = payload.get("result")
            if isinstance(result, str) and "rate limit" in result.lower() and attempt < 3:
                self._sleep(2**attempt)
                continue
            return payload
        raise VerificationError("explorer API rate limited")

    def is_verified(self, chain_id: int, address: str) -> bool:
        payload = self._get(
            {
                "chainid": str(chain_id),
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
            }
        )
        result = payload.get("result")
        if payload.get("status") != "1" or not isinstance(result, list) or not result:
            detail = result if isinstance(result, str) else payload.get("message", "unknown error")
            raise VerificationError(f"explorer lookup failed: {self._redact(str(detail))}")
        return bool(result[0].get("SourceCode"))
