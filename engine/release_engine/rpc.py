"""Minimal JSON-RPC client (stdlib only) used for independent pre/post-flight checks.

The engine deliberately does not trust forge's view of the chain: it re-reads chain id,
gas price, balances, receipts and deployed code itself.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from release_engine.errors import RpcError
from release_engine.redact import Redactor

_TRANSIENT = (urllib.error.URLError, TimeoutError, ConnectionError)


class RpcClient:
    def __init__(
        self,
        url: str,
        redactor: Redactor,
        timeout: float = 20.0,
        retries: int = 3,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not url.startswith(("http://", "https://")):
            raise RpcError("RPC URL must use http(s)")
        self._url = url
        self._redact = redactor
        self._timeout = timeout
        self._retries = max(1, retries)
        self._opener = opener
        self._sleep = sleep
        self._id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}
        ).encode()
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            self._url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "release-engine/0.1"},
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self._retries):
            try:
                with self._opener(request, timeout=self._timeout) as response:
                    payload = json.loads(response.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code < 500 and exc.code != 429:
                    raise RpcError(f"{method}: HTTP {exc.code}") from None
                last_error = exc
            except _TRANSIENT as exc:
                last_error = exc
            if attempt < self._retries - 1:
                self._sleep(min(2**attempt, 8))
        else:
            reason = self._redact(str(getattr(last_error, "reason", last_error)))
            raise RpcError(f"{method}: RPC unreachable after {self._retries} attempts ({reason})")

        if payload.get("error"):
            message = self._redact(str(payload["error"].get("message", payload["error"])))
            raise RpcError(f"{method}: {message}")
        return payload.get("result")

    # ------------------------------------------------------------------ typed helpers

    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def gas_price(self) -> int:
        return int(self.call("eth_gasPrice"), 16)

    def balance(self, address: str) -> int:
        return int(self.call("eth_getBalance", [address, "latest"]), 16)

    def code(self, address: str) -> str:
        return self.call("eth_getCode", [address, "latest"]) or "0x"

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def eth_call(self, to: str, data: str) -> str:
        return self.call("eth_call", [{"to": to, "data": data}, "latest"])
