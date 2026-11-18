"""RPC and Etherscan clients against a fake urlopen."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from release_engine.errors import RpcError, VerificationError
from release_engine.explorer import Etherscan
from release_engine.redact import Redactor
from release_engine.rpc import RpcClient

URL = "https://rpc.example.com/v2/PROVIDERKEY_0123456789abcdef"


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_returning(*payloads):
    queue = list(payloads)
    seen = []

    def opener(request, timeout):
        seen.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return Response(json.dumps(item).encode())

    opener.seen = seen
    return opener


def test_rpc_typed_helpers():
    opener = opener_returning({"result": "0xaa36a7"}, {"result": "0x3b9aca00"})
    rpc = RpcClient(URL, Redactor(github_actions=False), opener=opener, sleep=lambda s: None)
    assert rpc.chain_id() == 11155111
    assert rpc.gas_price() == 10**9
    body = json.loads(opener.seen[0].data)
    assert body["method"] == "eth_chainId"


def test_rpc_retries_transient_errors():
    opener = opener_returning(urllib.error.URLError("reset"), {"result": "0x1"})
    rpc = RpcClient(URL, Redactor(github_actions=False), opener=opener, sleep=lambda s: None)
    assert rpc.chain_id() == 1


def test_rpc_error_is_redacted():
    r = Redactor(github_actions=False)
    r.register(URL)
    opener = opener_returning({"error": {"message": f"bad request to {URL}"}})
    rpc = RpcClient(URL, r, opener=opener, sleep=lambda s: None)
    with pytest.raises(RpcError) as exc:
        rpc.chain_id()
    assert "PROVIDERKEY" not in str(exc.value)


def test_rpc_gives_up_after_retries():
    opener = opener_returning(*[urllib.error.URLError("down")] * 3)
    rpc = RpcClient(URL, Redactor(github_actions=False), opener=opener, sleep=lambda s: None)
    with pytest.raises(RpcError, match="unreachable after 3 attempts"):
        rpc.block_number()


def test_rpc_rejects_non_http_scheme():
    with pytest.raises(RpcError):
        RpcClient("file:///etc/passwd", Redactor(github_actions=False))


def test_etherscan_v2_verified_and_unverified():
    opener = opener_returning(
        {"status": "1", "message": "OK", "result": [{"SourceCode": "contract X {}"}]},
        {"status": "1", "message": "OK", "result": [{"SourceCode": ""}]},
    )
    es = Etherscan(
        "APIKEY_0123456789", Redactor(github_actions=False), opener=opener, sleep=lambda s: None
    )
    assert es.is_verified(42161, "0x" + "1" * 40) is True
    assert es.is_verified(10, "0x" + "1" * 40) is False
    assert "chainid=42161" in opener.seen[0].full_url
    assert opener.seen[0].full_url.startswith("https://api.etherscan.io/v2/api?")


def test_etherscan_error_does_not_leak_key():
    r = Redactor(github_actions=False)
    opener = opener_returning(
        {"status": "0", "message": "NOTOK", "result": "Invalid API Key APIKEY_0123456789"}
    )
    es = Etherscan("APIKEY_0123456789", r, opener=opener, sleep=lambda s: None)
    with pytest.raises(VerificationError) as exc:
        es.is_verified(1, "0x" + "1" * 40)
    assert "APIKEY_0123456789" not in str(exc.value)


def test_etherscan_backs_off_on_rate_limit():
    opener = opener_returning(
        {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"},
        {"status": "1", "message": "OK", "result": [{"SourceCode": "x"}]},
    )
    es = Etherscan(
        "APIKEY_0123456789", Redactor(github_actions=False), opener=opener, sleep=lambda s: None
    )
    assert es.is_verified(1, "0x" + "1" * 40) is True
