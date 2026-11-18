"""Redaction, secret stores, signers, bytecode integrity, guardrails, child-process env."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import ClassVar

import pytest

from release_engine import guardrails
from release_engine.bytecode import mask_immutables, runtime_code_matches
from release_engine.config import SignerConfig
from release_engine.errors import SecretError
from release_engine.foundry import Foundry
from release_engine.logger import ReleaseLogger
from release_engine.redact import Redactor
from release_engine.secret_store import AwsSecretsManagerStore, EnvSecretStore
from release_engine.signers import AnvilSigner, KmsSigner, SecretsManagerSigner, build_signer

# ------------------------------------------------------------------ redaction


def test_redactor_masks_full_value_and_url_key_fragment():
    r = Redactor(github_actions=False)
    url = "https://eth-sepolia.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUv"  # gitleaks:allow (fake key)
    r.register(url)
    assert r(f"error calling {url}") == "error calling ***"
    # The provider key alone (e.g. echoed in an error body) is masked too.
    assert r("invalid key AbCdEfGhIjKlMnOpQrStUv") == "invalid key ***"


def test_redactor_emits_github_add_mask_once():
    out = io.StringIO()
    r = Redactor(github_actions=True, stdout=out)
    r.register("0x" + "ab" * 32)
    r.register("0x" + "ab" * 32)
    assert out.getvalue().count("::add-mask::") == 1


def test_redactor_ignores_short_values():
    r = Redactor(github_actions=False)
    r.register("abc")
    assert r("abc") == "abc"


def test_logger_redacts_both_sinks(tmp_path):
    r = Redactor(github_actions=False)
    r.register("topsecretvalue")
    stream = io.StringIO()
    log = ReleaseLogger(r, stream=stream, github_actions=False)
    log.info("leaking topsecretvalue", detail="also topsecretvalue")
    log.attach_file(tmp_path / "log.jsonl")
    assert "topsecretvalue" not in stream.getvalue()
    record = json.loads((tmp_path / "log.jsonl").read_text())
    assert record["msg"] == "leaking ***" and record["detail"] == "also ***"


# ------------------------------------------------------------------ secret stores


class FakeSecretsManager:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def get_secret_value(self, SecretId):
        self.calls += 1
        if isinstance(self.payload, Exception):
            raise self.payload
        return {"SecretString": self.payload}


def test_aws_store_fetches_once_and_masks_every_field():
    r = Redactor(github_actions=False)
    client = FakeSecretsManager(
        json.dumps({"RPC": "https://x.io/v2/keykeykeykeykeykey", "OTHER": "zzzzzzzzzz"})
    )
    store = AwsSecretsManagerStore(r, "web3-release/testnet/config", client_factory=lambda: client)
    assert store.resolve("secret:RPC").startswith("https://")
    assert store.resolve("literal") == "literal"
    store.get("RPC")
    assert client.calls == 1
    assert r("OTHER=zzzzzzzzzz") == "OTHER=***"  # masked even though never requested


def test_aws_store_errors_do_not_leak_details():
    class Boom(Exception):
        response: ClassVar[dict] = {"Error": {"Code": "AccessDeniedException"}}

    store = AwsSecretsManagerStore(
        Redactor(github_actions=False), "id", client_factory=lambda: FakeSecretsManager(Boom())
    )
    with pytest.raises(SecretError, match="AccessDeniedException"):
        store.get("RPC")


def test_aws_store_rejects_non_json():
    store = AwsSecretsManagerStore(
        Redactor(github_actions=False), "id", client_factory=lambda: FakeSecretsManager("not json")
    )
    with pytest.raises(SecretError, match="JSON object"):
        store.get("RPC")


def test_env_store_missing_secret():
    with pytest.raises(SecretError, match="not found in environment"):
        EnvSecretStore(Redactor(github_actions=False), {}).get("MISSING")


# ------------------------------------------------------------------ signers


def test_secretsmanager_signer_normalises_hex_key():
    r = Redactor(github_actions=False)
    key = "ab" * 32
    signer = SecretsManagerSigner(EnvSecretStore(r, {"DEPLOYER_PRIVATE_KEY": key}))
    # vm.envUint would read a bare hex string as *decimal* - must be 0x-prefixed.
    assert signer.env() == {"DEPLOYER_PRIVATE_KEY": "0x" + key}
    assert signer.wallet_args() == []
    assert key not in json.dumps(signer.describe())
    assert r(key) == "***"


def test_secretsmanager_signer_rejects_garbage():
    signer = SecretsManagerSigner(
        EnvSecretStore(Redactor(github_actions=False), {"DEPLOYER_PRIVATE_KEY": "hunter2hunter2"})
    )
    with pytest.raises(SecretError, match="not a 32-byte hex private key"):
        signer.env()


def test_kms_signer_resolves_address_through_cast_once():
    calls = []

    class F:
        def wallet_address(self, args, env=None):
            calls.append((args, env))
            return "0x" + "12" * 20

    signer = KmsSigner("alias/deployer")
    assert signer.resolve_address(F()) == "0x" + "12" * 20
    signer.resolve_address(F())
    assert calls == [(["--aws"], {"AWS_KMS_KEY_ID": "alias/deployer"})]
    assert signer.wallet_args() == ["--aws", "--sender", "0x" + "12" * 20]
    assert KmsSigner.hardware_backed


def test_build_signer_types():
    store = EnvSecretStore(Redactor(github_actions=False), {})
    assert isinstance(
        build_signer(SignerConfig("anvil", {"address": "0x" + "1" * 40}), store), AnvilSigner
    )
    assert build_signer(SignerConfig("ledger", {}), store).hd_path == "m/44'/60'/0'/0/0"


# ------------------------------------------------------------------ child process env


def test_child_env_strips_inherited_secrets(tmp_path: Path):
    r = Redactor(github_actions=False)
    log = ReleaseLogger(r, stream=io.StringIO(), github_actions=False)
    inherited = {
        "PATH": "/bin",
        "DEPLOYER_PRIVATE_KEY": "0xdead",
        "ETHERSCAN_API_KEY": "k",
        "RELEASE_RPC_URL": "u",
    }
    foundry = Foundry(tmp_path, r, log, base_env=inherited)
    env = foundry.child_env({"AWS_KMS_KEY_ID": "alias/x"})
    assert env["PATH"] == "/bin" and env["AWS_KMS_KEY_ID"] == "alias/x"
    assert not {"DEPLOYER_PRIVATE_KEY", "ETHERSCAN_API_KEY", "RELEASE_RPC_URL"} & env.keys()


# ------------------------------------------------------------------ bytecode


def test_immutables_are_masked_before_comparison():
    refs = {"7": [{"start": 2, "length": 4}]}
    compiled = {
        "deployedBytecode": {"object": "0x6080" + "00" * 4 + "ff", "immutableReferences": refs}
    }
    onchain = "0x6080" + "deadbeef" + "ff"
    assert runtime_code_matches(onchain, compiled) == (
        True,
        "runtime bytecode matches compiled artifact",
    )
    assert mask_immutables(bytes.fromhex("6080deadbeefff"), refs) == bytes.fromhex("608000000000ff")


def test_tampered_bytecode_is_detected():
    compiled = {"deployedBytecode": {"object": "0x60806040ff", "immutableReferences": {}}}
    ok, reason = runtime_code_matches("0x60806041ff", compiled)
    assert not ok and "differs" in reason
    assert runtime_code_matches("0x", compiled)[1] == "no code at address"


# ------------------------------------------------------------------ guardrails


def _plan(**overrides):
    plan = {
        "production": False,
        "release": {"version": "1.0.0"},
        "signer": {"type": "kms"},
        "owner": "0x" + "1" * 40,
        "expected_deployer": "0x" + "2" * 40,
        "verify_explorer": True,
        "require_clean_git": False,
        "require_tag": False,
        "git": {"commit": "abc", "dirty": False, "tag": None},
        "chains": [{"name": "ethereum", "chain_id": 1, "rpc_source": "secret"}],
    }
    plan.update(overrides)
    return plan


def test_guardrails_accept_compliant_production_plan():
    plan = _plan(
        production=True, require_tag=True, git={"commit": "a", "dirty": False, "tag": "v1.0.0"}
    )
    assert guardrails.evaluate(plan) == []


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"signer": {"type": "anvil"}}, "anvil dev signer may only target local chains"),
        ({"production": True, "signer": {"type": "secretsmanager"}}, "non-exportable key"),
        ({"production": True, "owner": "0x" + "2" * 40}, "separation of duties"),
        ({"production": True, "expected_deployer": None}, "signer pinning"),
        ({"production": True, "verify_explorer": False}, "explorer source verification"),
        (
            {"production": True, "chains": [{"name": "e", "chain_id": 1, "rpc_source": "literal"}]},
            "secret store",
        ),
        (
            {
                "production": True,
                "chains": [{"name": "l", "chain_id": 31337, "rpc_source": "secret"}],
            },
            "local chains",
        ),
        (
            {"require_clean_git": True, "git": {"commit": "a", "dirty": True, "tag": None}},
            "working tree must be clean",
        ),
        (
            {"require_tag": True, "git": {"commit": "a", "dirty": False, "tag": "v0.9.0"}},
            "must be tagged v1.0.0",
        ),
    ],
)
def test_guardrails_refuse(overrides, fragment):
    violations = guardrails.evaluate(_plan(**overrides))
    assert any(fragment in v for v in violations), violations
