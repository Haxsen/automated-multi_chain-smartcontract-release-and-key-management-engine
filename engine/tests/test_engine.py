"""Orchestrator behaviour: happy path, idempotency, and every refusal path."""

from __future__ import annotations

import dataclasses
import json

import pytest

from release_engine.engine import ReleaseOptions
from release_engine.errors import PolicyViolation, PreflightError

from .conftest import DEPLOYER, ETHERSCAN_KEY, OWNER, RPC_URL, VAULT, owner_word


def by_chain(manifest):
    return {d["chain"]: d for d in manifest["deployments"]}


def test_fresh_release_deploys_and_verifies_everywhere(harness):
    manifest, paths = harness.engine.release(ReleaseOptions())

    assert manifest["success"] is True
    assert manifest["deterministic_address"] == VAULT
    for d in manifest["deployments"]:
        assert d["status"] == "deployed"
        assert d["bytecode_verified"] and d["owner_verified"] and d["explorer_verified"]
        assert d["tx_hash"] and d["gas_used"] == 700_000
        assert d["explorer_url"].endswith(f"/address/{VAULT}#code")
    assert sorted(harness.foundry.verified) == [(421614, VAULT), (11155111, VAULT)]

    # Outputs: manifest + digest + summary + plan + JSONL log, and latest.json for audit.
    out = harness.workspace / "deployments" / "test" / "1.0.0"
    assert paths["manifest"] == out / "manifest.json"
    assert (out / "manifest.json.sha256").read_text().split()[0]
    assert "Release succeeded" in (out / "summary.md").read_text(encoding="utf-8")
    assert json.loads((out / "plan.json").read_text())["profile"] == "test"
    assert (harness.workspace / "deployments" / "test" / "latest.json").exists()
    assert list((out / "logs").glob("*.jsonl"))


def test_kms_signer_flags_and_env_reach_forge(harness):
    harness.engine.release(ReleaseOptions())
    scripts = [c for name, c in harness.foundry.calls if name == "script"]
    broadcast = next(c for c in scripts if c["broadcast"])
    assert broadcast["wallet_args"] == ["--aws", "--sender", DEPLOYER]
    assert broadcast["env"]["AWS_KMS_KEY_ID"] == "alias/test-deployer"
    assert broadcast["env"]["EXPECTED_DEPLOYER"] == DEPLOYER
    assert broadcast["env"]["RELEASE_OWNER"] == OWNER
    assert "DEPLOYER_PRIVATE_KEY" not in broadcast["env"]
    # The RPC URL is handed over separately (env), never as a CLI argument.
    assert RPC_URL not in " ".join(broadcast["wallet_args"])


def test_rerun_is_idempotent(harness):
    harness.engine.release(ReleaseOptions())
    harness.foundry.calls.clear()

    manifest, _ = harness.engine.release(ReleaseOptions())

    assert manifest["success"] is True
    assert {d["status"] for d in manifest["deployments"]} == {"already_deployed"}
    assert not any(c["broadcast"] for n, c in harness.foundry.calls if n == "script")


def test_wrong_chain_id_is_refused_before_signing(harness):
    harness.beta.chain_id_value = 1  # RPC for "beta" actually points at Ethereum mainnet

    manifest, _ = harness.engine.release(ReleaseOptions())

    beta = by_chain(manifest)["beta"]
    assert beta["status"] == "failed"
    assert "RPC reports chain id 1, expected 421614" in beta["error"]
    assert manifest["success"] is False
    assert by_chain(manifest)["alpha"]["status"] == "deployed"  # chains are isolated
    assert not any(c["chain"] == "beta" for n, c in harness.foundry.calls if n == "script")


def test_gas_ceiling(harness):
    harness.alpha.gas_price_value = 51 * 10**9

    manifest, _ = harness.engine.release(ReleaseOptions())

    assert "exceeds ceiling 50.0 gwei" in by_chain(manifest)["alpha"]["error"]


def test_insufficient_balance_blocks_broadcast(harness):
    harness.alpha.balance_value = 10**15  # 0.001 ETH < 0.01 ETH

    manifest, _ = harness.engine.release(ReleaseOptions())

    alpha = by_chain(manifest)["alpha"]
    assert alpha["status"] == "failed" and "balance" in alpha["error"]
    assert not any(
        c["broadcast"] and c["chain"] == "alpha" for n, c in harness.foundry.calls if n == "script"
    )


def test_unexpected_signer_key_is_refused_globally(harness):
    harness.foundry.wallet = "0x000000000000000000000000000000000000dEaD"

    with pytest.raises(PreflightError, match="refusing to sign with an unexpected key"):
        harness.engine.release(ReleaseOptions())


def test_bytecode_mismatch_fails_verification(harness):
    harness.foundry.runtime = "0x6080604052deadbeef00000000000000000000"

    manifest, _ = harness.engine.release(ReleaseOptions())

    alpha = by_chain(manifest)["alpha"]
    assert alpha["status"] == "deployed"
    assert alpha["bytecode_verified"] is False
    assert "size mismatch" in alpha["error"]
    assert manifest["success"] is False


def test_owner_mismatch_fails_verification(harness):
    harness.alpha.owner = "0x000000000000000000000000000000000000bEEF"

    manifest, _ = harness.engine.release(ReleaseOptions())

    alpha = by_chain(manifest)["alpha"]
    assert alpha["owner_verified"] is False and "owner() is" in alpha["error"]


def test_dry_run_broadcasts_nothing(harness):
    manifest, paths = harness.engine.release(ReleaseOptions(dry_run=True))

    assert {d["status"] for d in manifest["deployments"]} == {"simulated"}
    assert not any(c["broadcast"] for n, c in harness.foundry.calls if n == "script")
    assert paths["manifest"].name == "manifest.dry-run.json"
    assert not (harness.workspace / "deployments" / "test" / "latest.json").exists()


def test_chain_filter_does_not_replace_latest(harness):
    manifest, _ = harness.engine.release(ReleaseOptions(chains=["beta"]))

    assert [d["chain"] for d in manifest["deployments"]] == ["beta"]
    assert not (harness.workspace / "deployments" / "test" / "latest.json").exists()


def test_secrets_never_reach_logs_or_outputs(harness):
    harness.engine.release(ReleaseOptions())

    logged = harness.stream.getvalue()
    out = harness.workspace / "deployments"
    persisted = "".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())
    for secret in (RPC_URL, "SUPERSECRETPROVIDERKEY0123456789", ETHERSCAN_KEY):
        assert secret not in logged
        assert secret not in persisted


def test_guardrail_violation_stops_before_any_work(harness):
    class HotKey:
        type = "secretsmanager"

        def describe(self):
            return {"type": "secretsmanager"}

    harness.engine.profile = dataclasses.replace(harness.engine.profile, production=True)
    harness.engine.signer = HotKey()
    with pytest.raises(PolicyViolation) as exc:
        harness.engine.release(ReleaseOptions())
    assert any("non-exportable key" in v for v in exc.value.violations)
    assert harness.foundry.calls == []


def test_audit_detects_owner_drift(harness):
    harness.engine.release(ReleaseOptions())
    assert harness.engine.audit()["ok"] is True

    harness.beta.owner = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # hijacked
    report = harness.engine.audit()

    assert report["ok"] is False
    beta = next(c for c in report["checks"] if c["chain"] == "beta")
    assert any("OWNER DRIFT" in i for i in beta["issues"])


def test_owner_word_helper():
    assert owner_word(OWNER).endswith(OWNER[2:].lower())
