"""CLI contract: outputs, exit codes, and which overrides are (not) allowed."""

from __future__ import annotations

import json

import pytest

from release_engine.cli import main

from .conftest import REPO_ROOT

CONFIG = str(REPO_ROOT / "release.toml")


def test_profiles_lists_every_profile(capsys):
    assert main(["--config", CONFIG, "profiles"]) == 0
    out = capsys.readouterr().out
    for name in ("local", "testnet", "testnet-break-glass", "mainnet"):
        assert name in out


def test_plan_emits_policy_input_without_secrets(tmp_path, capsys):
    out = tmp_path / "plan.json"
    assert main(["--config", CONFIG, "plan", "--profile", "local", "--out", str(out)]) == 0
    plan = json.loads(out.read_text())
    assert plan["schema"] == "release-engine/plan/v1"
    assert plan["guardrail_violations"] == []
    assert [c["chain_id"] for c in plan["chains"]] == [31337, 31338, 31339]
    assert {c["rpc_source"] for c in plan["chains"]} == {"literal"}


def test_missing_ci_variables_is_a_config_error(monkeypatch):
    for var in ("RELEASE_OWNER", "EXPECTED_DEPLOYER", "AWS_KMS_KEY_ID"):
        monkeypatch.delenv(var, raising=False)
    assert main(["--config", CONFIG, "plan", "--profile", "mainnet"]) == 2


def test_unknown_profile_is_a_config_error():
    assert main(["--config", CONFIG, "plan", "--profile", "prod-yolo"]) == 2


def test_release_has_no_secret_source_override():
    # Only the read-only `audit` command may swap the secret source.
    with pytest.raises(SystemExit):
        main(["--config", CONFIG, "release", "--profile", "local", "--secrets", "env"])


def test_audit_without_a_recorded_release_fails_cleanly(tmp_path):
    config = tmp_path / "release.toml"
    config.write_text(
        (REPO_ROOT / "release.toml")
        .read_text(encoding="utf-8")
        .replace(
            'foundry_root = "contracts"', f'foundry_root = "{(REPO_ROOT / "contracts").as_posix()}"'
        ),
        encoding="utf-8",
    )
    assert main(["--config", str(config), "audit", "--profile", "local", "--secrets", "env"]) == 2
