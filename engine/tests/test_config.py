from __future__ import annotations

import pytest

from release_engine.config import interpolate, load_config
from release_engine.errors import ConfigError

from .conftest import REPO_ROOT


def test_repository_config_local_profile_loads():
    config = load_config(REPO_ROOT / "release.toml", env={})
    profile = config.load_profile("local", env={})
    assert [c.chain_id for c in profile.chains] == [31337, 31338, 31339]
    assert profile.signer.type == "anvil"
    assert profile.chains[0].rpc == "http://127.0.0.1:8545"
    assert config.foundry_root.name == "contracts"


def test_repository_mainnet_profile_requires_ci_variables():
    config = load_config(REPO_ROOT / "release.toml", env={})
    with pytest.raises(ConfigError, match="RELEASE_OWNER is not set"):
        config.load_profile("mainnet", env={})


def test_repository_mainnet_profile_with_variables():
    env = {
        "RELEASE_OWNER": "0x1111111111111111111111111111111111111111",
        "EXPECTED_DEPLOYER": "0x2222222222222222222222222222222222222222",
        "AWS_KMS_KEY_ID": "alias/web3-release-mainnet-deployer",
    }
    config = load_config(REPO_ROOT / "release.toml", env=env)
    profile = config.load_profile("mainnet", env=env)
    assert profile.production and profile.require_tag
    assert profile.secrets == "aws:web3-release/mainnet/config"
    assert all(c.rpc_is_secret for c in profile.chains)
    assert {c.chain_id for c in profile.chains} == {1, 42161, 10}


@pytest.mark.parametrize(
    ("template", "env", "expected"),
    [
        ("${A}", {"A": "x"}, "x"),
        ("${A:-fallback}", {}, "fallback"),
        ("${A:-fallback}", {"A": ""}, "fallback"),
        ("pre-${A}-post", {"A": "mid"}, "pre-mid-post"),
        ("no vars", {}, "no vars"),
    ],
)
def test_interpolate(template, env, expected):
    assert interpolate(template, env, "t") == expected


def test_interpolate_missing_variable_names_location():
    with pytest.raises(
        ConfigError, match=r"profiles.x.owner: environment variable NOPE is not set"
    ):
        interpolate("${NOPE}", {}, "profiles.x.owner")


def _write(tmp_path, body: str):
    path = tmp_path / "release.toml"
    path.write_text(
        """
[release]
name = "x"
version = "1.0.0"
contract = "src/X.sol:X"
script = "script/D.s.sol:D"
salt = "s"

[chains.c]
chain_id = 5
rpc = "http://127.0.0.1:8545"
max_gas_price_gwei = 1
"""
        + body,
        encoding="utf-8",
    )
    return load_config(path, env={})


def test_rejects_bad_owner_address(tmp_path):
    config = _write(
        tmp_path, '[profiles.p]\nchains=["c"]\nowner="0x123"\n[profiles.p.signer]\ntype="ledger"\n'
    )
    with pytest.raises(ConfigError, match=r"profiles.p.owner"):
        config.load_profile("p", env={})


def test_rejects_unknown_signer(tmp_path):
    config = _write(
        tmp_path,
        '[profiles.p]\nchains=["c"]\nowner="0x1111111111111111111111111111111111111111"\n'
        '[profiles.p.signer]\ntype="plaintext-file"\n',
    )
    with pytest.raises(ConfigError, match=r"signer.type"):
        config.load_profile("p", env={})


def test_kms_requires_key_id(tmp_path):
    config = _write(
        tmp_path,
        '[profiles.p]\nchains=["c"]\nowner="0x1111111111111111111111111111111111111111"\n'
        '[profiles.p.signer]\ntype="kms"\n',
    )
    with pytest.raises(ConfigError, match="key_id"):
        config.load_profile("p", env={})


def test_secretsmanager_signer_requires_aws_secret_source(tmp_path):
    config = _write(
        tmp_path,
        '[profiles.p]\nchains=["c"]\nowner="0x1111111111111111111111111111111111111111"\n'
        'secrets="env"\n[profiles.p.signer]\ntype="secretsmanager"\n',
    )
    with pytest.raises(ConfigError, match="requires secrets"):
        config.load_profile("p", env={})


def test_explorer_verification_requires_api_key(tmp_path):
    config = _write(
        tmp_path,
        '[profiles.p]\nchains=["c"]\nowner="0x1111111111111111111111111111111111111111"\n'
        'verify_explorer=true\n[profiles.p.signer]\ntype="ledger"\n',
    )
    with pytest.raises(ConfigError, match="etherscan_api_key"):
        config.load_profile("p", env={})


def test_rejects_non_semver_version(tmp_path):
    path = tmp_path / "release.toml"
    path.write_text(
        '[release]\nname="x"\nversion="latest"\ncontract="a:b"\nscript="c:d"\nsalt="s"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="semver"):
        load_config(path, env={})
