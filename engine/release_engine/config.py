"""release.toml -> typed, validated, env-interpolated configuration.

Values may reference the environment as ``${NAME}`` or ``${NAME:-default}``. Secrets
(RPC URLs that embed provider keys, explorer API keys) are referenced as ``secret:NAME``
and are only resolved at release time through the profile's secret store - they never
live in the config file, the plan, the manifest or the logs.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from release_engine.errors import ConfigError

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

SECRET_PREFIX = "secret:"  # noqa: S105 - a reference marker, not a credential
SIGNER_TYPES = frozenset({"kms", "secretsmanager", "ledger", "anvil"})


def interpolate(value: str, env: Mapping[str, str], where: str) -> str:
    """Expand ``${VAR}`` / ``${VAR:-default}``. Empty variables count as unset."""

    def _sub(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        resolved = env.get(name)
        if resolved:
            return resolved
        if default is not None:
            return default
        raise ConfigError(f"{where}: environment variable {name} is not set")

    return _ENV_RE.sub(_sub, value)


def _interpolate_tree(node: Any, env: Mapping[str, str], where: str) -> Any:
    if isinstance(node, str):
        return interpolate(node, env, where)
    if isinstance(node, list):
        return [_interpolate_tree(v, env, f"{where}[{i}]") for i, v in enumerate(node)]
    if isinstance(node, dict):
        return {k: _interpolate_tree(v, env, f"{where}.{k}") for k, v in node.items()}
    return node


def _require_address(value: Any, where: str) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.match(value):
        raise ConfigError(f"{where}: expected a 0x-prefixed 20-byte address, got {value!r}")
    return value


@dataclass(frozen=True)
class Chain:
    name: str
    chain_id: int
    rpc: str
    explorer: str | None
    max_gas_price_gwei: float
    min_balance_eth: float
    confirmations: int

    @property
    def rpc_is_secret(self) -> bool:
        return self.rpc.startswith(SECRET_PREFIX)


@dataclass(frozen=True)
class SignerConfig:
    type: str
    options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Release:
    name: str
    version: str
    contract: str
    script: str
    salt: str

    @property
    def contract_path(self) -> str:
        return self.contract.split(":", 1)[0]

    @property
    def contract_name(self) -> str:
        return self.contract.split(":", 1)[1]

    @property
    def script_path(self) -> str:
        return self.script.split(":", 1)[0]


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    chains: tuple[Chain, ...]
    signer: SignerConfig
    owner: str
    expected_deployer: str | None
    secrets: str
    etherscan_api_key: str | None
    verify_explorer: bool
    require_clean_git: bool
    require_tag: bool
    production: bool

    @property
    def secrets_source(self) -> str:
        return "aws-secretsmanager" if self.secrets.startswith("aws:") else "env"


@dataclass(frozen=True)
class Config:
    path: Path
    root: Path
    foundry_root: Path
    deployments_dir: Path
    release: Release
    raw_chains: dict[str, Any]
    raw_profiles: dict[str, Any]

    def profile_names(self) -> list[str]:
        return sorted(self.raw_profiles)

    def load_profile(self, name: str, env: Mapping[str, str] | None = None) -> Profile:
        env = os.environ if env is None else env
        if name not in self.raw_profiles:
            known = ", ".join(self.profile_names())
            raise ConfigError(f"unknown profile {name!r} (known: {known})")
        where = f"profiles.{name}"
        raw = _interpolate_tree(self.raw_profiles[name], env, where)

        chain_names = raw.get("chains") or []
        if not chain_names:
            raise ConfigError(f"{where}.chains: at least one chain is required")
        if len(set(chain_names)) != len(chain_names):
            raise ConfigError(f"{where}.chains: duplicate chain names")
        chains = tuple(self._load_chain(c, env) for c in chain_names)

        signer_raw = dict(raw.get("signer") or {})
        signer_type = signer_raw.pop("type", None)
        if signer_type not in SIGNER_TYPES:
            raise ConfigError(f"{where}.signer.type must be one of {sorted(SIGNER_TYPES)}")
        signer = SignerConfig(signer_type, {k: str(v) for k, v in signer_raw.items()})

        secrets = raw.get("secrets", "env")
        if secrets != "env" and not (secrets.startswith("aws:") and len(secrets) > 4):
            raise ConfigError(f"{where}.secrets must be 'env' or 'aws:<secret-id>'")

        profile = Profile(
            name=name,
            description=raw.get("description", ""),
            chains=chains,
            signer=signer,
            owner=_require_address(raw.get("owner"), f"{where}.owner"),
            expected_deployer=(
                _require_address(raw["expected_deployer"], f"{where}.expected_deployer")
                if raw.get("expected_deployer")
                else None
            ),
            secrets=secrets,
            etherscan_api_key=raw.get("etherscan_api_key"),
            verify_explorer=bool(raw.get("verify_explorer", False)),
            require_clean_git=bool(raw.get("require_clean_git", False)),
            require_tag=bool(raw.get("require_tag", False)),
            production=bool(raw.get("production", False)),
        )
        _validate_profile(profile, where)
        return profile

    def _load_chain(self, name: str, env: Mapping[str, str]) -> Chain:
        where = f"chains.{name}"
        if name not in self.raw_chains:
            raise ConfigError(f"{where}: chain is referenced by a profile but not defined")
        raw = _interpolate_tree(self.raw_chains[name], env, where)
        try:
            chain = Chain(
                name=name,
                chain_id=int(raw["chain_id"]),
                rpc=str(raw["rpc"]),
                explorer=raw.get("explorer"),
                max_gas_price_gwei=float(raw["max_gas_price_gwei"]),
                min_balance_eth=float(raw.get("min_balance_eth", 0)),
                confirmations=int(raw.get("confirmations", 1)),
            )
        except KeyError as exc:
            raise ConfigError(f"{where}: missing required key {exc.args[0]!r}") from None
        if chain.chain_id <= 0:
            raise ConfigError(f"{where}.chain_id must be positive")
        if chain.confirmations < 1:
            raise ConfigError(f"{where}.confirmations must be >= 1")
        if chain.max_gas_price_gwei <= 0:
            raise ConfigError(f"{where}.max_gas_price_gwei must be > 0")
        return chain


def _validate_profile(p: Profile, where: str) -> None:
    opts = p.signer.options
    if p.signer.type == "kms" and not opts.get("key_id"):
        raise ConfigError(f"{where}.signer.key_id is required for the kms signer")
    if p.signer.type == "anvil":
        _require_address(opts.get("address"), f"{where}.signer.address")
    if p.signer.type == "secretsmanager" and p.secrets_source != "aws-secretsmanager":
        raise ConfigError(f"{where}: the secretsmanager signer requires secrets = 'aws:<id>'")
    if p.verify_explorer:
        if not p.etherscan_api_key:
            raise ConfigError(f"{where}.etherscan_api_key is required when verify_explorer = true")
        missing = [c.name for c in p.chains if not c.explorer]
        if missing:
            raise ConfigError(f"{where}: chains without an explorer cannot be verified: {missing}")
    ids = [c.chain_id for c in p.chains]
    if len(set(ids)) != len(ids):
        raise ConfigError(f"{where}: two chains share a chain_id")


def load_config(path: str | Path, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    path = Path(path).resolve()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path.name}: invalid TOML: {exc}") from None

    root = path.parent
    project = data.get("project", {})
    rel = _interpolate_tree(data.get("release", {}), env, "release")
    try:
        release = Release(
            name=rel["name"],
            version=rel["version"],
            contract=rel["contract"],
            script=rel["script"],
            salt=rel["salt"],
        )
    except KeyError as exc:
        raise ConfigError(f"release: missing required key {exc.args[0]!r}") from None
    if not SEMVER_RE.match(release.version):
        raise ConfigError(f"release.version must be semver, got {release.version!r}")
    for key, value in (("contract", release.contract), ("script", release.script)):
        if ":" not in value:
            raise ConfigError(f"release.{key} must look like 'path/File.sol:Name'")

    return Config(
        path=path,
        root=root,
        foundry_root=(root / project.get("foundry_root", ".")).resolve(),
        deployments_dir=(root / project.get("deployments_dir", "deployments")).resolve(),
        release=release,
        raw_chains=data.get("chains", {}),
        raw_profiles=data.get("profiles", {}),
    )
