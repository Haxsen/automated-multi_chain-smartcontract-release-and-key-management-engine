"""Signer backends. The private key never touches the engine, disk or argv.

=================  ===========================================  =====================
type               where the key lives                          how forge signs
=================  ===========================================  =====================
kms  (default)     AWS KMS HSM (FIPS 140-3 L3), non-exportable  ``--aws`` -> kms:Sign
ledger             Ledger hardware wallet                       ``--ledger``
secretsmanager     AWS Secrets Manager (break-glass fallback)   env -> vm.startBroadcast(pk)
anvil              local dev node's unlocked account            ``--unlocked``
=================  ===========================================  =====================
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from release_engine.config import SignerConfig
from release_engine.errors import ConfigError, SecretError

if TYPE_CHECKING:
    from release_engine.foundry import Foundry
    from release_engine.secret_store import SecretStore

_PRIVATE_KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")


class Signer(ABC):
    type: ClassVar[str]
    #: True when the key cannot be exported (HSM / hardware wallet).
    hardware_backed: ClassVar[bool] = False

    def __init__(self) -> None:
        self._address: str | None = None

    @abstractmethod
    def describe(self) -> dict[str, str]:
        """Non-secret metadata recorded in the plan and manifest."""

    def env(self) -> dict[str, str]:
        """Environment for the forge child process."""
        return {}

    def wallet_args(self) -> list[str]:
        """forge script wallet flags (after the address is resolved)."""
        return []

    def resolve_address(self, foundry: Foundry) -> str | None:
        """Deployer address if knowable before simulation; None if learned from the script."""
        return self._address


class AnvilSigner(Signer):
    type = "anvil"

    def __init__(self, address: str):
        super().__init__()
        self._address = address

    def describe(self) -> dict[str, str]:
        return {"type": self.type, "address": self._address or ""}

    def wallet_args(self) -> list[str]:
        return ["--unlocked", "--sender", self._address or ""]


class KmsSigner(Signer):
    type = "kms"
    hardware_backed = True

    def __init__(self, key_id: str):
        super().__init__()
        self.key_id = key_id

    def describe(self) -> dict[str, str]:
        # A key ARN/alias is an identifier, not a secret; it is useless without IAM permission.
        return {"type": self.type, "key_id": self.key_id, "address": self._address or ""}

    def env(self) -> dict[str, str]:
        return {"AWS_KMS_KEY_ID": self.key_id}

    def resolve_address(self, foundry: Foundry) -> str:
        if self._address is None:
            # Derived via kms:GetPublicKey - proves the role can reach the key before anything else.
            # (Sign is never needed for this; only the release role may call kms:Sign.)
            self._address = foundry.wallet_address(["--aws"], env=self.env())
        return self._address

    def wallet_args(self) -> list[str]:
        if self._address is None:
            raise ConfigError("KMS signer address must be resolved before use")
        return ["--aws", "--sender", self._address]


class LedgerSigner(Signer):
    type = "ledger"
    hardware_backed = True

    def __init__(self, hd_path: str = "m/44'/60'/0'/0/0"):
        super().__init__()
        self.hd_path = hd_path

    def describe(self) -> dict[str, str]:
        return {"type": self.type, "hd_path": self.hd_path, "address": self._address or ""}

    def resolve_address(self, foundry: Foundry) -> str:
        if self._address is None:
            self._address = foundry.wallet_address(
                ["--ledger", "--mnemonic-derivation-path", self.hd_path]
            )
        return self._address

    def wallet_args(self) -> list[str]:
        if self._address is None:
            raise ConfigError("Ledger signer address must be resolved before use")
        return ["--ledger", "--mnemonic-derivation-paths", self.hd_path, "--sender", self._address]


class SecretsManagerSigner(Signer):
    """Break-glass fallback for accounts without KMS.

    The key is fetched into memory only, masked, and handed to forge via the child-process
    environment (``DEPLOYER_PRIVATE_KEY`` -> ``vm.startBroadcast(pk)``). It is still an
    exportable hot key, which is why guardrails forbid it for production profiles.
    """

    type = "secretsmanager"

    def __init__(self, store: SecretStore, field: str = "DEPLOYER_PRIVATE_KEY"):
        super().__init__()
        self._store = store
        self.field = field

    def describe(self) -> dict[str, str]:
        secret_id = getattr(self._store, "secret_id", self._store.source)
        return {"type": self.type, "secret_id": secret_id, "field": self.field}

    def env(self) -> dict[str, str]:
        key = self._store.get(self.field).strip()
        if not _PRIVATE_KEY_RE.match(key):
            raise SecretError(f"secret field {self.field!r} is not a 32-byte hex private key")
        # vm.envUint parses '0x..' as hex but bare digits as *decimal* - always normalise.
        return {"DEPLOYER_PRIVATE_KEY": key if key.startswith("0x") else "0x" + key}


def build_signer(cfg: SignerConfig, store: SecretStore) -> Signer:
    opts = cfg.options
    if cfg.type == "kms":
        return KmsSigner(opts["key_id"])
    if cfg.type == "ledger":
        return LedgerSigner(opts.get("hd_path", "m/44'/60'/0'/0/0"))
    if cfg.type == "anvil":
        return AnvilSigner(opts["address"])
    if cfg.type == "secretsmanager":
        return SecretsManagerSigner(store, opts.get("field", "DEPLOYER_PRIVATE_KEY"))
    raise ConfigError(f"unknown signer type {cfg.type!r}")
