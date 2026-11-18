"""Test doubles for the chain, forge and the explorer, so the orchestrator is tested offline."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from release_engine.config import load_config
from release_engine.engine import ReleaseEngine
from release_engine.gitinfo import GitInfo
from release_engine.logger import ReleaseLogger
from release_engine.redact import Redactor
from release_engine.secret_store import EnvSecretStore
from release_engine.signers import build_signer

REPO_ROOT = Path(__file__).resolve().parents[2]

DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
OWNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
VAULT = "0xC84Fc5207886EadAF688730a7A7c0c1F16e37710"
RUNTIME = "0x6080604052348015600e575f5ffd5b50"
CREATION = "0x6080604052" + "aa" * 20
RPC_URL = "https://rpc.example.com/v2/SUPERSECRETPROVIDERKEY0123456789"
ETHERSCAN_KEY = "ETHERSCANKEY0123456789"  # gitleaks:allow (fake key)


def owner_word(address: str) -> str:
    return "0x" + "00" * 12 + address[2:].lower()


class FakeRpc:
    def __init__(self, chain_id: int, *, gas_price: int = 10**9, balance: int = 10**18):
        self.chain_id_value = chain_id
        self.gas_price_value = gas_price
        self.balance_value = balance
        self.codes: dict[str, str] = {}
        self.owner = OWNER
        self.receipts: dict[str, dict[str, Any]] = {}
        self.head = 100

    def chain_id(self) -> int:
        return self.chain_id_value

    def gas_price(self) -> int:
        return self.gas_price_value

    def balance(self, address: str) -> int:
        return self.balance_value

    def code(self, address: str) -> str:
        return self.codes.get(address.lower(), "0x")

    def block_number(self) -> int:
        self.head += 1  # every poll sees a new block
        return self.head - 1

    def receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.receipts.get(tx_hash)

    def eth_call(self, to: str, data: str) -> str:
        if data == "0x8da5cb5b":
            return owner_word(self.owner)
        return "0x" + "00" * 32


class FakeFoundry:
    """Mimics forge: writes the script result file and the broadcast log, mutates FakeRpc."""

    def __init__(self, root: Path, rpcs: dict[str, FakeRpc], runtime: str = RUNTIME):
        self.root = root
        self.rpcs = rpcs  # keyed by RPC URL
        self.runtime = runtime  # what a broadcast "deploys"
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.verified: list[str] = []
        self.wallet = DEPLOYER
        self.script_error: Exception | None = None

    def build(self) -> None:
        self.calls.append(("build", {}))

    def artifact(self, contract_path: str, contract_name: str) -> dict[str, Any]:
        return {
            "bytecode": {"object": CREATION},
            "deployedBytecode": {"object": RUNTIME, "immutableReferences": {}},
            "metadata": {"compiler": {"version": "0.8.28+commit.7893614a"}},
        }

    def broadcast_log(self, script_path: str, chain_id: int) -> Path:
        return self.root / "broadcast" / Path(script_path).name / str(chain_id) / "run-latest.json"

    def run_script(
        self,
        script: str,
        *,
        rpc_url: str,
        wallet_args: list[str],
        env: dict[str, str],
        broadcast: bool,
        chain: str,
    ) -> str:
        self.calls.append(
            (
                "script",
                {
                    "broadcast": broadcast,
                    "env": dict(env),
                    "wallet_args": wallet_args,
                    "rpc_url": rpc_url,
                    "chain": chain,
                },
            )
        )
        if self.script_error:
            raise self.script_error
        rpc = self.rpcs[rpc_url]
        deployer = DEPLOYER
        already = rpc.code(VAULT) != "0x"
        if broadcast and not already:
            tx = "0x" + f"{rpc.chain_id_value:064x}"
            rpc.codes[VAULT.lower()] = self.runtime
            rpc.receipts[tx] = {
                "status": "0x1",
                "blockNumber": hex(rpc.head),
                "blockHash": "0xabc",
                "gasUsed": hex(700_000),
                "effectiveGasPrice": hex(10**9),
            }
            log = self.broadcast_log("script/Deploy.s.sol", rpc.chain_id_value)
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                json.dumps(
                    {
                        "transactions": [
                            {"hash": tx, "transactionType": "CREATE2", "contractAddress": VAULT}
                        ]
                    }
                )
            )
        out = self.root / env["RELEASE_OUTPUT"]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "deployer": deployer,
                    "vault": VAULT,
                    "alreadyDeployed": already,
                    "initCodeHash": "0x" + "11" * 32,
                    "salt": "0x" + "22" * 32,
                    "chainId": rpc.chain_id_value,
                    "constructorArgs": owner_word(env["RELEASE_OWNER"]),
                }
            )
        )
        return "ok"

    def verify_contract(self, **kwargs: Any) -> str:
        self.verified.append((kwargs["chain_id"], kwargs["address"]))
        return "verified"

    def wallet_address(self, wallet_args: list[str], env: dict[str, str] | None = None) -> str:
        self.calls.append(("wallet", {"args": wallet_args, "env": env}))
        return self.wallet


class FakeExplorer:
    def __init__(self) -> None:
        self.verified: set[tuple[int, str]] = set()
        self.foundry: FakeFoundry | None = None

    def is_verified(self, chain_id: int, address: str) -> bool:
        # CREATE2 => same address on every chain, so verification is tracked per chain.
        if self.foundry and (chain_id, address) in self.foundry.verified:
            self.verified.add((chain_id, address))
        return (chain_id, address) in self.verified


CONFIG_TEMPLATE = """
[project]
foundry_root = "contracts"
deployments_dir = "deployments"

[release]
name = "safe-vault"
version = "1.0.0"
contract = "src/SafeVault.sol:SafeVault"
script = "script/Deploy.s.sol:Deploy"
salt = "safe-vault/v1.0.0"

[chains.alpha]
chain_id = 11155111
rpc = "secret:ALPHA_RPC_URL"
explorer = "https://sepolia.etherscan.io"
max_gas_price_gwei = 50
min_balance_eth = 0.01
confirmations = 2

[chains.beta]
chain_id = 421614
rpc = "secret:BETA_RPC_URL"
explorer = "https://sepolia.arbiscan.io"
max_gas_price_gwei = 5
min_balance_eth = 0.01
confirmations = 1

[profiles.test]
chains = ["alpha", "beta"]
owner = "{owner}"
expected_deployer = "{deployer}"
secrets = "env"
etherscan_api_key = "secret:ETHERSCAN_API_KEY"
verify_explorer = true

[profiles.test.signer]
type = "kms"
key_id = "alias/test-deployer"
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "contracts").mkdir()
    (tmp_path / "release.toml").write_text(
        textwrap.dedent(CONFIG_TEMPLATE).format(owner=OWNER, deployer=DEPLOYER), encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def harness(workspace: Path):
    """A fully wired ReleaseEngine against two fake chains."""
    alpha_url, beta_url = RPC_URL, RPC_URL.replace("rpc.", "beta.")
    env = {"ALPHA_RPC_URL": alpha_url, "BETA_RPC_URL": beta_url, "ETHERSCAN_API_KEY": ETHERSCAN_KEY}
    rpcs = {alpha_url: FakeRpc(11155111), beta_url: FakeRpc(421614)}

    redactor = Redactor(github_actions=False)
    stream = io.StringIO()
    log = ReleaseLogger(redactor, stream=stream, verbose=True, github_actions=False)
    config = load_config(workspace / "release.toml", env={})
    profile = config.load_profile("test", env={})
    store = EnvSecretStore(redactor, env)
    foundry = FakeFoundry(workspace / "contracts", rpcs)
    explorer = FakeExplorer()
    explorer.foundry = foundry

    engine = ReleaseEngine(
        config,
        profile,
        redactor=redactor,
        log=log,
        foundry=foundry,
        store=store,
        signer=build_signer(profile.signer, store),
        git=GitInfo(commit="deadbeef", dirty=False, tag=None),
        rpc_factory=lambda url: rpcs[url],
        explorer_factory=lambda key: explorer,
        sleep=lambda s: None,
    )

    class Harness:
        pass

    h = Harness()
    h.engine, h.rpcs, h.foundry, h.explorer, h.stream, h.workspace = (
        engine,
        rpcs,
        foundry,
        explorer,
        stream,
        workspace,
    )
    h.alpha, h.beta = rpcs[alpha_url], rpcs[beta_url]
    return h
