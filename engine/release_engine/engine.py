"""Release orchestration.

    plan ──► guardrails ──► forge build ──► resolve signer (KMS GetPublicKey)
                                   │
            for each chain ◄───────┘
              1. resolve RPC from secret store (masked)       5. broadcast (signed in KMS)
              2. RPC chain-id == configured chain-id          6. wait N confirmations + reorg check
              3. gas price <= ceiling                         7. on-chain runtime code == artifact
              4. simulate; deployer == pinned address;        8. owner() == configured owner
                 balance >= minimum                           9. Etherscan V2 source verification
                                   │
            manifest.json + sha256 + summary.md + JSONL log ──► (CI) cosign sign + S3 WORM ledger

Chains are processed independently: one chain failing never leaves another half-done, and
because the address is CREATE2-deterministic a re-run only finishes what is missing.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from release_engine import guardrails
from release_engine.bytecode import (
    artifact_digests,
    compiler_version,
    runtime_code_matches,
    sha256_hex,
    to_bytes,
)
from release_engine.config import Chain, Config, Profile
from release_engine.errors import (
    ConfigError,
    PolicyViolation,
    PreflightError,
    ReleaseError,
    VerificationError,
)
from release_engine.explorer import Etherscan
from release_engine.foundry import Foundry
from release_engine.gitinfo import GitInfo
from release_engine.logger import ReleaseLogger, utcnow
from release_engine.manifest import ChainResult, build_manifest, write_json, write_release_outputs
from release_engine.redact import Redactor
from release_engine.rpc import RpcClient
from release_engine.secret_store import SecretStore
from release_engine.signers import Signer

PLAN_SCHEMA = "release-engine/plan/v1"
OWNER_SELECTOR = "0x8da5cb5b"  # owner()
PAUSED_SELECTOR = "0x5c975abb"  # paused()
GWEI = 10**9
WEI_PER_ETH = 10**18


@dataclass
class ReleaseOptions:
    chains: list[str] | None = None
    dry_run: bool = False
    skip_explorer: bool = False
    fail_fast: bool = False
    skip_build: bool = False


def _decode_address(word: str) -> str:
    raw = to_bytes(word)
    if len(raw) != 32:
        raise VerificationError("owner() returned malformed data")
    return "0x" + raw[12:].hex()


class ReleaseEngine:
    def __init__(
        self,
        config: Config,
        profile: Profile,
        *,
        redactor: Redactor,
        log: ReleaseLogger,
        foundry: Foundry,
        store: SecretStore,
        signer: Signer,
        git: GitInfo,
        rpc_factory: Callable[[str], RpcClient] | None = None,
        explorer_factory: Callable[[str], Etherscan] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        confirmation_timeout: float = 900.0,
        poll_interval: float = 3.0,
        explorer_poll_interval: float = 10.0,
    ):
        self.config = config
        self.profile = profile
        self.redactor = redactor
        self.log = log
        self.foundry = foundry
        self.store = store
        self.signer = signer
        self.git = git
        self._rpc_factory = rpc_factory or (lambda url: RpcClient(url, redactor))
        self._explorer_factory = explorer_factory or (lambda key: Etherscan(key, redactor))
        self._sleep = sleep
        self._clock = clock
        self._confirmation_timeout = confirmation_timeout
        self._poll = poll_interval
        self._explorer_poll = explorer_poll_interval

    # ================================================================== plan

    def plan(self) -> dict[str, Any]:
        """Everything about the release that policy needs - with no secrets and no network."""
        p, rel = self.profile, self.config.release
        return {
            "schema": PLAN_SCHEMA,
            "profile": p.name,
            "description": p.description,
            "production": p.production,
            "release": {
                "name": rel.name,
                "version": rel.version,
                "contract": rel.contract,
                "script": rel.script,
                "salt": rel.salt,
            },
            "signer": self.signer.describe(),
            "owner": p.owner,
            "expected_deployer": p.expected_deployer,
            "secrets_source": p.secrets_source,
            "verify_explorer": p.verify_explorer,
            "require_clean_git": p.require_clean_git,
            "require_tag": p.require_tag,
            "git": self.git.as_dict(),
            "chains": [
                {
                    "name": c.name,
                    "chain_id": c.chain_id,
                    "rpc_source": "secret" if c.rpc_is_secret else "literal",
                    "explorer": c.explorer,
                    "max_gas_price_gwei": c.max_gas_price_gwei,
                    "min_balance_eth": c.min_balance_eth,
                    "confirmations": c.confirmations,
                }
                for c in p.chains
            ],
        }

    # ================================================================== release

    def release(self, opts: ReleaseOptions) -> tuple[dict[str, Any], dict[str, Path]]:
        started_at = utcnow()
        plan = self.plan()
        violations = guardrails.evaluate(plan)
        if violations:
            raise PolicyViolation(violations)

        p, rel = self.profile, self.config.release
        out_dir = self.config.deployments_dir / p.name / rel.version
        run_id = os.environ.get("GITHUB_RUN_ID") or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.log.attach_file(out_dir / "logs" / f"{run_id}.jsonl")
        write_json(out_dir / "plan.json", plan)

        chains = self._select_chains(opts.chains)
        self.log.info(
            f"release {rel.name} v{rel.version} -> profile '{p.name}' "
            f"({', '.join(c.name for c in chains)}) signer={self.signer.type}"
            + (" [DRY RUN]" if opts.dry_run else ""),
            event="release_started",
            git=plan["git"],
        )

        if not opts.skip_build:
            self.foundry.build()
        artifact = self.foundry.artifact(rel.contract_path, rel.contract_name)
        artifact_info = {
            "contract": rel.contract,
            "compiler": compiler_version(artifact),
            **artifact_digests(artifact),
        }

        # Resolve the signer once, up front: for KMS this is kms:GetPublicKey, which proves the
        # OIDC role can reach the key before any chain is touched.
        address = self.signer.resolve_address(self.foundry)
        if address:
            self.log.info(
                f"signer {self.signer.type} resolved to {address}", event="signer_resolved"
            )
            self._check_pinned_deployer(address)

        results: list[ChainResult] = []
        for chain in chains:
            result = self._release_chain(chain, artifact, opts)
            results.append(result)
            if opts.fail_fast and not result.succeeded(
                p.verify_explorer and not opts.skip_explorer
            ):
                self.log.warning("--fail-fast: stopping after first failed chain")
                break

        manifest = build_manifest(
            plan={**plan, "signer": self.signer.describe()},
            artifact=artifact_info,
            results=results,
            started_at=started_at,
            finished_at=utcnow(),
            dry_run=opts.dry_run,
        )
        # Only a full-profile run may replace latest.json (what `audit` checks against).
        latest = None if opts.chains else self.config.deployments_dir / p.name / "latest.json"
        paths = write_release_outputs(out_dir, manifest, latest)
        self.log.info(
            "release finished" if manifest["success"] else "release finished WITH FAILURES",
            event="release_finished",
            success=manifest["success"],
            manifest=str(paths["manifest"]),
        )
        self._publish_ci_outputs(manifest, paths)
        return manifest, paths

    def _select_chains(self, names: list[str] | None) -> list[Chain]:
        if not names:
            return list(self.profile.chains)
        by_name = {c.name: c for c in self.profile.chains}
        unknown = [n for n in names if n not in by_name]
        if unknown:
            raise ConfigError(f"chains {unknown} are not part of profile '{self.profile.name}'")
        return [by_name[n] for n in names]

    def _check_pinned_deployer(self, address: str) -> None:
        expected = self.profile.expected_deployer
        if expected and address.lower() != expected.lower():
            raise PreflightError(
                f"signer resolved to {address} but the profile pins {expected}: "
                "refusing to sign with an unexpected key"
            )

    # ------------------------------------------------------------------ per chain

    def _release_chain(
        self, chain: Chain, artifact: dict[str, Any], opts: ReleaseOptions
    ) -> ChainResult:
        result = ChainResult(chain=chain.name, chain_id=chain.chain_id)
        start = self._clock()
        try:
            self._run_chain(chain, artifact, opts, result)
        except Exception as exc:  # isolate chains: record and continue
            if result.status == "pending":
                result.status = "failed"
            kind = (
                type(exc).__name__
                if isinstance(exc, ReleaseError)
                else f"unexpected {type(exc).__name__}"
            )
            result.error = self.redactor(f"{kind}: {exc}")
            self.log.error(result.error.splitlines()[0], chain=chain.name, event="chain_failed")
        finally:
            result.duration_s = round(self._clock() - start, 2)
        return result

    def _run_chain(
        self, chain: Chain, artifact: dict[str, Any], opts: ReleaseOptions, r: ChainResult
    ) -> None:
        p = self.profile
        info = lambda msg, **kw: self.log.info(msg, chain=chain.name, **kw)  # noqa: E731

        rpc_url = self.store.resolve(chain.rpc)
        self._check_transport(chain, rpc_url)
        rpc = self._rpc_factory(rpc_url)

        # 1. Chain identity: a misconfigured/compromised RPC must not trick us into signing
        #    for a different network (e.g. a mainnet tx while we believe we are on testnet).
        actual_id = rpc.chain_id()
        if actual_id != chain.chain_id:
            raise PreflightError(
                f"RPC reports chain id {actual_id}, expected {chain.chain_id}: refusing to sign"
            )

        # 2. Gas ceiling: never pay through a fee spike or a manipulated eth_gasPrice.
        gas_price = rpc.gas_price()
        if gas_price > int(chain.max_gas_price_gwei * GWEI):
            raise PreflightError(
                f"gas price {gas_price / GWEI:.3f} gwei exceeds ceiling "
                f"{chain.max_gas_price_gwei} gwei"
            )
        info(
            f"preflight ok: chain id {actual_id}, gas {gas_price / GWEI:.3f} gwei",
            event="preflight",
        )

        # 3. Simulation against live state: predicted address, deployer, idempotency.
        sim = self._script(chain, rpc_url, broadcast=False)
        r.address, r.deployer = sim["vault"], sim["deployer"]
        self._check_pinned_deployer(r.deployer)

        if sim["alreadyDeployed"]:
            r.status = "already_deployed"
            info(f"already deployed at {r.address} - nothing to broadcast", event="skip_existing")
        else:
            balance = rpc.balance(r.deployer)
            required = int(chain.min_balance_eth * WEI_PER_ETH)
            if balance < required:
                raise PreflightError(
                    f"deployer {r.deployer} balance {balance / WEI_PER_ETH:.6f} ETH "
                    f"< required {chain.min_balance_eth} ETH"
                )
            info(f"simulation ok: CREATE2 -> {r.address}", event="simulated")
            if opts.dry_run:
                r.status = "simulated"
                return

            broadcast_started = time.time()
            out = self._script(chain, rpc_url, broadcast=True)
            if out["vault"].lower() != r.address.lower():
                raise VerificationError(
                    f"broadcast produced {out['vault']}, simulation predicted {r.address}"
                )
            r.tx_hash = self._broadcast_tx_hash(chain, r.address, broadcast_started)
            receipt = self._await_finality(rpc, chain, r.tx_hash)
            r.status = "deployed"
            r.block_number = int(receipt["blockNumber"], 16)
            r.block_hash = receipt["blockHash"]
            r.gas_used = int(receipt["gasUsed"], 16)
            r.effective_gas_price_wei = int(receipt.get("effectiveGasPrice", "0x0"), 16)
            r.cost_wei = r.gas_used * r.effective_gas_price_wei
            info(
                f"deployed in block {r.block_number} tx {r.tx_hash} "
                f"({r.gas_used} gas, {chain.confirmations} confirmations)",
                event="deployed",
                tx_hash=r.tx_hash,
            )

        # 4. What is live must be exactly what was compiled, tested and scanned.
        code = rpc.code(r.address)
        ok, reason = runtime_code_matches(code, artifact)
        r.bytecode_verified = ok
        r.runtime_code_sha256 = sha256_hex(to_bytes(code)) if code not in ("", "0x") else None
        if not ok:
            raise VerificationError(reason)
        owner = _decode_address(rpc.eth_call(r.address, OWNER_SELECTOR))
        r.owner_verified = owner.lower() == p.owner.lower()
        if not r.owner_verified:
            raise VerificationError(f"owner() is {owner}, expected {p.owner}")
        info("on-chain verification ok: runtime bytecode + owner match", event="verified_onchain")

        # 5. Public source verification so anyone can audit what was deployed.
        if p.verify_explorer and not opts.dry_run:
            if opts.skip_explorer:
                r.warnings.append("explorer verification skipped (--skip-explorer)")
            else:
                self._verify_on_explorer(chain, r, sim["constructorArgs"])

    # ------------------------------------------------------------------ helpers

    def _check_transport(self, chain: Chain, url: str) -> None:
        if url.startswith("http://") and chain.chain_id not in guardrails.LOCAL_CHAIN_IDS:
            raise PreflightError("refusing plaintext http:// RPC for a public chain")

    def _script(self, chain: Chain, rpc_url: str, *, broadcast: bool) -> dict[str, Any]:
        rel, p = self.config.release, self.profile
        out_rel = Path("release-out") / f"{chain.name}.json"
        out_abs = self.foundry.root / out_rel
        out_abs.parent.mkdir(parents=True, exist_ok=True)
        out_abs.unlink(missing_ok=True)  # never read a stale result

        env = {
            **self.signer.env(),
            "RELEASE_OWNER": p.owner,
            "RELEASE_SALT": rel.salt,
            "RELEASE_OUTPUT": out_rel.as_posix(),
        }
        if p.expected_deployer:
            env["EXPECTED_DEPLOYER"] = p.expected_deployer
        self.foundry.run_script(
            rel.script,
            rpc_url=rpc_url,
            wallet_args=self.signer.wallet_args(),
            env=env,
            broadcast=broadcast,
            chain=chain.name,
        )
        try:
            data = json.loads(out_abs.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise VerificationError("deploy script did not write its result file") from None
        if int(data["chainId"]) != chain.chain_id:
            raise PreflightError(
                f"script executed on chain {data['chainId']}, expected {chain.chain_id}"
            )
        return data

    def _broadcast_tx_hash(self, chain: Chain, address: str, since: float) -> str:
        path = self.foundry.broadcast_log(self.config.release.script_path, chain.chain_id)
        if not path.exists() or path.stat().st_mtime < since - 2:
            raise VerificationError(f"no fresh broadcast log at {path.name}")
        data = json.loads(path.read_text(encoding="utf-8"))
        for tx in data.get("transactions", []):
            if (
                tx.get("transactionType") in ("CREATE2", "CREATE")
                and (tx.get("contractAddress") or "").lower() == address.lower()
            ):
                return tx["hash"]
        raise VerificationError("deployment transaction not found in broadcast log")

    def _await_finality(self, rpc: RpcClient, chain: Chain, tx_hash: str) -> dict[str, Any]:
        deadline = self._clock() + self._confirmation_timeout
        while True:
            receipt = rpc.receipt(tx_hash)
            if receipt:
                if int(receipt["status"], 16) != 1:
                    raise VerificationError(f"deployment transaction {tx_hash} reverted")
                mined = int(receipt["blockNumber"], 16)
                if rpc.block_number() - mined + 1 >= chain.confirmations:
                    confirmed = rpc.receipt(tx_hash)
                    if confirmed and confirmed["blockHash"] == receipt["blockHash"]:
                        return confirmed
                    self.log.warning(
                        "reorg detected while confirming; waiting again", chain=chain.name
                    )
            if self._clock() > deadline:
                raise VerificationError(
                    f"timed out waiting for {chain.confirmations} confirmations"
                )
            self._sleep(self._poll)

    def _verify_on_explorer(self, chain: Chain, r: ChainResult, constructor_args: str) -> None:
        # Explicit check, not `assert`: asserts vanish under `python -O`.
        if not (chain.explorer and self.profile.etherscan_api_key and r.address):
            raise ConfigError(f"{chain.name}: explorer verification is not configured")
        r.explorer_url = f"{chain.explorer.rstrip('/')}/address/{r.address}#code"
        try:
            api_key = self.store.resolve(self.profile.etherscan_api_key)
            explorer = self._explorer_factory(api_key)
            if explorer.is_verified(chain.chain_id, r.address):
                r.explorer_verified = True
                self.log.info("source already verified on explorer", chain=chain.name)
                return
            self.foundry.verify_contract(
                address=r.address,
                contract=self.config.release.contract,
                chain_id=chain.chain_id,
                constructor_args=constructor_args,
                api_key=api_key,
                chain=chain.name,
            )
            for _ in range(6):  # explorer indexing lags behind the verification receipt
                if explorer.is_verified(chain.chain_id, r.address):
                    r.explorer_verified = True
                    self.log.info(
                        f"source verified: {r.explorer_url}",
                        chain=chain.name,
                        event="explorer_verified",
                    )
                    return
                self._sleep(self._explorer_poll)
            raise VerificationError("explorer still reports unverified source")
        except ReleaseError:
            r.explorer_verified = False
            raise

    def _publish_ci_outputs(self, manifest: dict[str, Any], paths: dict[str, Path]) -> None:
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            with open(summary_file, "a", encoding="utf-8") as fh:
                fh.write(paths["summary"].read_text(encoding="utf-8"))
        output_file = os.environ.get("GITHUB_OUTPUT")
        if output_file:
            with open(output_file, "a", encoding="utf-8") as fh:
                fh.write(f"manifest={paths['manifest']}\n")
                fh.write(f"success={str(manifest['success']).lower()}\n")
                fh.write(f"address={manifest['deterministic_address'] or ''}\n")

    # ================================================================== audit (drift detection)

    def audit(self) -> dict[str, Any]:
        """Re-check live state against the last recorded release: code, owner, explorer."""
        latest = self.config.deployments_dir / self.profile.name / "latest.json"
        try:
            manifest = json.loads(latest.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(
                f"no release recorded for profile '{self.profile.name}' ({latest})"
            ) from None

        chains = {c.name: c for c in self.profile.chains}
        checks: list[dict[str, Any]] = []
        for record in manifest["deployments"]:
            chain = chains.get(record["chain"])
            if chain is None or not record.get("address") or not record.get("runtime_code_sha256"):
                continue
            check: dict[str, Any] = {
                "chain": chain.name,
                "address": record["address"],
                "issues": [],
            }
            try:
                rpc = self._rpc_factory(self.store.resolve(chain.rpc))
                if rpc.chain_id() != chain.chain_id:
                    check["issues"].append("RPC chain id mismatch")
                code = rpc.code(record["address"])
                if code in ("", "0x"):
                    check["issues"].append("contract code is gone")
                elif sha256_hex(to_bytes(code)) != record["runtime_code_sha256"]:
                    check["issues"].append("runtime code changed since release")
                else:
                    owner = _decode_address(rpc.eth_call(record["address"], OWNER_SELECTOR))
                    check["owner"] = owner
                    if owner.lower() != manifest["owner"].lower():
                        check["issues"].append(
                            f"OWNER DRIFT: {owner} != released owner {manifest['owner']}"
                        )
                    check["paused"] = int(rpc.eth_call(record["address"], PAUSED_SELECTOR), 16) == 1
            except ReleaseError as exc:
                check["issues"].append(self.redactor(f"check failed: {exc}"))
            level = "error" if check["issues"] else "info"
            self.log.event(
                level, "; ".join(check["issues"]) or "no drift", chain=chain.name, event="audit"
            )
            checks.append(check)

        report = {
            "profile": self.profile.name,
            "release": manifest["release"],
            "checked_at": utcnow(),
            "ok": bool(checks) and all(not c["issues"] for c in checks),
            "checks": checks,
        }
        return report
