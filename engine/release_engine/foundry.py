"""Thin, secret-safe wrapper around the forge / cast CLIs.

Hard rules enforced here:
  * secrets are passed to child processes through environment variables, never argv
    (argv is world-readable via /proc/<pid>/cmdline and is echoed by many CI tools);
  * the child environment is scrubbed of engine-managed secrets it was not explicitly given;
  * all child output is redacted before it is logged or attached to an error.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from release_engine.errors import ToolError
from release_engine.logger import ReleaseLogger
from release_engine.redact import Redactor

# Variables the engine owns. They are stripped from the inherited environment and only
# re-added for the specific child process that needs them.
SENSITIVE_ENV = frozenset(
    {
        "DEPLOYER_PRIVATE_KEY",
        "PRIVATE_KEY",
        "ETH_PRIVATE_KEY",
        "RELEASE_RPC_URL",
        "ETH_RPC_URL",
        "ETHERSCAN_API_KEY",
        "AWS_KMS_KEY_ID",
        "ETH_KEYSTORE",
        "ETH_PASSWORD",
        "ETH_FROM",
    }
)


class Foundry:
    def __init__(
        self,
        root: Path,
        redactor: Redactor,
        log: ReleaseLogger,
        forge: str = "forge",
        cast: str = "cast",
        base_env: Mapping[str, str] | None = None,
        timeout: float = 900.0,
    ):
        self.root = root
        self._redact = redactor
        self._log = log
        self._forge = forge
        self._cast = cast
        self._base_env = dict(os.environ if base_env is None else base_env)
        self._timeout = timeout

    # ------------------------------------------------------------------ process plumbing

    def child_env(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = {k: v for k, v in self._base_env.items() if k not in SENSITIVE_ENV}
        env["NO_COLOR"] = "1"
        env["FOUNDRY_DISABLE_NIGHTLY_WARNING"] = "1"
        if extra:
            env.update(extra)
        return env

    def run(
        self,
        args: list[str],
        env: Mapping[str, str] | None = None,
        label: str = "",
        chain: str | None = None,
    ) -> str:
        """Run a tool, streaming redacted output to the debug log. Returns full redacted output."""
        self._log.debug(f"exec {args[0]} {args[1] if len(args) > 1 else ''}", chain=chain)
        try:
            proc = subprocess.Popen(
                args,
                cwd=self.root,
                env=self.child_env(env),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            raise ToolError(
                f"{args[0]} not found on PATH (install Foundry: getfoundry.sh)"
            ) from None

        timer = threading.Timer(self._timeout, proc.kill)
        timer.start()
        lines: list[str] = []
        tail: deque[str] = deque(maxlen=25)
        try:
            if proc.stdout is None:  # pragma: no cover - PIPE always yields a stream
                raise ToolError(f"{args[0]}: no output stream")
            for raw in proc.stdout:
                line = self._redact(raw.rstrip())
                lines.append(line)
                tail.append(line)
                if line.strip():
                    self._log.debug(line, chain=chain, tool=args[0])
            code = proc.wait()
        finally:
            timer.cancel()
        if code != 0:
            what = label or " ".join(args[:2])
            raise ToolError(f"{what} failed (exit {code}):\n" + "\n".join(tail))
        return "\n".join(lines)

    # ------------------------------------------------------------------ forge

    def build(self) -> None:
        self.run([self._forge, "build"], label="forge build")

    def artifact(self, contract_path: str, contract_name: str) -> dict[str, Any]:
        path = self.root / "out" / Path(contract_path).name / f"{contract_name}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ToolError(f"artifact {path} not found - run forge build") from None

    def run_script(
        self,
        script: str,
        *,
        rpc_url: str,
        wallet_args: list[str],
        env: Mapping[str, str],
        broadcast: bool,
        chain: str,
    ) -> str:
        args = [self._forge, "script", script, "--rpc-url", "release", "--non-interactive"]
        if broadcast:
            args.append("--broadcast")
        args += wallet_args
        full_env = {"RELEASE_RPC_URL": rpc_url, **env}
        label = f"forge script ({'broadcast' if broadcast else 'simulation'})"
        return self.run(args, env=full_env, label=label, chain=chain)

    def broadcast_log(self, script_path: str, chain_id: int) -> Path:
        return self.root / "broadcast" / Path(script_path).name / str(chain_id) / "run-latest.json"

    def verify_contract(
        self,
        *,
        address: str,
        contract: str,
        chain_id: int,
        constructor_args: str,
        api_key: str,
        chain: str,
    ) -> str:
        args = [
            self._forge,
            "verify-contract",
            address,
            contract,
            "--chain",
            str(chain_id),
            "--verifier",
            "etherscan",
            "--constructor-args",
            constructor_args,
            "--watch",
            "--retries",
            "10",
            "--delay",
            "10",
        ]
        return self.run(
            args, env={"ETHERSCAN_API_KEY": api_key}, label="forge verify-contract", chain=chain
        )

    # ------------------------------------------------------------------ cast

    def wallet_address(self, wallet_args: list[str], env: Mapping[str, str] | None = None) -> str:
        out = self.run(
            [self._cast, "wallet", "address", *wallet_args], env=env, label="cast wallet address"
        )
        address = out.strip().splitlines()[-1].strip() if out.strip() else ""
        if not (address.startswith("0x") and len(address) == 42):
            raise ToolError("cast wallet address returned an unexpected value")
        return address
