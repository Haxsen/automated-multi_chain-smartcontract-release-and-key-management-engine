"""Deployment records: a signed-able JSON manifest, its digest, and a Markdown summary."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "release-engine/manifest/v1"
OK_STATUSES = frozenset({"deployed", "already_deployed", "simulated"})


@dataclass
class ChainResult:
    chain: str
    chain_id: int
    status: str = "pending"  # deployed | already_deployed | simulated | failed
    address: str | None = None
    deployer: str | None = None
    tx_hash: str | None = None
    block_number: int | None = None
    block_hash: str | None = None
    gas_used: int | None = None
    effective_gas_price_wei: int | None = None
    cost_wei: int | None = None
    bytecode_verified: bool | None = None
    runtime_code_sha256: str | None = None
    owner_verified: bool | None = None
    explorer_verified: bool | None = None
    explorer_url: str | None = None
    duration_s: float | None = None
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def succeeded(self, explorer_required: bool) -> bool:
        if self.status not in OK_STATUSES:
            return False
        if self.status == "simulated":
            return True
        if not (self.bytecode_verified and self.owner_verified):
            return False
        return self.explorer_verified is True or not explorer_required


def build_manifest(
    *,
    plan: dict[str, Any],
    artifact: dict[str, Any],
    results: list[ChainResult],
    started_at: str,
    finished_at: str,
    dry_run: bool,
) -> dict[str, Any]:
    explorer_required = plan["verify_explorer"]
    addresses = {r.address for r in results if r.address}
    return {
        "schema": MANIFEST_SCHEMA,
        "dry_run": dry_run,
        "success": all(r.succeeded(explorer_required) for r in results),
        "deterministic_address": addresses.pop() if len(addresses) == 1 else None,
        "release": plan["release"],
        "profile": plan["profile"],
        "production": plan["production"],
        "git": plan["git"],
        "signer": plan["signer"],
        "owner": plan["owner"],
        "artifact": artifact,
        "ci": {
            k: os.environ[k]
            for k in (
                "GITHUB_REPOSITORY",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
                "GITHUB_ACTOR",
                "GITHUB_WORKFLOW_REF",
            )
            if k in os.environ
        },
        "started_at": started_at,
        "finished_at": finished_at,
        "deployments": [asdict(r) for r in results],
    }


def write_json(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def write_release_outputs(
    out_dir: Path, manifest: dict[str, Any], latest: Path | None
) -> dict[str, Path]:
    """Write manifest + sha256 sidecar + summary. ``latest`` gets a copy for `audit`."""
    name = "manifest.dry-run.json" if manifest["dry_run"] else "manifest.json"
    manifest_path = write_json(out_dir / name, manifest)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    sha_path = manifest_path.with_name(manifest_path.name + ".sha256")
    sha_path.write_text(f"{digest}  {manifest_path.name}\n", encoding="utf-8")
    summary_path = out_dir / "summary.md"
    summary_path.write_text(render_summary(manifest), encoding="utf-8")
    if latest is not None and not manifest["dry_run"]:
        latest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(manifest_path, latest)
    return {"manifest": manifest_path, "sha256": sha_path, "summary": summary_path}


def _flag(value: bool | None) -> str:
    return {True: "✅", False: "❌", None: "—"}[value]


def render_summary(manifest: dict[str, Any]) -> str:
    rel = manifest["release"]
    git = manifest["git"]
    head = "✅ Release succeeded" if manifest["success"] else "❌ Release failed"
    if manifest["dry_run"]:
        head += " (dry run)"
    deployer = manifest["signer"].get("address") or next(
        (d["deployer"] for d in manifest["deployments"] if d.get("deployer")), "unknown"
    )
    lines = [
        f"## {head}: `{rel['name']}` v{rel['version']} → `{manifest['profile']}`",
        "",
        f"- **Signer:** `{manifest['signer']['type']}` `{deployer}`",
        f"- **Owner:** `{manifest['owner']}`",
        f"- **Commit:** `{(git.get('commit') or 'unknown')[:12]}` tag `{git.get('tag') or '—'}`",
        f"- **CREATE2 address:** `{manifest['deterministic_address'] or 'n/a'}`",
        f"- **Runtime code sha256:** `{manifest['artifact'].get('runtime_code_sha256', '')[:16]}…`",
        "",
        "| Chain | Status | Address | Tx | Gas used | Bytecode | Owner | Explorer |",
        "|---|---|---|---|---:|:-:|:-:|:-:|",
    ]
    for d in manifest["deployments"]:
        explorer = _flag(d["explorer_verified"])
        if d.get("explorer_url") and d["explorer_verified"]:
            explorer = f"[✅]({d['explorer_url']})"
        tx = f"`{d['tx_hash'][:10]}…`" if d.get("tx_hash") else "—"
        lines.append(
            f"| {d['chain']} ({d['chain_id']}) | {d['status']} | `{d['address'] or '—'}` | {tx} "
            f"| {d['gas_used'] or '—'} | {_flag(d['bytecode_verified'])} "
            f"| {_flag(d['owner_verified'])} | {explorer} |"
        )
    errors = [(d["chain"], d["error"]) for d in manifest["deployments"] if d.get("error")]
    if errors:
        lines += ["", "### Errors", ""]
        lines += [f"- **{chain}:** {err.splitlines()[0]}" for chain, err in errors]
    return "\n".join(lines) + "\n"
