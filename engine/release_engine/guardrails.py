"""Built-in, non-bypassable guardrails evaluated on the release plan before any secret is read.

The same rules (plus more) are enforced as policy-as-code in ``policy/release/*.rego`` by an
OPA/conftest gate in CI. They are duplicated here on purpose: the engine must stay safe even
when run by hand, outside the pipeline.
"""

from __future__ import annotations

from typing import Any

# Chain ids of local dev networks (anvil/hardhat). Dev signers may only ever touch these.
LOCAL_CHAIN_IDS = frozenset({31337, 31338, 31339, 1337})
HARDWARE_BACKED_SIGNERS = frozenset({"kms", "ledger"})


def evaluate(plan: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    signer = plan["signer"]["type"]
    chains = plan["chains"]
    git = plan["git"]
    production = plan["production"]

    non_local = [c["name"] for c in chains if c["chain_id"] not in LOCAL_CHAIN_IDS]
    if signer == "anvil" and non_local:
        violations.append(f"anvil dev signer may only target local chains, not {non_local}")

    if plan["require_clean_git"] and git["dirty"] is not False:
        violations.append("working tree must be clean (commit or stash changes)")

    if plan["require_tag"]:
        expected_tag = f"v{plan['release']['version']}"
        if git["tag"] != expected_tag:
            violations.append(f"HEAD must be tagged {expected_tag} (found {git['tag']!r})")

    if production:
        if signer not in HARDWARE_BACKED_SIGNERS:
            violations.append(
                f"production requires a non-exportable key (kms/ledger), not {signer!r}"
            )
        if not plan["expected_deployer"]:
            violations.append("production requires expected_deployer (signer pinning)")
        elif plan["expected_deployer"].lower() == plan["owner"].lower():
            violations.append("deployer key must not be the contract owner (separation of duties)")
        if not plan["verify_explorer"]:
            violations.append("production requires explorer source verification")
        literal = [c["name"] for c in chains if c["rpc_source"] != "secret"]
        if literal:
            violations.append(
                f"production RPC endpoints must come from the secret store: {literal}"
            )
        local = [c["name"] for c in chains if c["chain_id"] in LOCAL_CHAIN_IDS]
        if local:
            violations.append(f"production profile must not include local chains: {local}")

    return violations
