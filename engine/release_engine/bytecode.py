"""On-chain bytecode integrity: what is live must be exactly what we compiled and tested."""

from __future__ import annotations

import hashlib
from typing import Any


def to_bytes(hex_str: str) -> bytes:
    hex_str = hex_str[2:] if hex_str.startswith(("0x", "0X")) else hex_str
    return bytes.fromhex(hex_str)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mask_immutables(code: bytes, immutable_refs: dict[str, list[dict[str, int]]] | None) -> bytes:
    """Zero out immutable slots: they are filled in by the constructor at deploy time."""
    if not immutable_refs:
        return code
    buf = bytearray(code)
    for refs in immutable_refs.values():
        for ref in refs:
            start, length = int(ref["start"]), int(ref["length"])
            buf[start : start + length] = b"\x00" * length
    return bytes(buf)


def runtime_code_matches(onchain_hex: str, artifact: dict[str, Any]) -> tuple[bool, str]:
    deployed = artifact.get("deployedBytecode") or {}
    expected = to_bytes(deployed.get("object", "0x"))
    actual = to_bytes(onchain_hex)
    if not actual:
        return False, "no code at address"
    if len(actual) != len(expected):
        return False, f"runtime size mismatch: on-chain {len(actual)} B, compiled {len(expected)} B"
    refs = deployed.get("immutableReferences")
    if mask_immutables(actual, refs) != mask_immutables(expected, refs):
        return False, "runtime bytecode differs from the compiled artifact"
    return True, "runtime bytecode matches compiled artifact"


def artifact_digests(artifact: dict[str, Any]) -> dict[str, str]:
    return {
        "creation_code_sha256": sha256_hex(to_bytes(artifact["bytecode"]["object"])),
        "runtime_code_sha256": sha256_hex(to_bytes(artifact["deployedBytecode"]["object"])),
    }


def compiler_version(artifact: dict[str, Any]) -> str | None:
    metadata = artifact.get("metadata")
    if isinstance(metadata, dict):
        return (metadata.get("compiler") or {}).get("version")
    return None
