"""Command line interface.

    release-engine profiles                       list profiles
    release-engine plan    --profile testnet      emit the policy-checkable plan (no secrets)
    release-engine release --profile testnet      deploy + verify across every chain in the profile
    release-engine audit   --profile testnet      drift detection against the last release

Exit codes: 0 success, 1 release/audit failure, 2 config or policy refusal, 130 interrupted.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

from release_engine import __version__, gitinfo, guardrails
from release_engine.config import Config, Profile, load_config
from release_engine.engine import ReleaseEngine, ReleaseOptions
from release_engine.errors import ConfigError, PolicyViolation, ReleaseError
from release_engine.foundry import Foundry
from release_engine.logger import ReleaseLogger
from release_engine.manifest import render_summary
from release_engine.redact import Redactor
from release_engine.secret_store import build_secret_store
from release_engine.signers import build_signer


def build_engine(
    config: Config, profile: Profile, redactor: Redactor, log: ReleaseLogger
) -> ReleaseEngine:
    store = build_secret_store(profile.secrets, redactor)
    return ReleaseEngine(
        config,
        profile,
        redactor=redactor,
        log=log,
        foundry=Foundry(
            config.foundry_root,
            redactor,
            log,
            forge=os.environ.get("FORGE_BIN", "forge"),
            cast=os.environ.get("CAST_BIN", "cast"),
        ),
        store=store,
        signer=build_signer(profile.signer, store),
        git=gitinfo.collect(config.root),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release-engine",
        description="Secure multi-chain smart contract release & key management engine.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        default=os.environ.get("RELEASE_CONFIG", "release.toml"),
        help="path to release.toml (default: ./release.toml or $RELEASE_CONFIG)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="stream forge/cast output")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("profiles", help="list release profiles")

    plan = sub.add_parser("plan", help="emit the release plan JSON for policy evaluation")
    plan.add_argument("--profile", required=True)
    plan.add_argument("--out", type=Path, help="write the plan here instead of stdout")

    rel = sub.add_parser("release", help="deploy and verify across all chains of a profile")
    rel.add_argument("--profile", required=True)
    rel.add_argument(
        "--chain", action="append", dest="chains", help="limit to chain(s); repeatable"
    )
    rel.add_argument("--dry-run", action="store_true", help="simulate only; broadcast nothing")
    rel.add_argument("--skip-explorer", action="store_true", help="skip Etherscan verification")
    rel.add_argument("--fail-fast", action="store_true", help="stop at the first failing chain")
    rel.add_argument("--skip-build", action="store_true", help="reuse existing forge artifacts")

    audit = sub.add_parser("audit", help="detect drift between live contracts and the last release")
    audit.add_argument("--profile", required=True)
    audit.add_argument("--out", type=Path, help="write the audit report JSON here")
    audit.add_argument(
        "--secrets",
        help="override the profile's secret source (e.g. 'env'). Audit only reads public chain "
        "state, so it can use low-privilege read-only RPC keys instead of the release secret. "
        "Deliberately not available for `release`.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    redactor = Redactor()
    log = ReleaseLogger(redactor, verbose=args.verbose)

    try:
        config = load_config(args.config)
        if args.command == "profiles":
            for name in config.profile_names():
                desc = config.raw_profiles[name].get("description", "")
                print(f"{name:<18} {desc}")
            return 0

        profile = config.load_profile(args.profile)
        if args.command == "audit" and args.secrets:
            profile = dataclasses.replace(profile, secrets=args.secrets)
        engine = build_engine(config, profile, redactor, log)

        if args.command == "plan":
            plan = engine.plan()
            plan["guardrail_violations"] = guardrails.evaluate(plan)
            text = json.dumps(plan, indent=2) + "\n"
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(text, encoding="utf-8")
                log.info(f"plan written to {args.out}")
            else:
                sys.stdout.write(text)
            if plan["guardrail_violations"]:
                raise PolicyViolation(plan["guardrail_violations"])
            return 0

        if args.command == "release":
            manifest, paths = engine.release(
                ReleaseOptions(
                    chains=args.chains,
                    dry_run=args.dry_run,
                    skip_explorer=args.skip_explorer,
                    fail_fast=args.fail_fast,
                    skip_build=args.skip_build,
                )
            )
            sys.stdout.write("\n" + render_summary(manifest))
            sys.stdout.write(f"\nmanifest: {paths['manifest']}\n")
            return 0 if manifest["success"] else 1

        if args.command == "audit":
            report = engine.audit()
            text = json.dumps(report, indent=2) + "\n"
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
            return 0 if report["ok"] else 1

    except PolicyViolation as exc:
        log.error("guardrails refused the release plan:")
        for violation in exc.violations:
            log.error(f"  - {violation}")
        return 2
    except ConfigError as exc:
        log.error(f"configuration error: {exc}")
        return 2
    except ReleaseError as exc:
        log.error(redactor(f"{type(exc).__name__}: {exc}"))
        return 1
    except OSError as exc:
        log.error(redactor(f"filesystem error: {exc}"))
        return 1
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130
    return 1
