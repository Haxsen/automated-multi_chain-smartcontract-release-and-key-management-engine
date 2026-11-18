# Threat model

**Asset:** the authority to put bytecode on Ethereum, Arbitrum and Optimism under the
project's name, i.e. the deployer key and everything that can make it sign.

**Trust boundaries:** developer laptop → GitHub (repo, Actions, Environments) → AWS (STS,
KMS, Secrets Manager, S3) → RPC providers → chains and block explorers.

## Threats and controls

| # | Threat | Controls | Where |
|---|---|---|---|
| T1 | **Deployer key exfiltrated** from a laptop, CI log, env dump, Docker layer or the repo | The key is generated inside AWS KMS HSMs and is **non-exportable**, so there is nothing to steal. The engine never sees key material: forge asks KMS to sign (`--aws`). A Ledger is the manual alternative. | [kms.tf](../infra/terraform/kms.tf), [signers.py](../engine/release_engine/signers.py) |
| T2 | **Malicious workflow run signs a transaction** (compromised PR, fork, stolen PAT, workflow edit) | OIDC trust is pinned to `repo:<owner>/<repo>:environment:<env>` with an exact match. The Environment requires reviewers and tag-only refs. Fork PRs never get `id-token`. The key policy explicitly **denies `kms:Sign` to every principal except the release role**. The CI gate runs before release. | [iam.tf](../infra/terraform/iam.tf), [release.yml](../.github/workflows/release.yml) |
| T3 | **Signing for the wrong network**: a misconfigured or malicious RPC makes a "testnet" run sign a mainnet transaction | `eth_chainId` must equal the configured chain id before anything is signed. The deploy script re-checks `block.chainid`. EIP-155 binds every signature to its chain. Plaintext `http://` RPC is refused for public chains. | [engine.py](../engine/release_engine/engine.py) |
| T4 | **Bytecode substitution**: what is live differs from what was reviewed | Built in CI from a clean, tagged tree. The live runtime code is compared byte-for-byte with the compiled artifact (immutables masked). `owner()` is checked. Source is verified on Etherscan. LF line endings are enforced, so builds are deterministic across OSes. | [bytecode.py](../engine/release_engine/bytecode.py), [.gitattributes](../.gitattributes) |
| T5 | **Supply-chain compromise** of an action, tool image, Python package, provider or library | Actions are pinned by commit SHA and images by digest. Python installs use `pip --require-hashes`. The Terraform lockfile covers 4 platforms. forge-std is a pinned submodule. The engine core is stdlib-only. Dependabot proposes updates, harden-runner audits egress, and zizmor/actionlint check the workflows. | workflows, [requirements-*.lock](../engine) |
| T6 | **Secrets leak through logs** (RPC URLs embed provider keys) | Every resolved secret is registered with a redactor, which masks it in all output, the JSONL log and the manifest, and emits `::add-mask::`. Secrets go to child processes via env, never argv. Inherited env is scrubbed. Tests assert that no secret reaches logs or artifacts. | [redact.py](../engine/release_engine/redact.py), [foundry.py](../engine/release_engine/foundry.py) |
| T7 | **Humans read production secrets** | The Secrets Manager resource policy denies `GetSecretValue` to everyone except the release role, so the secret is write-only for humans. Changes to it raise an alert. | [secrets.tf](../infra/terraform/secrets.tf) |
| T8 | **Insider abuse of KMS** (admin adds a grant or policy to sign) | Key admins have no `Sign`. An explicit Deny covers `Sign`/`CreateGrant` for other principals. EventBridge alerts on `PutKeyPolicy`, `CreateGrant`, `DisableKey`, `ScheduleKeyDeletion` and alias changes, and on IAM changes to the release role. | [kms.tf](../infra/terraform/kms.tf), [monitoring.tf](../infra/terraform/monitoring.tf) |
| T9 | **CREATE2 address squatting / front-running** | The init code contains the owner, so anyone replaying it can only deploy *our* contract owned by *our* multisig. A different owner gives a different address (tested). | [Deploy.t.sol](../contracts/test/Deploy.t.sol) |
| T10 | **Fee spikes or manipulated gas price** | A per-chain gas price ceiling, a minimum balance check, and a deployer funded only for the next release. | [release.toml](../release.toml) |
| T11 | **Partial multi-chain release** / nonce races | Per-chain isolation. Idempotent CREATE2 re-runs finish only what is missing. One release per environment (`concurrency`). | [engine.py](../engine/release_engine/engine.py) |
| T12 | **Reorg drops the deployment** | Waits N confirmations, then re-reads the receipt and requires the same `blockHash`. | [engine.py](../engine/release_engine/engine.py) |
| T13 | **Deployment records rewritten** to hide a malicious release | The manifest has a sha256 and a Sigstore keyless signature bound to the workflow identity. It is stored in S3 Object Lock (WORM) and recorded through a reviewed PR. | [release.yml](../.github/workflows/release.yml), [ledger.tf](../infra/terraform/ledger.tf) |
| T14 | **Post-deploy admin takeover** (multisig compromise, unexpected transfer) | Daily drift audit of code hash, `owner()` and `paused()`, which opens an incident issue on drift. Two-step ownership transfer. | [drift.yml](../.github/workflows/drift.yml) |
| T15 | **Dev shortcuts reach production** (hot key, local chain, dirty tree) | Python guardrails *and* OPA policy, both evaluated before any credential is issued. | [guardrails.py](../engine/release_engine/guardrails.py), [release.rego](../policy/release/release.rego) |

## Residual risks (known, accepted, documented)

- **Digest signing is broad.** `kms:Sign` with `MessageType=DIGEST` can sign *any* 32-byte
  digest, so a fully compromised release session could sign an arbitrary transaction from the
  deployer address. Blast radius is bounded by design: the deployer owns nothing (admin is a
  multisig), holds only gas money, sessions last at most 1 h, and every `Sign` raises an alert.
- **Single RPC per chain.** A malicious RPC could lie about state. Bytecode and owner checks
  limit the damage, but they read through the same RPC. For mainnet, cross-check through a
  second provider, e.g. the drift audit's independent read-only keys.
- **CloudTrail is a prerequisite** for the EventBridge alerts (normally an org-wide trail).
- **`GOVERNANCE` lock mode** (the default, so the demo can be torn down) can be bypassed by a
  privileged principal. Use `COMPLIANCE` for production.
- **harden-runner runs in `audit` mode.** Switch to `block` with an allow-list once the
  egress baseline is known.
- **SafeVault is a demo artifact.** It is tested (unit, fuzz, invariants, Slither) but not
  audited.
