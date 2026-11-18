# Operations runbook

## 1. First-time setup

```bash
# 1. Infrastructure (KMS keys, OIDC roles, secrets, ledger, alerts)
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # set github_repository, alert_email, ...
terraform init && terraform apply
terraform output github_environment_variables

# 2. Derive each deployer's EVM address from its KMS public key
AWS_KMS_KEY_ID=alias/web3-release-testnet-deployer cast wallet address --aws

# 3. Write the release secret (JSON). Humans can write it but cannot read it back.
aws secretsmanager put-secret-value --secret-id web3-release/testnet/config \
  --secret-string file://testnet-secret.json && shred -u testnet-secret.json
```

`testnet-secret.json` holds `SEPOLIA_RPC_URL`, `ARBITRUM_SEPOLIA_RPC_URL`,
`OPTIMISM_SEPOLIA_RPC_URL` and `ETHERSCAN_API_KEY`. One Etherscan V2 key covers every chain.

4. **GitHub → Settings → Environments**, create `testnet` and `mainnet`:
   - *Variables:* the Terraform output, plus `RELEASE_OWNER` (your Safe multisig) and
     `EXPECTED_DEPLOYER` (step 2).
   - *Protection:* required reviewers. For `mainnet`, also "Deployment branches and tags"
     set to tags `v*` only, with self-review prevented.
   - There are **no secrets** in these environments.
5. Create `testnet-audit` with *secrets* holding read-only RPC URLs (separate provider keys)
   and the same variables, with no reviewers. It powers the daily drift audit and cannot
   assume the release role.
6. Fund each deployer address with gas only (e.g. 0.05 ETH per testnet).
7. Settings → Actions → General: allow GitHub Actions to create pull requests (for the
   deployment-records PR).

## 2. Cutting a release

1. Bump `release.version` **and** `release.salt` in `release.toml` (policy enforces that the
   salt embeds the version) in a PR. CI runs the full gate, including a 3-chain e2e release.
2. Merge, then tag: `git tag -s v1.1.0 && git push origin v1.1.0`. This releases to testnet
   automatically (after `testnet` environment approval).
3. Mainnet: *Actions → release → Run workflow* on the tag, with `profile=mainnet`.
   Reviewers approve the `mainnet` environment, and only then can the job obtain AWS
   credentials.
4. Merge the auto-opened **"Deployment records"** PR.

Dry run: dispatch with `dry_run=true`. It simulates against live state and broadcasts
nothing.

## 3. Verifying a release record

```bash
sha256sum -c manifest.json.sha256
cosign verify-blob manifest.json \
  --bundle manifest.json.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/\.github/workflows/release\.yml@refs/tags/v'
```

The ledger copy lives at `s3://<bucket>/<profile>/<version>/<run-id>-<attempt>/` and is
immutable for `ledger_retention_days`.

## 4. A chain failed mid-release

Nothing needs to be rolled back. Every chain is independent and the CREATE2 address is
deterministic. Fix the cause (gas spike, RPC outage, low balance), then re-run the same
release: finished chains report `already_deployed` and are re-verified, and only the
missing chain is broadcast. To limit the run: `release-engine release --profile testnet
--chain arbitrum-sepolia` (this does not overwrite `latest.json`).

## 5. Rotating keys

| What | How | Effect on contracts |
|---|---|---|
| **Deployer (KMS)** | `terraform apply -replace='aws_kms_key.deployer["mainnet"]'`, derive the new address, update `EXPECTED_DEPLOYER`, fund it, sweep the old one, then let the old key's deletion window run. | **None.** CREATE2 addresses come from the factory, salt and init code, not the deployer, and the deployer owns nothing. |
| **RPC / Etherscan keys** | Rotate at the provider, then `aws secretsmanager put-secret-value`. | None |
| **Break-glass hot key** | Generate a new key, put it in the secret, sweep the old address. **Always** do this after any break-glass use. | None |

Asymmetric KMS keys cannot auto-rotate. Plan deployer rotation on a schedule (e.g. yearly)
or after any alert you cannot explain.

## 6. Incident: unexpected `Sign` / key tamper alert

1. **Contain:** `aws kms disable-key --key-id <arn>`. This blocks all signing immediately and
   is reversible.
2. Revoke live sessions: IAM → role `web3-release-<env>-release` → *Revoke active sessions*.
3. Disable the `release` workflow and lock the GitHub Environment (remove deployment refs).
4. Investigate: CloudTrail `kms:Sign` events (`userIdentity`, `sourceIPAddress`, role
   session name = `release-<run_id>-<attempt>`), then cross-check against Actions run
   history and the deployer's on-chain transactions.
5. Recover: rotate the deployer (section 5), then review OIDC trust, environment rules and
   workflow changes.

## 7. Incident: ownership drift (drift-audit issue)

1. Confirm on-chain: `cast call <vault> "owner()(address)" --rpc-url ...`.
2. If the transfer was not approved by the multisig signers, treat the multisig as
   compromised. Use the protocol's emergency procedure (pausing deposits is possible only
   while the owner is still yours) and follow your incident-response plan.
3. If it was approved, record it: release a new manifest, or document the change in the
   deployment-records PR, so the audit baseline matches reality.

## 8. Break-glass (KMS unavailable)

Use only for testnets (policy and guardrails refuse hot keys for `production` profiles):

1. Put `DEPLOYER_PRIVATE_KEY` into the testnet secret (write-only for humans).
2. Run the `testnet-break-glass` profile. OPA emits a warning and the key is masked
   everywhere.
3. Afterwards, remove the key from the secret and rotate (section 5).
