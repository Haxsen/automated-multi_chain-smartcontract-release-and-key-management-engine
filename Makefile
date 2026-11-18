# Everything runs in pinned containers: the only host requirement is Docker.
SHELL := /bin/bash
.DEFAULT_GOAL := help

FOUNDRY_IMAGE  := ghcr.io/foundry-rs/foundry:v1.9.0@sha256:3a392c18f9b16e665e932de159fb6fa9ed972c4b4352f2f76a1a8c7ca9b57d39
PYTHON_IMAGE   := python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
CONFTEST_IMAGE := openpolicyagent/conftest@sha256:0e77cdf7c1fcde035f3c579e4aaa6664ee2a8be5777eaa9af9f520cdd02280c0
TF_IMAGE       := hashicorp/terraform@sha256:6e9c1e647c31a960dc9b59e13272f9111d90010c10b717f77ffb324767660475
CHECKOV_IMAGE  := bridgecrew/checkov@sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b
GITLEAKS_IMAGE := zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
ZIZMOR_IMAGE   := ghcr.io/zizmorcore/zizmor@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d
ACTIONLINT_IMAGE := rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

RUN := docker run --rm -v "$(CURDIR):/repo" -w /repo
FORGE := docker run --rm -v "$(CURDIR)/contracts:/app" -w /app --entrypoint forge $(FOUNDRY_IMAGE)

export RUNNER_UID ?= $(shell id -u)
export RUNNER_GID ?= $(shell id -g)

PROFILE ?= local

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ───────────────────────────── demo ──────────────────────────────────────────
.PHONY: demo
demo: ## Local demo: 3 chains -> deploy -> verify -> idempotent re-run -> drift audit
	docker compose up --build --detach --wait anvil-l1 anvil-arb anvil-op
	docker compose run --rm --no-deps release plan --profile local --out deployments/local/plan.json
	$(RUN) $(CONFTEST_IMAGE) test --policy policy/release --namespace release deployments/local/plan.json
	docker compose run --rm --no-deps release release --profile local
	docker compose run --rm --no-deps release release --profile local
	docker compose run --rm --no-deps release audit --profile local
	docker compose down

# ───────────────────────────── tests ─────────────────────────────────────────
.PHONY: test test-contracts test-engine test-policy
test: test-contracts test-engine test-policy ## Run every test suite

test-contracts: ## Foundry unit, fuzz and invariant tests (CI profile)
	docker run --rm -e FOUNDRY_PROFILE=ci -v "$(CURDIR)/contracts:/app" -w /app --entrypoint forge $(FOUNDRY_IMAGE) test

test-engine: ## Python engine: ruff + pytest
	$(RUN) -w /repo/engine $(PYTHON_IMAGE) sh -c "pip install -q --root-user-action=ignore --require-hashes -r requirements-dev.lock \
		&& ruff check release_engine tests && ruff format --check release_engine tests && python -m pytest -p no:cacheprovider"

test-policy: ## OPA policy unit tests + Terraform policy check
	$(RUN) $(CONFTEST_IMAGE) verify --policy policy/terraform --policy policy/release
	$(RUN) $(CONFTEST_IMAGE) test --parser hcl2 --policy policy/terraform --namespace terraform infra/terraform/

# ───────────────────────────── lint & scan ───────────────────────────────────
.PHONY: lint scan
lint: ## Formatting + linters (forge, terraform, workflows)
	$(FORGE) fmt --check
	$(FORGE) lint -D warnings
	$(RUN) -w /repo/infra/terraform $(TF_IMAGE) fmt -check -recursive
	$(RUN) $(ACTIONLINT_IMAGE)
	$(RUN) $(ZIZMOR_IMAGE) --offline --min-severity low .github/workflows

scan: ## Security scanners: gitleaks, checkov (+ slither if installed)
	$(RUN) $(GITLEAKS_IMAGE) git --config .gitleaks.toml --redact --no-banner .
	$(RUN) $(CHECKOV_IMAGE) -d /repo/infra/terraform --framework terraform --compact --quiet
	@if command -v slither >/dev/null; then cd contracts && slither . --config-file slither.config.json; \
	 else echo "slither not installed - it runs in CI (crytic/slither-action)"; fi

# ───────────────────────────── engine ────────────────────────────────────────
.PHONY: plan
plan: ## Emit the release plan for PROFILE (default: local)
	docker compose run --rm --no-deps release plan --profile $(PROFILE)

.PHONY: clean
clean: ## Remove build output and local demo records
	rm -rf contracts/out contracts/cache contracts/broadcast contracts/release-out deployments/local
	docker compose down --volumes --remove-orphans 2>/dev/null || true
