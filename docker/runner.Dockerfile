# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Hermetic release runner: pinned Foundry + pinned solc + hash-locked Python deps,
# running as an unprivileged user. Base images are pinned by digest (supply chain).
# ─────────────────────────────────────────────────────────────────────────────
FROM ghcr.io/foundry-rs/foundry:v1.10.0@sha256:03ca6dc0accb53b6f67278b5a1c70bef984d5a2a2bcb197298c3b6f3b929c798 AS foundry

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

LABEL org.opencontainers.image.title="release-engine-runner" \
      org.opencontainers.image.description="Multi-chain smart contract release & key management engine"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 # The workspace is bind-mounted with a different owner; git must still read provenance.
 && git config --system --add safe.directory '*'

COPY --from=foundry /usr/local/bin/forge /usr/local/bin/cast /usr/local/bin/anvil /usr/local/bin/

COPY engine/requirements-aws.lock /tmp/requirements-aws.lock
RUN pip install --no-cache-dir --require-hashes --root-user-action=ignore -r /tmp/requirements-aws.lock \
 && rm /tmp/requirements-aws.lock

COPY engine/release_engine /opt/engine/release_engine
ENV PYTHONPATH=/opt/engine \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELEASE_CONFIG=/workspace/release.toml

RUN groupadd --gid 10001 release && useradd --uid 10001 --gid 10001 --create-home release
USER release
# Fixed HOME so the image also works under an arbitrary --user uid (e.g. CI runners map
# the workspace owner's uid), which has no passwd entry and therefore no home directory.
ENV HOME=/home/release

# Pre-install the pinned solc so releases never download a compiler at deploy time.
COPY --chown=release:release contracts /tmp/warm
RUN cd /tmp/warm && forge build --quiet && rm -rf /tmp/warm \
 && chmod -R a+rX /home/release

WORKDIR /workspace
ENTRYPOINT ["python", "-m", "release_engine"]
CMD ["--help"]
