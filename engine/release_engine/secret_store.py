"""Runtime secret resolution.

A profile uses exactly one secret source - never a silent fallback chain - so it is always
auditable where a value came from:

* ``secrets = "env"``            local development: read process environment variables
* ``secrets = "aws:<secret-id>"`` CI: one AWS Secrets Manager secret holding a JSON object,
                                   fetched with short-lived OIDC credentials

Every value returned is registered with the Redactor before it is handed out.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import Any

from release_engine.config import SECRET_PREFIX
from release_engine.errors import SecretError
from release_engine.redact import Redactor


class SecretStore(ABC):
    source: str = "unknown"

    def __init__(self, redactor: Redactor):
        self._redactor = redactor

    @abstractmethod
    def _fetch(self, name: str) -> str | None: ...

    def get(self, name: str) -> str:
        value = self._fetch(name)
        if not value:
            raise SecretError(f"secret {name!r} not found in {self.source}")
        self._redactor.register(value)
        return value

    def resolve(self, value: str) -> str:
        """Return literal values unchanged; resolve ``secret:NAME`` references."""
        if value.startswith(SECRET_PREFIX):
            return self.get(value[len(SECRET_PREFIX) :])
        return value


class EnvSecretStore(SecretStore):
    source = "environment"

    def __init__(self, redactor: Redactor, env: Mapping[str, str] | None = None):
        super().__init__(redactor)
        self._env = os.environ if env is None else env

    def _fetch(self, name: str) -> str | None:
        return self._env.get(name)


class AwsSecretsManagerStore(SecretStore):
    source = "aws-secretsmanager"

    def __init__(
        self,
        redactor: Redactor,
        secret_id: str,
        client_factory: Callable[[], Any] | None = None,
    ):
        super().__init__(redactor)
        self.secret_id = secret_id
        self._client_factory = client_factory or _default_client
        self._cache: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._cache is None:
            try:
                response = self._client_factory().get_secret_value(SecretId=self.secret_id)
            except Exception as exc:  # botocore raises many types; never echo request details
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
                raise SecretError(
                    f"cannot read {self.secret_id!r} from Secrets Manager: {code}"
                ) from None
            try:
                payload = json.loads(response["SecretString"])
            except (KeyError, json.JSONDecodeError):
                raise SecretError(f"{self.secret_id!r} must be a JSON object of strings") from None
            if not isinstance(payload, dict):
                raise SecretError(f"{self.secret_id!r} must be a JSON object of strings")
            self._cache = {str(k): str(v) for k, v in payload.items()}
            for value in self._cache.values():  # mask everything in the bundle up front
                self._redactor.register(value)
        return self._cache

    def _fetch(self, name: str) -> str | None:
        return self._load().get(name)


def _default_client() -> Any:
    try:
        import boto3
    except ImportError:
        raise SecretError(
            "boto3 is required for AWS Secrets Manager: pip install 'release-engine[aws]'"
        ) from None
    return boto3.client("secretsmanager")


def build_secret_store(
    spec: str, redactor: Redactor, env: Mapping[str, str] | None = None
) -> SecretStore:
    if spec == "env":
        return EnvSecretStore(redactor, env)
    if spec.startswith("aws:"):
        return AwsSecretsManagerStore(redactor, spec[4:])
    raise SecretError(f"unsupported secret source {spec!r}")
