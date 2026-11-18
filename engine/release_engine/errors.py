"""Exception hierarchy. Every message must be safe to log (it is redacted anyway)."""


class ReleaseError(Exception):
    """Base class for all engine errors."""


class ConfigError(ReleaseError):
    """release.toml is invalid or a required environment variable is missing."""


class PolicyViolation(ReleaseError):
    """A guardrail refused the release plan."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__("; ".join(violations))


class SecretError(ReleaseError):
    """A secret could not be resolved from the configured secret source."""


class PreflightError(ReleaseError):
    """A pre-signing safety check failed. Nothing was broadcast."""


class ToolError(ReleaseError):
    """forge / cast / git exited unsuccessfully."""


class RpcError(ReleaseError):
    """JSON-RPC transport or node error."""


class VerificationError(ReleaseError):
    """Post-deployment verification failed (bytecode, owner or explorer)."""
