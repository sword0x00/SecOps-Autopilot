"""Typed errors used across the engine.

Connector failures are deliberately distinguishable: an authentication failure
must stop a run, while a missing optional scope (for example agent inventory)
must degrade to an explicit ``unknown`` instead of failing the whole pipeline.
"""


class SecOpsError(Exception):
    """Base class for all engine errors."""


class ConfigError(SecOpsError):
    """Configuration is missing or invalid."""


class IntakeError(SecOpsError):
    """The vulnerability input could not be normalized."""


class ConnectorError(SecOpsError):
    """An external system could not be queried."""


class AuthError(ConnectorError):
    """Credentials were rejected."""


class ScopeError(ConnectorError):
    """The credential is valid but lacks the scope for this endpoint."""


class NotFoundError(ConnectorError):
    """The requested object does not exist."""


class RateLimitError(ConnectorError):
    """The remote system asked us to slow down."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ConflictError(ConnectorError):
    """The remote system reported a conflict (for example, an active export)."""

    def __init__(self, message: str, payload: dict | None = None):
        super().__init__(message)
        self.payload = payload or {}


class ExportError(ConnectorError):
    """A Tenable asynchronous export failed or timed out."""


class ApprovalError(SecOpsError):
    """A state-changing action was attempted without a valid approval."""


class StateError(SecOpsError):
    """The run is not in a state that permits the requested transition."""


class EvidenceError(SecOpsError):
    """An evidence artifact is missing or failed integrity verification."""
