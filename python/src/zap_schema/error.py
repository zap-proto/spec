"""ZAP error types."""


class ZapError(Exception):
    """Base ZAP error."""

    pass


class ConnectionError(ZapError):
    """Connection error."""

    pass


class ProtocolError(ZapError):
    """Protocol error."""

    pass


class ToolNotFoundError(ZapError):
    """Tool not found."""

    pass


class ResourceNotFoundError(ZapError):
    """Resource not found."""

    pass
