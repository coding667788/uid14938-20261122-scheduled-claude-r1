"""Typed errors.

Every error that originates in user supplied case data carries a JSON-style
field path (``initial.slots.A.generation``) or an event index
(``events[3].manifest_id``) so failures can be located at a concrete field or
event.
"""

from __future__ import annotations

from typing import Any


class BootReplayError(Exception):
    """Base class for all package errors."""


class CaseError(BootReplayError):
    """The CASE.json document is malformed or semantically inconsistent.

    ``path`` is a JSON-style pointer to the offending field or event;
    ``detail`` explains the rule that was violated.
    """

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")

    def to_payload(self) -> dict[str, Any]:
        return {"error": "case_error", "path": self.path, "detail": self.detail}


class EventRejected(BootReplayError):
    """A log event is legal JSON but illegal against the current device state.

    Rejected events do not mutate state; the replay engine records them as
    ``rejected`` results instead of aborting the whole trace.
    """

    def __init__(self, reason: str, event_index: int | None = None) -> None:
        self.reason = reason
        self.event_index = event_index
        super().__init__(reason)


def require(condition: bool, path: str, detail: str) -> None:
    """Raise :class:`CaseError` with a field path when ``condition`` is false."""
    if not condition:
        raise CaseError(path, detail)


def require_type(value: Any, expected: type | tuple[type, ...], path: str) -> None:
    if not isinstance(value, expected):
        names = (
            ", ".join(t.__name__ for t in expected)
            if isinstance(expected, tuple)
            else expected.__name__
        )
        raise CaseError(path, f"expected {names}, got {type(value).__name__}")
