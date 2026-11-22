"""Immutable-ish state model for the simulated A/B device.

The device is a pure file simulation.  A :class:`DeviceState` value is a full
snapshot; every engine transition returns a new snapshot (implemented with
:func:`copy.deepcopy`) so that replay, cut enumeration and repair search can
share snapshots freely.

Persistence fiction
-------------------
Each marker listed on :class:`SlotState` and the monotonic counter are written
by *individual atomic operations*.  Nothing guarantees atomicity across
markers or across the counter and a marker -- the engine therefore models each
of them as its own micro-step where the update protocol separates them
(``switch_candidate`` / ``switch_confirm_health`` / ``counter_raise`` /
``switch_publish_active``).
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any

SLOT_IDS = ("A", "B")


def page_summary(pages: dict[str, str]) -> str:
    """Fictional page-summary witness over sorted ``(page_id, digest)`` pairs."""
    h = hashlib.sha256()
    for page_id in sorted(pages):
        h.update(page_id.encode("utf-8"))
        h.update(b"\x00")
        h.update(pages[page_id].encode("utf-8"))
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


@dataclass
class Manifest:
    """Signed candidate manifest (the fictional signing manifest)."""

    manifest_id: str
    version: int
    device_group: str
    authorized_generation: int
    pages: dict[str, str]  # page_id -> digest
    auth_id: str
    signer: str

    @property
    def page_ids(self) -> list[str]:
        return sorted(self.pages)

    def digest_witness(self) -> str:
        return page_summary(self.pages)


@dataclass
class Sector:
    sector_id: str
    pages: list[str]
    capacity: int  # full per-erase writable page budget


@dataclass
class SlotState:
    """Full persisted state of one A/B region."""

    slot_id: str
    generation: int = 0
    manifest_id: str | None = None
    written_pages: dict[str, str] = field(default_factory=dict)
    ready: bool = False
    sig_entry: dict[str, Any] | None = None
    candidate: bool = False
    active: bool = False
    trial: dict[str, Any] | None = None
    health: dict[str, Any] | None = None
    # Persisted write session for batching, crash resume and retry matching.
    session: dict[str, Any] | None = None
    # Page ids whose digest was re-read and matched during the current session.
    readback_verified: list[str] = field(default_factory=list)
    erase_count: int = 0

    def clone(self) -> "SlotState":
        return copy.deepcopy(self)

    # --- derived predicates -------------------------------------------------

    def manifest(self, case: "CaseConfig") -> Manifest | None:
        if self.manifest_id is None:
            return None
        return case.manifest_by_id.get(self.manifest_id)

    def is_complete(self, case: "CaseConfig") -> bool:
        """Every manifest page is present with the exact signed digest."""
        m = self.manifest(case)
        if m is None:
            return False
        if len(self.written_pages) != len(m.pages):
            return False
        for page_id, digest in m.pages.items():
            if self.written_pages.get(page_id) != digest:
                return False
        return True

    def is_signed_current(self, case: "CaseConfig", revoked: set[str]) -> bool:
        """Signature directory entry exists and is still authorized now."""
        m = self.manifest(case)
        if m is None or self.sig_entry is None:
            return False
        if m.manifest_id in revoked:
            return False
        if self.sig_entry.get("manifest_id") != m.manifest_id:
            return False
        if self.sig_entry.get("generation") != m.authorized_generation:
            return False
        if self.sig_entry.get("auth_id") != m.auth_id:
            return False
        if self.generation != m.authorized_generation:
            return False
        return True

    def trusted_complete(
        self, case: "CaseConfig", revoked: set[str]
    ) -> bool:
        """Full image, read back, READY and signed under a current authorization."""
        return bool(
            self.ready
            and self.sig_entry is not None
            and self.is_complete(case)
            and self.is_signed_current(case, revoked)
        )

    def formally_bootable(
        self, case: "CaseConfig", counter: int, revoked: set[str]
    ) -> bool:
        """A trusted complete copy at/above the counter floor, not in trial.

        A slot carrying the candidate marker is still inside the four-step
        switch and is not a published boot image until the active marker is
        written; it is therefore excluded even though its copy is trusted.
        """
        return (
            self.trusted_complete(case, revoked)
            and self.generation >= counter
            and self.trial is None
            and not self.candidate
        )


@dataclass
class DeviceState:
    slots: dict[str, SlotState]
    counter: int
    revoked_manifests: set[str]
    sector_budgets: dict[str, int]
    program_writes: int = 0

    def clone(self) -> "DeviceState":
        return copy.deepcopy(self)

    def other_slot(self, slot_id: str) -> SlotState:
        return self.slots["B" if slot_id == "A" else "A"]

    def canonical(self) -> str:
        """Deterministic JSON text used for state de-duplication."""
        import json

        payload = {
            "counter": self.counter,
            "revoked_manifests": sorted(self.revoked_manifests),
            "sector_budgets": dict(sorted(self.sector_budgets.items())),
            "program_writes": self.program_writes,
            "slots": [_slot_canonical(self.slots[s]) for s in SLOT_IDS],
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _slot_canonical(slot: SlotState) -> dict[str, Any]:
    return {
        "slot_id": slot.slot_id,
        "generation": slot.generation,
        "manifest_id": slot.manifest_id,
        "written_pages": dict(sorted(slot.written_pages.items())),
        "ready": slot.ready,
        "sig_entry": copy.deepcopy(slot.sig_entry),
        "candidate": slot.candidate,
        "active": slot.active,
        "trial": copy.deepcopy(slot.trial),
        "health": copy.deepcopy(slot.health),
        "session": copy.deepcopy(slot.session),
        "readback_verified": sorted(slot.readback_verified),
        "erase_count": slot.erase_count,
    }


@dataclass
class Policy:
    # "maintain": a still-trusted formal old image must stay serviceable when
    # the strategy can keep one; "halt_allowed": safe stop is an accepted end.
    fallback: str = "maintain"


@dataclass
class CaseConfig:
    schema_version: int
    case_id: str
    device_group: str
    policy: Policy
    max_power_losses: int
    sectors: list[Sector]
    manifests: list[Manifest]
    initial_state: DeviceState
    events: list[dict[str, Any]]
    manifest_by_id: dict[str, Manifest] = field(default_factory=dict)
    page_sector: dict[str, str] = field(default_factory=dict)
    repair_depth: int = 12
