"""State transition engine.

Every log event is applied through :func:`apply_event`, which expands the
event into ordered *micro-steps*.  Each micro-step is one individually atomic
persistence action (a single page write, a single marker write, the single
counter write ...).  A programming pass may legitimately stop after any
prefix of those micro-steps; ``check`` enumerates such prefixes to model
power loss.  Macro events that are rejected against current state produce no
micro-steps and mutate nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .errors import EventRejected
from .model import (
    SLOT_IDS,
    CaseConfig,
    DeviceState,
    Manifest,
    SlotState,
)


@dataclass
class MicroStep:
    """One atomic persistence action."""

    step_id: str          # deterministic id, unique within the macro event
    label: str            # human-readable witness label
    action: Callable[[DeviceState], None]
    consumes_budget: bool = False
    sector_id: str | None = None
    page_id: str | None = None


@dataclass
class EventResult:
    index: int
    type: str
    status: str           # applied | rejected | power_loss
    reason: str | None
    steps: list[dict[str, Any]]
    detail: dict[str, Any]


# ---------------------------------------------------------------------------
# Signature / trust helpers
# ---------------------------------------------------------------------------

def sig_entry_for(manifest: Manifest) -> dict[str, Any]:
    return {
        "manifest_id": manifest.manifest_id,
        "version": manifest.version,
        "generation": manifest.authorized_generation,
        "auth_id": manifest.auth_id,
        "signer": manifest.signer,
        "digest_witness": manifest.digest_witness(),
    }


def trusted_complete(slot: SlotState, case: CaseConfig, state: DeviceState) -> bool:
    return slot.trusted_complete(case, state.revoked_manifests)


def formal_bootable_slots(
    state: DeviceState, case: CaseConfig
) -> list[SlotState]:
    out = []
    for sid in SLOT_IDS:
        slot = state.slots[sid]
        if slot.formally_bootable(case, state.counter, state.revoked_manifests):
            out.append(slot)
    return out


def any_bootable_after_counter(
    state: DeviceState, case: CaseConfig, new_counter: int
) -> list[str]:
    """Decide whether the counter may be raised to ``new_counter``.

    Two independent guarantees are required:

    1. the candidate itself is a complete trusted copy at the new floor (it
       becomes the bootable image the moment the active marker is published);
    2. at the instant *before* the raise at least one other complete trusted
       copy exists, so a power loss between the counter write and the
       active-marker write never leaves the device with zero rollback options
       that survived under the previous floor.
    """
    candidate_ok = False
    independent_backup = False
    for sid in SLOT_IDS:
        slot = state.slots[sid]
        if not slot.trusted_complete(case, state.revoked_manifests):
            continue
        if slot.trial is not None:
            continue
        if slot.candidate and slot.generation >= new_counter:
            candidate_ok = True
        if not slot.candidate and slot.generation >= state.counter:
            independent_backup = True
    if candidate_ok and independent_backup:
        return [sid for sid in SLOT_IDS if state.slots[sid].candidate]
    return []


# ---------------------------------------------------------------------------
# Boot decision (the rule the boot ROM follows on restart)
# ---------------------------------------------------------------------------

def _recover_candidate_publish(
    state: DeviceState, case: CaseConfig
) -> dict[str, Any] | None:
    """Complete a switch whose only missing step is the active-marker write.

    Returns a witness describing the recovery, or ``None`` when no candidate
    is eligible.  A candidate qualifies only when it is complete + READY +
    currently signed, its health was confirmed for its own generation, and the
    counter floor already equals its generation.
    """
    for sid in SLOT_IDS:
        slot = state.slots[sid]
        if not slot.candidate:
            continue
        if slot.trial is not None:
            continue
        if not slot.trusted_complete(case, state.revoked_manifests):
            continue
        if not (slot.health or {}).get("confirmed"):
            continue
        if state.counter != slot.generation:
            continue
        for other in SLOT_IDS:
            state.slots[other].active = False
        slot.active = True
        slot.candidate = False
        return {
            "slot": sid,
            "generation": slot.generation,
            "manifest_id": slot.manifest_id,
            "reason": "active marker republished after restart; counter floor already met",
        }
    return None


def boot_decision(state: DeviceState, case: CaseConfig) -> dict[str, Any]:
    """Decide what the device does after a restart.

    Selection rule: among formally bootable slots (trusted, complete, READY,
    current authorization, generation >= counter, not in trial) choose the
    highest generation; ties prefer the active marker, then the lower slot id
    for reproducibility.

    Recovery rule: if a slot still carries the candidate marker but the
    counter floor has already reached its generation and its health has been
    confirmed, the only missing step is the atomic active-marker publish.  On
    restart the boot ROM completes that publish (the candidate is fully
    verified) and boots the slot.
    """
    recovered_publish = _recover_candidate_publish(state, case)
    candidates = formal_bootable_slots(state, case)
    candidates.sort(
        key=lambda s: (-s.generation, 0 if s.active else 1, s.slot_id)
    )
    if candidates:
        chosen = candidates[0]
        return {
            "outcome": "formal_boot",
            "slot": chosen.slot_id,
            "generation": chosen.generation,
            "manifest_id": chosen.manifest_id,
            "recovered_publish": recovered_publish,
            "evidence": boot_evidence(chosen, case, state),
        }

    # No formally bootable copy.  Distinguish the security cases for witnesses.
    reasons = []
    for sid in SLOT_IDS:
        slot = state.slots[sid]
        reasons.append(_slot_failure_reason(slot, case, state))
    trusted_below = [
        s.slot_id
        for s in state.slots.values()
        if s.ready
        and s.is_complete(case)
        and s.is_signed_current(case, state.revoked_manifests)
        and s.generation < state.counter
        and s.trial is None
    ]
    return {
        "outcome": "safe_halt",
        "reason": "no_formally_bootable_slot",
        "trusted_below_floor": trusted_below,
        "slot_reasons": reasons,
        "counter": state.counter,
        "revoked_manifests": sorted(state.revoked_manifests),
    }


def _slot_failure_reason(slot: SlotState, case: CaseConfig, state: DeviceState) -> dict[str, Any]:
    m = slot.manifest(case)
    reason: dict[str, Any] = {"slot": slot.slot_id}
    if m is None:
        reason["reason"] = "no_manifest"
        return reason
    missing = [p for p in m.page_ids if p not in slot.written_pages]
    if missing:
        reason["reason"] = "incomplete"
        reason["missing_pages"] = missing
        return reason
    if not slot.ready:
        reason["reason"] = "not_ready"
        return reason
    if slot.sig_entry is None:
        reason["reason"] = "no_signature_directory"
        return reason
    if not slot.is_signed_current(case, state.revoked_manifests):
        if m.manifest_id in state.revoked_manifests:
            reason["reason"] = "authorization_revoked"
        else:
            reason["reason"] = "signature_stale"
        return reason
    if slot.generation < state.counter:
        reason["reason"] = "below_counter_floor"
        reason["slot_generation"] = slot.generation
        reason["counter"] = state.counter
        return reason
    if slot.trial is not None:
        reason["reason"] = "trial_marker_present"
        return reason
    reason["reason"] = "unknown"
    return reason


def boot_evidence(slot: SlotState, case: CaseConfig, state: DeviceState) -> dict[str, Any]:
    m = slot.manifest(case)
    assert m is not None
    return {
        "slot": slot.slot_id,
        "generation": slot.generation,
        "counter_floor": state.counter,
        "manifest_id": m.manifest_id,
        "version": m.version,
        "auth_id": m.auth_id,
        "revoked": m.manifest_id in state.revoked_manifests,
        "page_count": len(m.pages),
        "digest_witness": m.digest_witness(),
        "stored_digest_witness": slot.sig_entry.get("digest_witness") if slot.sig_entry else None,
        "ready": slot.ready,
        "active": slot.active,
        "candidate": slot.candidate,
        "complete": slot.is_complete(case),
        "readback_pages": sorted(slot.readback_verified),
    }


# ---------------------------------------------------------------------------
# Micro-step expansion
# ---------------------------------------------------------------------------

def apply_event(
    state: DeviceState, case: CaseConfig, event: dict[str, Any], index: int
) -> tuple[DeviceState, EventResult, list[MicroStep]]:
    """Validate ``event`` against ``state`` and expand it into micro-steps.

    Returns the (unmodified) state, an :class:`EventResult` describing
    validation, and the micro-step list.  The caller decides how many of the
    micro-steps actually run (full replay runs all of them).
    """
    etype = event["type"]
    if etype == "power_loss":
        return (
            state,
            EventResult(index, etype, "power_loss", None, [], {}),
            [],
        )
    handler = _HANDLERS.get(etype)
    if handler is None:  # loader normally rejects this earlier
        raise EventRejected(f"unknown event type {etype}", index)
    try:
        steps = handler(state, case, event)
    except EventRejected as exc:
        exc.event_index = index
        return (
            state,
            EventResult(index, etype, "rejected", exc.reason, [], {"event": event}),
            [],
        )
    result = EventResult(
        index,
        etype,
        "applied",
        None,
        [
            {
                "step_id": s.step_id,
                "label": s.label,
                "sector_id": s.sector_id,
                "page_id": s.page_id,
            }
            for s in steps
        ],
        {"event": event},
    )
    return state, result, steps


def run_steps(
    state: DeviceState, steps: list[MicroStep], prefix: int | None = None
) -> tuple[DeviceState, list[str]]:
    """Deep-copy state and run the first ``prefix`` micro-steps (all if None)."""
    new_state = state.clone()
    n = len(steps) if prefix is None else max(0, min(prefix, len(steps)))
    done = []
    for step in steps[:n]:
        step.action(new_state)
        done.append(step.step_id)
    return new_state, done


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def _h_update(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    if manifest.device_group != case.device_group:
        raise EventRejected("manifest targets a different device group")
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if slot.session is not None:
        # Retry of the same application: must match the original request and
        # the slot generation must not have advanced underneath us.
        sess = slot.session
        if sess.get("manifest_id") != manifest.manifest_id:
            raise EventRejected(
                "retry manifest does not match the open write session"
            )
        if sess.get("target_slot") != target:
            raise EventRejected("retry target slot does not match the open session")
        if slot.generation != sess.get("authorized_generation"):
            raise EventRejected("slot generation changed since the original application")
        return []  # idempotent reopen: nothing new to persist
    if slot.generation >= manifest.authorized_generation:
        raise EventRejected(
            f"target slot generation {slot.generation} is not older than "
            f"authorized generation {manifest.authorized_generation}; erase before reuse"
        )
    if slot.manifest_id is not None and slot.manifest_id != manifest.manifest_id:
        raise EventRejected(
            "slot still holds pages of another generation; erase is required "
            "before a new generation can be written"
        )

    def do_open(s: DeviceState) -> None:
        sl = s.slots[target]
        previous_generation = sl.generation
        # Opening the session commits the slot to the manifest's generation:
        # from this point on old-generation pages may never be mixed in.
        sl.manifest_id = manifest.manifest_id
        sl.generation = manifest.authorized_generation
        sl.session = {
            "manifest_id": manifest.manifest_id,
            "target_slot": target,
            "version": manifest.version,
            "authorized_generation": manifest.authorized_generation,
            "generation_at_open": previous_generation,
            "remaining_pages": manifest.page_ids,
            "written_in_session": [],
        }

    return [MicroStep("open_session", f"open write session for {manifest.manifest_id} on {target}", do_open)]


def _resolve_target_slot(state: DeviceState, event: dict[str, Any]) -> str:
    if "slot" in event:
        if event["slot"] not in SLOT_IDS:
            raise EventRejected(f"unknown slot {event['slot']}")
        return event["slot"]
    active = [sid for sid in SLOT_IDS if state.slots[sid].active]
    if not active:
        # No active marker: pick the slot with the lower generation, then A.
        return min(SLOT_IDS, key=lambda sid: (state.slots[sid].generation, sid))
    return "B" if active[0] == "A" else "A"


def _h_program(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if slot.session is None:
        raise EventRejected("no open write session on target slot")
    if slot.session["manifest_id"] != manifest.manifest_id:
        raise EventRejected("program event does not match the open session manifest")
    if slot.session["target_slot"] != target:
        raise EventRejected("program event targets the wrong slot for the session")

    steps: list[MicroStep] = []
    for order, page_id in enumerate(event["pages"]):
        if page_id not in manifest.pages:
            raise EventRejected(f"page {page_id} is not part of manifest {manifest.manifest_id}")
        digest = manifest.pages[page_id]
        sector_id = case.page_sector[page_id]
        # A page already persisted with the correct digest is skipped (resume).
        if slot.written_pages.get(page_id) == digest:
            continue
        if page_id in slot.written_pages:
            raise EventRejected(
                f"page {page_id} holds a stale digest: mixing old pages into a "
                "new generation is forbidden"
            )
        if state.sector_budgets[sector_id] <= 0:
            raise EventRejected(
                f"sector {sector_id} write budget exhausted; an erase action is required"
            )

        def make_write(pid: str, dgst: str, sec: str, ord_no: int) -> Callable[[DeviceState], None]:
            def do_write(s: DeviceState) -> None:
                sl = s.slots[target]
                if s.sector_budgets[sec] <= 0:
                    raise EventRejected(f"sector {sec} budget exhausted during replay")
                sl.written_pages[pid] = dgst
                s.sector_budgets[sec] -= 1
                s.program_writes += 1
                remaining = sl.session["remaining_pages"]
                if pid in remaining:
                    remaining.remove(pid)
                written = sl.session["written_in_session"]
                if pid not in written:
                    written.append(pid)
                sl.ready = False  # READY may only be (re)published atomically later
            return do_write

        steps.append(
            MicroStep(
                f"write_page:{page_id}",
                f"program page {page_id} (sector {sector_id}, digest {digest[:16]}...)",
                make_write(page_id, digest, sector_id, order),
                consumes_budget=True,
                sector_id=sector_id,
                page_id=page_id,
            )
        )
    if not steps:
        raise EventRejected("program batch contains no new pages for the open session")
    return steps


def _h_verify(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if slot.session is None or slot.session["manifest_id"] != manifest.manifest_id:
        raise EventRejected("verify requires an open session for the same manifest")
    missing = [p for p in manifest.page_ids if p not in slot.written_pages]
    if missing:
        raise EventRejected(f"verify failed: pages not fully written: {missing}")
    bad = [
        p for p, digest in manifest.pages.items()
        if slot.written_pages.get(p) != digest
    ]
    if bad:
        raise EventRejected(f"verify failed: digest mismatch on pages {bad}")

    steps: list[MicroStep] = []
    pending = [p for p in manifest.page_ids if p not in slot.readback_verified]
    for page_id in pending:
        def make_readback(pid: str) -> Callable[[DeviceState], None]:
            def do_readback(s: DeviceState) -> None:
                sl = s.slots[target]
                m = case.manifest_by_id[manifest.manifest_id]
                if sl.written_pages.get(pid) != m.pages[pid]:
                    raise EventRejected(f"readback mismatch on page {pid}")
                if pid not in sl.readback_verified:
                    sl.readback_verified.append(pid)
                    sl.readback_verified.sort()
            return do_readback
        steps.append(
            MicroStep(
                f"readback:{page_id}",
                f"read back and verify page {page_id}",
                make_readback(page_id),
                page_id=page_id,
            )
        )
    if not steps:
        # Idempotent re-verify: still record one marker-style no-op witness.
        def noop(s: DeviceState) -> None:
            return None
        steps.append(MicroStep("readback:already_verified", "all pages already read back", noop))
    return steps


def _h_mark_ready(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if slot.session is None or slot.session["manifest_id"] != manifest.manifest_id:
        raise EventRejected("mark_ready requires an open session for the manifest")
    if not slot.is_complete(case):
        raise EventRejected("mark_ready rejected: image is incomplete")
    not_verified = [p for p in manifest.page_ids if p not in slot.readback_verified]
    if not_verified:
        raise EventRejected(f"mark_ready rejected: pages not read back: {not_verified}")
    if manifest.manifest_id in state.revoked_manifests:
        raise EventRejected("mark_ready rejected: authorization already revoked")

    def do_ready(s: DeviceState) -> None:
        sl = s.slots[target]
        sl.ready = True
        # Signature directory is published atomically with READY.
        sl.sig_entry = sig_entry_for(manifest)

    return [MicroStep("publish_ready", f"atomically publish READY + signature directory on {target}", do_ready)]


def _h_trial_start(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if not slot.trusted_complete(case, state.revoked_manifests):
        raise EventRejected("trial_start requires a complete, read-back, currently signed READY image")
    if slot.generation != manifest.authorized_generation:
        raise EventRejected("trial manifest generation does not match slot generation")
    if slot.active:
        raise EventRejected("trial cannot run on the slot currently serving external traffic")
    if slot.trial is not None:
        raise EventRejected("a trial is already open on this slot")

    def do_trial(s: DeviceState) -> None:
        sl = s.slots[target]
        sl.trial = {
            "manifest_id": manifest.manifest_id,
            "generation": manifest.authorized_generation,
            "isolation": True,
            "external_service": False,
        }
        sl.health = None  # a new trial needs a fresh health receipt

    return [MicroStep("trial_start", f"enter isolated trial on {target} generation {slot.generation}", do_trial)]


def _h_health(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    receipt_id = event["receipt_id"]
    if slot.trial is None:
        raise EventRejected("late health receipt: no trial is open for this generation")
    if slot.trial["manifest_id"] != manifest.manifest_id:
        raise EventRejected("late health receipt: manifest does not match the open trial")
    if slot.trial["generation"] != manifest.authorized_generation:
        raise EventRejected("late health receipt: generation does not match the open trial")

    def do_health(s: DeviceState) -> None:
        sl = s.slots[target]
        sl.health = {
            "receipt_id": receipt_id,
            "manifest_id": manifest.manifest_id,
            "generation": manifest.authorized_generation,
            "auth_id": manifest.auth_id,
            "revoked_at_receipt": manifest.manifest_id in s.revoked_manifests,
        }

    return [MicroStep(f"health:{receipt_id}", f"record health receipt {receipt_id} for trial generation {manifest.authorized_generation}", do_health)]


def _h_trial_end(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if slot.trial is None:
        raise EventRejected("trial_end requires an open trial")
    if slot.trial["manifest_id"] != manifest.manifest_id:
        raise EventRejected("trial_end manifest does not match the open trial")

    def do_end(s: DeviceState) -> None:
        s.slots[target].trial = None

    return [MicroStep("trial_end", f"close isolated trial on {target}", do_end)]


def _h_switch_candidate(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if not slot.trusted_complete(case, state.revoked_manifests):
        raise EventRejected("candidate marker requires a trusted complete READY image")
    if slot.generation != manifest.authorized_generation:
        raise EventRejected("candidate manifest generation does not match slot")
    if slot.trial is not None:
        raise EventRejected("candidate marker cannot be set while a trial is open")

    def do(s: DeviceState) -> None:
        s.slots[target].candidate = True

    return [MicroStep("switch_candidate", f"write candidate marker on {target}", do)]


def _h_switch_confirm_health(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if not slot.candidate:
        raise EventRejected("health confirmation requires the candidate marker")
    if slot.health is None:
        raise EventRejected("no health receipt on record for the candidate")
    if slot.health.get("manifest_id") != manifest.manifest_id:
        raise EventRejected("health receipt belongs to a different manifest")
    if slot.health.get("generation") != manifest.authorized_generation:
        raise EventRejected("health receipt belongs to a different (stale) trial generation")
    if manifest.manifest_id in state.revoked_manifests:
        raise EventRejected("health cannot be confirmed: authorization has been revoked")
    if slot.health.get("revoked_at_receipt"):
        raise EventRejected("health receipt was issued under a since-revoked authorization")

    def do(s: DeviceState) -> None:
        s.slots[target].health["confirmed"] = True

    return [MicroStep("switch_confirm_health", f"confirm candidate health on {target}", do)]


def _h_counter_raise(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if not slot.candidate:
        raise EventRejected("counter raise requires the candidate marker")
    if not (slot.health or {}).get("confirmed"):
        raise EventRejected("counter raise requires confirmed candidate health")
    if manifest.manifest_id in state.revoked_manifests:
        raise EventRejected("counter raise rejected: candidate authorization revoked")
    new_counter = manifest.authorized_generation
    if new_counter <= state.counter:
        raise EventRejected(
            f"counter is monotonic: {new_counter} not greater than current {state.counter}"
        )
    survivors = any_bootable_after_counter(state, case, new_counter)
    if not survivors:
        raise EventRejected(
            "counter raise rejected: no complete trusted bootable copy would remain"
        )

    def do(s: DeviceState) -> None:
        s.counter = new_counter

    return [MicroStep(
        "counter_raise",
        f"raise monotonic counter {state.counter} -> {new_counter} (survivors: {','.join(survivors)})",
        do,
    )]


def _h_switch_publish_active(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]
    target = _resolve_target_slot(state, event)
    slot = state.slots[target]
    if not slot.candidate:
        raise EventRejected("publishing active marker requires the candidate marker")
    if state.counter < manifest.authorized_generation:
        raise EventRejected(
            "active marker rejected: counter floor has not been raised to the candidate generation"
        )
    if not slot.trusted_complete(case, state.revoked_manifests):
        raise EventRejected("active marker rejected: candidate is no longer trusted/complete")

    def do(s: DeviceState) -> None:
        for sid in SLOT_IDS:
            s.slots[sid].active = False
        sl = s.slots[target]
        sl.active = True
        sl.candidate = False
        sl.session = None
        sl.readback_verified = []

    return [MicroStep("switch_publish_active", f"publish active marker on {target}, retire old active", do)]


def _h_revoke(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    manifest = case.manifest_by_id[event["manifest_id"]]

    def do(s: DeviceState) -> None:
        s.revoked_manifests.add(manifest.manifest_id)

    return [MicroStep(f"revoke:{manifest.manifest_id}", f"revoke authorization of {manifest.manifest_id}", do)]


def _h_erase(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> list[MicroStep]:
    target = event["slot"]
    sector_id = event["sector_id"]
    sector = next((x for x in case.sectors if x.sector_id == sector_id), None)
    if sector is None:
        raise EventRejected(f"unknown sector {sector_id}")
    slot = state.slots[target]
    if slot.active:
        raise EventRejected("refusing to erase a sector of the slot serving external traffic")

    def do(s: DeviceState) -> None:
        sl = s.slots[target]
        for pid in sector.pages:
            sl.written_pages.pop(pid, None)
            if pid in sl.readback_verified:
                sl.readback_verified.remove(pid)
            if sl.session is not None and pid in sl.session.get("remaining_pages", []):
                pass
            if sl.session is not None and pid in sl.session.get("written_in_session", []):
                sl.session["written_in_session"].remove(pid)
                if pid not in sl.session["remaining_pages"]:
                    sl.session["remaining_pages"].append(pid)
        # Any partial image loses READY and its signature/candidate markers.
        m = sl.manifest(case)
        if m is not None and not all(p in sl.written_pages for p in m.page_ids):
            sl.ready = False
            sl.sig_entry = None
            sl.candidate = False
            sl.health = None
        # When the erase empties the slot entirely it returns to the blank,
        # reusable state; its generation binding is dropped so a new manifest
        # can be opened without a cross-generation rejection.
        if not sl.written_pages and sl.session is None:
            sl.manifest_id = None
            sl.generation = 0
            sl.ready = False
            sl.sig_entry = None
            sl.candidate = False
            sl.trial = None
            sl.health = None
        s.sector_budgets[sector_id] = sector.capacity
        sl.erase_count += 1

    return [MicroStep(f"erase:{sector_id}", f"erase sector {sector_id} on slot {target} and restore budget", do)]


_HANDLERS: dict[str, Callable[[DeviceState, CaseConfig, dict[str, Any]], list[MicroStep]]] = {
    "update": _h_update,
    "program": _h_program,
    "verify": _h_verify,
    "mark_ready": _h_mark_ready,
    "trial_start": _h_trial_start,
    "health": _h_health,
    "trial_end": _h_trial_end,
    "switch_candidate": _h_switch_candidate,
    "switch_confirm_health": _h_switch_confirm_health,
    "counter_raise": _h_counter_raise,
    "switch_publish_active": _h_switch_publish_active,
    "revoke": _h_revoke,
    "erase": _h_erase,
}
