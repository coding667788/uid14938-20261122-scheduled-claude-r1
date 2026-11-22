"""Deterministic full replay and micro-step trace construction.

``replay`` runs every log event to completion (all of its micro-steps) and
records the boot decision after each explicit ``power_loss`` event and at the
end.  The same expansion utilities are reused by ``check`` to enumerate
power-loss prefixes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .engine import (
    EventResult,
    MicroStep,
    apply_event,
    boot_decision,
    run_steps,
)
from .model import CaseConfig, DeviceState


@dataclass
class ExpandedStep:
    event_index: int
    event_type: str
    step_index: int          # index within the macro event
    step_id: str
    label: str
    micro: MicroStep
    event: dict[str, Any]


def expand_trace(case: CaseConfig) -> tuple[list[ExpandedStep], list[EventResult], DeviceState]:
    """Validate all events and expand them into atomic micro-steps.

    Rejected macro events contribute zero micro-steps.  The returned initial
    state is a fresh clone the caller may freely mutate.
    """
    state = case.initial_state.clone()
    expanded: list[ExpandedStep] = []
    results: list[EventResult] = []
    for index, event in enumerate(case.events):
        state, result, steps = apply_event(state, case, event, index)
        results.append(result)
        for step_index, micro in enumerate(steps):
            expanded.append(
                ExpandedStep(
                    event_index=index,
                    event_type=event["type"],
                    step_index=step_index,
                    step_id=micro.step_id,
                    label=micro.label,
                    micro=micro,
                    event=event,
                )
            )
        if steps:
            state, _ = run_steps(state, steps)
    return expanded, results, state


def micro_cuts(case: CaseConfig) -> list[dict[str, Any]]:
    """All legal power-loss cut points.

    A cut is ``(event_index, prefix)`` where prefix is the number of
    micro-steps of that event that have persisted when power is lost.
    Prefix 0 means the loss happened before the event's first atomic action.
    Power-loss events themselves and rejected events offer no cut.
    """
    state = case.initial_state.clone()
    cuts: list[dict[str, Any]] = []
    for index, event in enumerate(case.events):
        state, result, steps = apply_event(state, case, event, index)
        if event["type"] == "power_loss":
            continue
        if not steps:
            continue  # rejected or idempotent reopen: nothing atomic to cut
        for prefix in range(0, len(steps) + 1):
            cuts.append(
                {
                    "cut_id": f"e{index}.p{prefix}",
                    "event_index": index,
                    "prefix": prefix,
                    "event_type": event["type"],
                    "total_steps": len(steps),
                    "step_ids": [m.step_id for m in steps],
                }
            )
        state, _ = run_steps(state, steps)
    return cuts


def state_after_cut(
    case: CaseConfig, event_index: int, prefix: int
) -> tuple[DeviceState, list[dict[str, Any]]]:
    """Reconstruct the persisted state when power is lost at one cut point."""
    state = case.initial_state.clone()
    applied: list[dict[str, Any]] = []
    for index, event in enumerate(case.events):
        if index > event_index:
            break
        state, result, steps = apply_event(state, case, event, index)
        if index == event_index:
            run_prefix = prefix
        else:
            run_prefix = None  # full execution for earlier events
        if steps:
            state, done = run_steps(state, steps, run_prefix)
            applied.append(
                {
                    "event_index": index,
                    "type": event["type"],
                    "ran_steps": done,
                    "truncated": index == event_index and prefix < len(steps),
                }
            )
    return state, applied


def replay(case: CaseConfig) -> dict[str, Any]:
    """Full deterministic replay used by the ``replay`` CLI command."""
    expanded, results, final_state = expand_trace(case)
    boot_snapshots: list[dict[str, Any]] = []
    # Re-run while tracking power-loss points for boot evidence.
    state = case.initial_state.clone()
    boot_snapshots.append(
        {
            "point": "initial",
            **boot_decision(state, case),
        }
    )
    for index, event in enumerate(case.events):
        state, result, steps = apply_event(state, case, event, index)
        if steps:
            state, _ = run_steps(state, steps)
        if event["type"] == "power_loss":
            decision = boot_decision(state, case)
            boot_snapshots.append(
                {
                    "point": f"after_event[{index}]",
                    "power_loss_event_index": index,
                    **decision,
                }
            )
    boot_snapshots.append(
        {
            "point": "final",
            **boot_decision(final_state, case),
        }
    )

    return {
        "command": "replay",
        "case_id": case.case_id,
        "summary": {
            "events": len(case.events),
            "micro_steps": len(expanded),
            "applied": sum(1 for r in results if r.status == "applied"),
            "rejected": sum(1 for r in results if r.status == "rejected"),
            "power_loss_events": sum(1 for r in results if r.status == "power_loss"),
            "program_writes": final_state.program_writes,
            "final_counter": final_state.counter,
            "active_slot": next((s.slot_id for s in final_state.slots.values() if s.active), None),
        },
        "events": [_result_payload(r) for r in results],
        "boot_snapshots": boot_snapshots,
        "final_bootable_partitions": _bootable_partitions(final_state, case),
        "final_state": _state_payload(final_state, case),
    }


def _result_payload(result: EventResult) -> dict[str, Any]:
    return {
        "event_index": result.index,
        "type": result.type,
        "status": result.status,
        "reason": result.reason,
        "micro_steps": result.steps,
    }


def _bootable_partitions(state: DeviceState, case: CaseConfig) -> list[dict[str, Any]]:
    out = []
    for sid in ("A", "B"):
        slot = state.slots[sid]
        record = {
            "slot": sid,
            "generation": slot.generation,
            "manifest_id": slot.manifest_id,
            "complete": slot.is_complete(case),
            "ready": slot.ready,
            "signed_current": slot.is_signed_current(case, state.revoked_manifests),
            "trusted_complete": slot.trusted_complete(case, state.revoked_manifests),
            "formally_bootable": slot.formally_bootable(
                case, state.counter, state.revoked_manifests
            ),
            "active": slot.active,
            "candidate": slot.candidate,
            "in_trial": slot.trial is not None,
        }
        if record["formally_bootable"]:
            record["evidence"] = {
                "counter_floor": state.counter,
                "digest_witness": slot.sig_entry.get("digest_witness") if slot.sig_entry else None,
                "auth_id": slot.sig_entry.get("auth_id") if slot.sig_entry else None,
                "readback_pages": sorted(slot.readback_verified),
            }
        out.append(record)
    return out


def _state_payload(state: DeviceState, case: CaseConfig) -> dict[str, Any]:
    slots: dict[str, Any] = {}
    for sid, slot in state.slots.items():
        slots[sid] = {
            "generation": slot.generation,
            "manifest_id": slot.manifest_id,
            "written_pages": dict(sorted(slot.written_pages.items())),
            "ready": slot.ready,
            "sig_entry": slot.sig_entry,
            "candidate": slot.candidate,
            "active": slot.active,
            "trial": slot.trial,
            "health": slot.health,
            "session": slot.session,
            "readback_verified": sorted(slot.readback_verified),
            "erase_count": slot.erase_count,
        }
    return {
        "counter": state.counter,
        "revoked_manifests": sorted(state.revoked_manifests),
        "sector_budgets": dict(sorted(state.sector_budgets.items())),
        "program_writes": state.program_writes,
        "slots": slots,
    }
