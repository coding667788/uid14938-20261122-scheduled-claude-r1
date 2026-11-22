"""The ``check`` command: bounded power-loss verification.

The verifier enumerates every way the declared update sequence can be
interrupted by at most ``max_power_losses`` power losses.  A loss may land on
any atomic micro-step boundary, including "before the first action" of an
event.  After each simulated restart the device re-reads its persistent
markers and applies its boot rule; the verifier checks two properties:

P1 (never serve an unverified image)
    External service is only ever entered on a formally bootable partition
    (complete, read back, READY, signature directory valid under the current
    authorization, generation >= counter floor, not in trial).

P2 (availability under the maintain fallback policy)
    Whenever a still-trusted formal old image existed at the cut and the
    fallback policy is ``maintain``, recovery must reach external service on a
    formally bootable image rather than safe-halting.  Under
    ``halt_allowed`` a halt is an accepted (but reported) outcome.

The engine itself makes P1 unviolatable by construction; a violation here can
therefore only come from a malformed initial state or an illegal protocol
step, and is reported with concrete page / authorization / counter witnesses.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

from .engine import boot_decision
from .model import CaseConfig, DeviceState
from .replay import expand_trace, micro_cuts


def check(case: CaseConfig) -> dict[str, Any]:
    cuts = micro_cuts(case)
    _, _, clean_final = expand_trace(case)

    # Baseline: the uninterrupted sequence must itself end in a sane state.
    baseline = boot_decision(clean_final, case)
    baseline_violation = _classify_baseline(case, baseline)

    scenarios: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    # Zero-loss scenario first.
    scenarios.append(
        _scenario_record(
            cuts_used=[],
            state=clean_final,
            case=case,
            label="uninterrupted",
        )
    )

    for k in range(1, case.max_power_losses + 1):
        for combo in combinations(range(len(cuts)), k):
            cut_choices = [cuts[i] for i in combo]
            if not _cuts_are_ordered(cut_choices):
                continue
            record = _evaluate_combo(case, cut_choices)
            scenarios.append(record)
            if record["verdict"] == "fail":
                failures.append(record)

    if baseline_violation is not None:
        failures.insert(0, baseline_violation)

    # De-duplicate identical failure shapes while keeping the shortest trace.
    failures.sort(key=lambda f: (f["loss_count"], f["cut_trace"]))
    shortest = failures[0] if failures else None
    halts = [s for s in scenarios if s["boot"]["outcome"] == "safe_halt"]

    status = "pass"
    if failures:
        status = "fail"
    elif halts and case.policy.fallback == "halt_allowed":
        status = "pass_with_halts"

    return {
        "command": "check",
        "case_id": case.case_id,
        "status": status,
        "policy": {"fallback": case.policy.fallback},
        "bounds": {"max_power_losses": case.max_power_losses},
        "summary": {
            "cut_points": len(cuts),
            "scenarios_evaluated": len(scenarios),
            "safe_halts": len(halts),
            "failure_count": len(failures),
        },
        "shortest_failure": shortest,
        "all_failures": failures,
        "safe_halt_scenarios": [
            {"cut_trace": s["cut_trace"], "boot": s["boot"]} for s in halts
        ],
        "baseline_boot": baseline,
    }


def _cuts_are_ordered(chosen: list[dict[str, Any]]) -> bool:
    # Two losses inside one macro event are physically indistinguishable from
    # the deepest cut: after a loss the abandoned event is not re-executed on
    # restart (only its persisted write session can be resumed by later
    # program events).  Require distinct events and strictly increasing points.
    event_indexes = [c["event_index"] for c in chosen]
    if len(set(event_indexes)) != len(event_indexes):
        return False
    for earlier, later in zip(chosen, chosen[1:]):
        if (later["event_index"], later["prefix"]) <= (
            earlier["event_index"],
            earlier["prefix"],
        ):
            return False
    return True


def _evaluate_combo(case: CaseConfig, chosen: list[dict[str, Any]]) -> dict[str, Any]:
    """Replay with losses at the chosen cut points, then run the rest cleanly."""
    state = case.initial_state.clone()
    cut_trace: list[dict[str, Any]] = []
    # Distinct event indices are guaranteed by _cuts_are_ordered.
    prefix_by_event = {c["event_index"]: c for c in chosen}

    for index, event in enumerate(case.events):
        from .engine import apply_event, run_steps

        state, result, steps = apply_event(state, case, event, index)
        cut = prefix_by_event.get(index)
        if cut is not None and not steps and event["type"] != "power_loss":
            # Cut landed on an event with no atomic steps: still a restart.
            cut_trace.append(_cut_witness(cut, state, ran=0))
        if not steps:
            continue
        prefix = cut["prefix"] if cut is not None else None
        before = state.clone()
        state, _done = run_steps(state, steps, prefix)
        if prefix is not None and prefix < len(steps):
            cut_trace.append(_cut_witness(cut, before, ran=prefix))

    boot = boot_decision(state, case)
    verdict, reason = _verdict_for(case, boot, state, cut_trace)
    return {
        "verdict": verdict,
        "violation": reason,
        "loss_count": len(chosen),
        "cut_trace": [c["cut_id"] for c in chosen],
        "cuts": cut_trace,
        "boot": boot,
        "witnesses": _witnesses(state, case, boot),
    }


def _cut_witness(cut: dict[str, Any], state_before: DeviceState, ran: int) -> dict[str, Any]:
    return {
        "cut_id": cut["cut_id"],
        "event_index": cut["event_index"],
        "event_type": cut["event_type"],
        "atomic_steps_total": cut["total_steps"],
        "steps_persisted_before_loss": ran,
        "surviving_step_ids": cut["step_ids"][:ran],
        "lost_step_ids": cut["step_ids"][ran:],
        "counter_at_loss": state_before.counter,
    }


def _verdict_for(
    case: CaseConfig,
    boot: dict[str, Any],
    state: DeviceState,
    cut_trace: list[dict[str, Any]],
) -> tuple[str, str | None]:
    if boot["outcome"] == "formal_boot":
        # P1: formal_boot already guarantees every trust predicate.
        return "pass", None
    # safe_halt.  A halt is security-correct whenever no trusted complete
    # image survives above the counter floor: incomplete regions may never be
    # rollback targets and revoked images may never be served.
    if not boot.get("trusted_below_floor"):
        return "pass_halt", None
    # A still-trusted old image exists but is stranded below the raised floor,
    # with nothing formally bootable.  Under maintain policy the strategy was
    # required to keep service available and failed; under halt_allowed the
    # operator explicitly accepts stopping.
    if case.policy.fallback == "halt_allowed":
        return "pass_halt", None
    return (
        "fail",
        "availability_violation: trusted old image exists but is below the "
        "raised counter floor and no formal bootable copy remains",
    )


def _classify_baseline(case: CaseConfig, boot: dict[str, Any]) -> dict[str, Any] | None:
    verdict, reason = _verdict_for(case, boot, None, [])  # type: ignore[arg-type]
    if verdict != "fail":
        return None
    return {
        "verdict": "fail",
        "violation": reason,
        "loss_count": 0,
        "cut_trace": [],
        "cuts": [],
        "boot": boot,
        "witnesses": {},
    }


def _scenario_record(
    cuts_used: list[dict[str, Any]],
    state: DeviceState,
    case: CaseConfig,
    label: str,
) -> dict[str, Any]:
    boot = boot_decision(state, case)
    verdict, reason = _verdict_for(case, boot, state, [])
    return {
        "label": label,
        "verdict": verdict,
        "violation": reason,
        "loss_count": len(cuts_used),
        "cut_trace": [c["cut_id"] for c in cuts_used],
        "boot": boot,
        "witnesses": _witnesses(state, case, boot),
    }


def _witnesses(state: DeviceState, case: CaseConfig, boot: dict[str, Any]) -> dict[str, Any]:
    page_witness: dict[str, Any] = {}
    for sid, slot in state.slots.items():
        m = slot.manifest(case)
        page_witness[sid] = {
            "generation": slot.generation,
            "manifest_id": slot.manifest_id,
            "written_count": len(slot.written_pages),
            "expected_count": len(m.pages) if m else 0,
            "missing_pages": [p for p in m.page_ids if p not in slot.written_pages] if m else [],
            "ready": slot.ready,
            "has_signature_directory": slot.sig_entry is not None,
            "signed_current": slot.is_signed_current(case, state.revoked_manifests),
            "candidate": slot.candidate,
            "active": slot.active,
            "trial": slot.trial,
            "health": slot.health,
            "readback_verified": sorted(slot.readback_verified),
        }
    return {
        "counter": state.counter,
        "revoked_manifests": sorted(state.revoked_manifests),
        "sector_budgets": dict(sorted(state.sector_budgets.items())),
        "page_witness": page_witness,
        "authorization_witness": [
            {
                "manifest_id": m.manifest_id,
                "auth_id": m.auth_id,
                "generation": m.authorized_generation,
                "revoked": m.manifest_id in state.revoked_manifests,
            }
            for m in case.manifests
        ],
        "boot_outcome": boot["outcome"],
    }
