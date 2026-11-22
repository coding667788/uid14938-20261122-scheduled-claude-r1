"""The ``repair`` command: fixed action sequences that make ``check`` pass.

The planner searches a deliberately small, pre-approved catalog of repair
actions (the only actions a field technician is allowed to run).  Every
candidate sequence is validated through the same engine and the same
power-loss cut enumeration as ``check``; a sequence is accepted only when
every bounded-cut recovery reaches a formally bootable image (or a policy
accepted safe halt).

Cost ordering (the required optimization)
-----------------------------------------
1. total sector erases (fewer is better),
2. number of repair actions,
3. lexicographic action id sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .check import _verdict_for, _witnesses
from .engine import apply_event, boot_decision, run_steps
from .model import CaseConfig, DeviceState, Manifest, SlotState
from .replay import micro_cuts


@dataclass(frozen=True)
class RepairAction:
    action_id: str
    events: tuple[dict[str, Any], ...]
    erases: int


def repair(case: CaseConfig) -> dict[str, Any]:
    start = case.initial_state.clone()
    # The repair goal follows the case policy: under maintain the device must
    # be returned to external service (formal boot); under halt_allowed a
    # security-correct safe halt is already an acceptable end state.
    require_service = case.policy.fallback == "maintain"
    max_depth = case.repair_depth
    queue: list[dict[str, Any]] = [
        {"state": start, "actions": [], "events": [], "erases": 0}
    ]
    seen: set[str] = {start.canonical()}
    goal_hits: list[dict[str, Any]] = []

    while queue:
        node = queue.pop(0)
        # Goal test before expansion: the empty repair may already pass.
        if _repair_goal(case, node["state"], require_service):
            goal_hits.append(node)
            continue
        if len(node["actions"]) >= max_depth:
            continue
        macros, housekeeping = _candidate_actions(case, node["state"])
        enqueued_here = 0
        # Goal-directed macros are explored exhaustively; they already embed
        # every erase their own protocol needs, so housekeeping is only a
        # fallback when no macro makes progress.
        for candidate in macros:
            new_state = _apply_repair_events(node["state"], case, candidate.events)
            key = new_state.canonical()
            if key in seen:
                continue
            seen.add(key)
            queue.append(
                {
                    "state": new_state,
                    "actions": node["actions"] + [candidate.action_id],
                    "events": node["events"] + list(candidate.events),
                    "erases": node["erases"] + candidate.erases,
                }
            )
            enqueued_here += 1
        if enqueued_here == 0:
            # No productive macro: allow exactly one deterministic housekeeping
            # branch (abort before erase, lowest id first) to unblock progress.
            for candidate in housekeeping[:1]:
                new_state = _apply_repair_events(node["state"], case, candidate.events)
                key = new_state.canonical()
                if key in seen:
                    continue
                seen.add(key)
                queue.append(
                    {
                        "state": new_state,
                        "actions": node["actions"] + [candidate.action_id],
                        "events": node["events"] + list(candidate.events),
                        "erases": node["erases"] + candidate.erases,
                    }
                )

    if not goal_hits:
        return {
            "command": "repair",
            "case_id": case.case_id,
            "status": "no_repair",
            "explored_states": len(seen),
            "depth_limit": max_depth,
            "message": "no approved action sequence reaches a check-passing state",
        }

    goal_hits.sort(
        key=lambda n: (n["erases"], len(n["actions"]), n["actions"])
    )
    best = goal_hits[0]
    verification = _verify_suffix(case, best["state"], best["events"])
    return {
        "command": "repair",
        "case_id": case.case_id,
        "status": "ok",
        "cost": {
            "sector_erases": best["erases"],
            "action_count": len(best["actions"]),
            "action_id_sequence": best["actions"],
        },
        "alternatives": [
            {
                "sector_erases": n["erases"],
                "action_count": len(n["actions"]),
                "action_id_sequence": n["actions"],
            }
            for n in goal_hits[1:6]
        ],
        "repair_events": best["events"],
        "final_boot": boot_decision(best["state"], case),
        "cut_verification": verification,
        "explored_states": len(seen),
        "depth_limit": max_depth,
    }


# ---------------------------------------------------------------------------
# Approved action catalog
# ---------------------------------------------------------------------------

def _action_rank(action_id: str) -> tuple[int, str]:
    if action_id.startswith("complete_update") or action_id.startswith("complete_switch"):
        return (0, action_id)
    if action_id.startswith("abort"):
        return (1, action_id)
    return (2, action_id)  # single-sector erases last


def _candidate_actions(
    case: CaseConfig, state: DeviceState
) -> tuple[list[RepairAction], list[RepairAction]]:
    """Return ``(goal_macros, housekeeping)``.

    Goal macros drive the device straight to a serviceable state and embed
    every erase their own protocol requires.  Housekeeping (single-sector
    erases, session aborts) only unblocks a stuck state and is explored one
    branch at a time by the planner.
    """
    macros: list[RepairAction] = []
    housekeeping: list[RepairAction] = []
    trusted_manifests = [
        m for m in case.manifests if m.manifest_id not in state.revoked_manifests
    ]

    # Housekeeping 1: erase one sector of an inactive slot (restore budget).
    for slot_id in ("A", "B"):
        slot = state.slots[slot_id]
        if slot.active:
            continue
        for sector in case.sectors:
            touched = any(p in slot.written_pages for p in sector.pages) or (
                state.sector_budgets[sector.sector_id] < sector.capacity
            )
            if not touched:
                continue
            housekeeping.append(
                RepairAction(
                    action_id=f"erase:{slot_id}:{sector.sector_id}",
                    events=({"type": "erase", "slot": slot_id, "sector_id": sector.sector_id},),
                    erases=1,
                )
            )

    # Housekeeping 2: abort an open write session on an inactive slot.
    for slot_id in ("A", "B"):
        slot = state.slots[slot_id]
        if slot.session is not None and not slot.active:
            housekeeping.append(
                RepairAction(
                    action_id=f"abort_session:{slot_id}",
                    events=(_abort_events(slot_id, case, state),),
                    erases=0,
                )
            )

    # Macro 1: full update protocol for a trusted manifest onto a safe target.
    for manifest in trusted_manifests:
        target = _repair_target(state, manifest)
        if target is None:
            continue
        events = _full_protocol_events(case, state, manifest, target)
        if events is None:
            continue
        erases = sum(1 for e in events if e["type"] == "erase")
        macros.append(
            RepairAction(
                action_id=f"complete_update:{target}:{manifest.manifest_id}",
                events=tuple(events),
                erases=erases,
            )
        )

    # Macro 2: finish an already-candidate slot: confirm + raise + publish.
    for slot_id in ("A", "B"):
        slot = state.slots[slot_id]
        if not slot.candidate or slot.manifest_id is None:
            continue
        manifest = case.manifest_by_id.get(slot.manifest_id)
        if manifest is None or manifest.manifest_id in state.revoked_manifests:
            continue
        events = _finish_switch_events(slot, manifest)
        if events:
            macros.append(
                RepairAction(
                    action_id=f"complete_switch:{slot_id}:{manifest.manifest_id}",
                    events=tuple(events),
                    erases=0,
                )
            )
    macros.sort(key=lambda a: a.action_id)
    # Aborts before erases inside housekeeping, then id order.
    housekeeping.sort(key=lambda a: _action_rank(a.action_id))
    return macros, housekeeping


def _repair_target(state: DeviceState, manifest: Manifest) -> str | None:
    # Never write into the slot serving traffic.
    inactive = [sid for sid in ("A", "B") if not state.slots[sid].active]
    if not inactive:
        return None
    # Prefer the slot whose generation is older.
    inactive.sort(key=lambda sid: (state.slots[sid].generation, sid))
    return inactive[0]


def _abort_events(slot_id: str, case: CaseConfig, state: DeviceState) -> dict[str, Any]:
    # An aborted session is removed by erasing the sectors its partial pages
    # occupy; the catalog expresses that as a single logical abort whose
    # expansion lists the required erases.
    slot = state.slots[slot_id]
    sectors_touched = {
        case.page_sector[p] for p in slot.written_pages
    }
    return {
        "type": "repair_abort",
        "slot": slot_id,
        "sectors": sorted(sectors_touched),
    }


def _full_protocol_events(
    case: CaseConfig,
    state: DeviceState,
    manifest: Manifest,
    target: str,
) -> list[dict[str, Any]] | None:
    slot = state.slots[target]
    events: list[dict[str, Any]] = []

    # Reuse requires erasing every sector that still stores old pages or has
    # a spent budget; a switched-away generation may never be mixed with new
    # pages.  When the slot is already bound to a different manifest, every
    # sector the new image touches must be erased even if its pages happen to
    # be gone, because the update gate refuses cross-generation reuse.
    cross_generation = slot.manifest_id not in (None, manifest.manifest_id)
    dirty_sectors = set()
    for sector in case.sectors:
        needed_here = any(p in manifest.pages for p in sector.pages)
        if any(p in slot.written_pages for p in sector.pages):
            dirty_sectors.add(sector.sector_id)
        elif state.sector_budgets[sector.sector_id] < _needed_budget(case, sector, manifest):
            dirty_sectors.add(sector.sector_id)
        elif cross_generation and needed_here:
            dirty_sectors.add(sector.sector_id)
    for sector_id in sorted(dirty_sectors):
        events.append({"type": "erase", "slot": target, "sector_id": sector_id})

    # If the post-erase budgets cannot hold the whole image, the catalog
    # action is infeasible rather than silently truncating.
    needed = _budget_requirements(case, manifest)
    sim_budget = dict(state.sector_budgets)
    for sector_id in dirty_sectors:
        sector = next(s for s in case.sectors if s.sector_id == sector_id)
        sim_budget[sector_id] = sector.capacity
    for sector_id, need in needed.items():
        if sim_budget[sector_id] < need:
            return None

    events.append(
        {"type": "update", "manifest_id": manifest.manifest_id, "slot": target}
    )
    # Batch pages per sector so the cut enumeration stays small but every page
    # remains its own atomic micro-step.
    for sector in case.sectors:
        pages = [p for p in sector.pages if p in manifest.pages]
        if pages:
            events.append(
                {"type": "program", "manifest_id": manifest.manifest_id, "slot": target, "pages": pages}
            )
    events.append({"type": "verify", "manifest_id": manifest.manifest_id, "slot": target})
    events.append({"type": "mark_ready", "manifest_id": manifest.manifest_id, "slot": target})
    events.append({"type": "trial_start", "manifest_id": manifest.manifest_id, "slot": target})
    events.append(
        {
            "type": "health",
            "manifest_id": manifest.manifest_id,
            "slot": target,
            "receipt_id": f"repair-health-{manifest.manifest_id}-{target}",
        }
    )
    events.append({"type": "trial_end", "manifest_id": manifest.manifest_id, "slot": target})
    events.append({"type": "switch_candidate", "manifest_id": manifest.manifest_id, "slot": target})
    events.append(
        {"type": "switch_confirm_health", "manifest_id": manifest.manifest_id, "slot": target}
    )
    events.append({"type": "counter_raise", "manifest_id": manifest.manifest_id, "slot": target})
    events.append(
        {"type": "switch_publish_active", "manifest_id": manifest.manifest_id, "slot": target}
    )
    return events


def _finish_switch_events(slot: SlotState, manifest: Manifest) -> list[dict[str, Any]]:
    target = slot.slot_id
    events: list[dict[str, Any]] = []
    if not (slot.health or {}).get("confirmed"):
        if slot.health is None:
            events.append(
                {
                    "type": "health",
                    "manifest_id": manifest.manifest_id,
                    "slot": target,
                    "receipt_id": f"repair-health-{manifest.manifest_id}-{target}",
                }
            )
        events.append(
            {"type": "switch_confirm_health", "manifest_id": manifest.manifest_id, "slot": target}
        )
    events.append({"type": "counter_raise", "manifest_id": manifest.manifest_id, "slot": target})
    events.append(
        {"type": "switch_publish_active", "manifest_id": manifest.manifest_id, "slot": target}
    )
    return events


def _needed_budget(case: CaseConfig, sector: Any, manifest: Manifest) -> int:
    return sum(1 for p in sector.pages if p in manifest.pages)


def _budget_requirements(case: CaseConfig, manifest: Manifest) -> dict[str, int]:
    need: dict[str, int] = {}
    for page_id in manifest.pages:
        sec = case.page_sector[page_id]
        need[sec] = need.get(sec, 0) + 1
    return need


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------

def _apply_repair_events(
    state: DeviceState, case: CaseConfig, events: tuple[dict[str, Any], ...]
) -> DeviceState:
    new_state = state.clone()
    for i, event in enumerate(events):
        if event["type"] == "repair_abort":
            new_state = _apply_abort(new_state, case, event)
            continue
        _, _, steps = apply_event(new_state, case, event, 10_000 + i)
        if steps:
            new_state, _ = run_steps(new_state, steps)
    return new_state


def _apply_abort(state: DeviceState, case: CaseConfig, event: dict[str, Any]) -> DeviceState:
    slot_id = event["slot"]
    for sector_id in event["sectors"]:
        _, _, steps = apply_event(
            state,
            case,
            {"type": "erase", "slot": slot_id, "sector_id": sector_id},
            -1,
        )
        if steps:
            state, _ = run_steps(state, steps)
    state.slots[slot_id].session = None
    state.slots[slot_id].readback_verified = []
    return state


def _repair_goal(case: CaseConfig, state: DeviceState, require_service: bool = False) -> bool:
    boot = boot_decision(state, case)
    if require_service:
        return boot["outcome"] == "formal_boot"
    verdict, _ = _verdict_for(case, boot, state, [])
    return verdict in ("pass", "pass_halt")


def _verify_suffix(
    case: CaseConfig, final_state: DeviceState, events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Re-run the cut enumeration over the repair suffix alone."""
    suffix_case = _suffix_view(case, final_state, events)
    cuts = micro_cuts(suffix_case)
    checked = 0
    bad: list[dict[str, Any]] = []
    from itertools import combinations

    for k in range(0, min(case.max_power_losses, 2) + 1):
        for combo in combinations(range(len(cuts)), k):
            if k and not _ordered(cuts, combo):
                continue
            state = suffix_case.initial_state.clone()
            cut_ids = [cuts[i]["cut_id"] for i in combo]
            cut_lookup = {cuts[i]["event_index"]: cuts[i]["prefix"] for i in combo}
            for index, event in enumerate(suffix_case.events):
                _, _, steps = apply_event(state, suffix_case, event, index)
                if not steps:
                    continue
                prefix = cut_lookup.get(index)
                state, _ = run_steps(state, steps, prefix)
            boot = boot_decision(state, suffix_case)
            verdict, reason = _verdict_for(suffix_case, boot, state, [])
            checked += 1
            if verdict == "fail":
                bad.append({"cut_trace": cut_ids, "reason": reason, "boot": boot})
    return {
        "scenarios_checked": checked,
        "failures": bad,
        "pass": not bad,
        "witnesses": _witnesses(final_state, case, boot_decision(final_state, case)),
    }


def _ordered(cuts: list[dict[str, Any]], combo: tuple[int, ...]) -> bool:
    # Mirror check semantics: losses must fall on distinct macro events and
    # in strictly increasing order.
    event_indexes = [cuts[i]["event_index"] for i in combo]
    if len(set(event_indexes)) != len(event_indexes):
        return False
    for a, b in zip(combo, combo[1:]):
        if (cuts[b]["event_index"], cuts[b]["prefix"]) <= (
            cuts[a]["event_index"],
            cuts[a]["prefix"],
        ):
            return False
    return True


def _suffix_view(
    case: CaseConfig, start: DeviceState, events: list[dict[str, Any]]
) -> CaseConfig:
    return CaseConfig(
        schema_version=case.schema_version,
        case_id=case.case_id + "#repair",
        device_group=case.device_group,
        policy=case.policy,
        max_power_losses=case.max_power_losses,
        sectors=case.sectors,
        manifests=case.manifests,
        initial_state=start,
        events=events,
        manifest_by_id=case.manifest_by_id,
        page_sector=case.page_sector,
        repair_depth=case.repair_depth,
    )
