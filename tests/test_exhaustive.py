"""Exhaustive small-page differential tests ("对拍").

A deliberately independent, naive reference implementation re-derives every
trust/boot predicate straight from the persisted state without reusing the
engine's predicate methods.  We then enumerate all reachable states of small
page-count devices (every legal power-loss prefix) and assert the engine's
:func:`boot_decision` agrees with the reference on every single state.

Two independent engines are compared as well: the macro-level
:func:`~boot_replay.replay.replay` driver and the micro-step cut reconstructor
must produce byte-identical canonical states when they claim to.
"""

from __future__ import annotations

import unittest

from boot_replay.engine import boot_decision
from boot_replay.loader import load_case
from boot_replay.replay import micro_cuts, replay, state_after_cut

from ._helpers import (
    GROUP,
    initial_slot,
    manifest,
    manifest_pages,
    sectors_def,
    sig_for,
    small_pages,
)


# ---------------------------------------------------------------------------
# Independent reference implementation (naive, separate logic)
# ---------------------------------------------------------------------------

def reference_boot(state, case):
    """Plain re-derivation of the boot rule from raw persisted fields."""
    bootable = []
    for sid in ("A", "B"):
        s = state.slots[sid]
        m = case.manifest_by_id.get(s.manifest_id) if s.manifest_id else None
        if m is None:
            continue
        if s.trial is not None:
            continue
        if s.candidate:
            # candidate only bootable via recovery publish when floor reached
            # and health confirmed; handled below.
            pass
        if not s.ready or s.sig_entry is None:
            continue
        if set(s.written_pages.items()) != set(m.pages.items()):
            continue
        if m.manifest_id in state.revoked_manifests:
            continue
        if s.sig_entry.get("generation") != m.authorized_generation:
            continue
        if s.generation != m.authorized_generation:
            continue
        if s.generation < state.counter:
            continue
        if s.candidate:
            # Recovery publish is allowed only when the counter floor has
            # already reached the candidate generation and health is
            # confirmed for that generation.
            if state.counter != s.generation:
                continue
            if not (s.health or {}).get("confirmed"):
                continue
        bootable.append(s)
    if not bootable:
        return "safe_halt", None
    bootable.sort(key=lambda s: (-s.generation, 0 if s.active else 1, s.slot_id))
    return "formal_boot", bootable[0].slot_id


def all_prefix_states(case):
    """Reconstruct the persisted state at every micro-step cut point."""
    cuts = micro_cuts(case)
    states = [case.initial_state.clone()]
    for cut in cuts:
        state, _ = state_after_cut(case, cut["event_index"], cut["prefix"])
        states.append(state)
    return cuts, states


class DifferentialTests(unittest.TestCase):
    def test_engine_matches_reference_on_happy_enumeration(self):
        case = _exhaustive_case(pages=3)
        cuts, states = all_prefix_states(case)
        mismatches = []
        for state in states:
            engine = boot_decision(state, case)
            ref_outcome, ref_slot = reference_boot(state, case)
            if engine["outcome"] != ref_outcome:
                mismatches.append(("outcome", state.canonical()))
                continue
            if ref_outcome == "formal_boot" and engine["slot"] != ref_slot:
                mismatches.append(("slot", engine["slot"], ref_slot, state.canonical()))
        self.assertEqual(mismatches, [])
        self.assertGreater(len(states), 10)

    def test_engine_matches_reference_under_revocation(self):
        case = _exhaustive_case(pages=3, revoke_at=6)
        _, states = all_prefix_states(case)
        for state in states:
            engine = boot_decision(state, case)
            ref_outcome, ref_slot = reference_boot(state, case)
            self.assertEqual(engine["outcome"], ref_outcome)
            if ref_outcome == "formal_boot":
                self.assertEqual(engine["slot"], ref_slot)

    def test_macro_and_micro_drivers_agree_on_final_state(self):
        for pages in (2, 3, 4):
            case = _exhaustive_case(pages=pages)
            macro = replay(case)
            cuts = micro_cuts(case)
            last = cuts[-1]
            micro_state, _ = state_after_cut(
                case, last["event_index"], last["prefix"]
            )
            from .test_replay_check import _canonical_from_report
            self.assertEqual(micro_state.canonical(), _canonical_from_report(macro))

    def test_every_cut_is_a_legal_prefix(self):
        case = _exhaustive_case(pages=3)
        cuts = micro_cuts(case)
        for cut in cuts:
            self.assertGreaterEqual(cut["prefix"], 0)
            self.assertLessEqual(cut["prefix"], cut["total_steps"])
            self.assertEqual(len(cut["step_ids"]), cut["total_steps"])

    def test_written_pages_never_exceed_manifest_pages(self):
        case = _exhaustive_case(pages=3)
        _, states = all_prefix_states(case)
        for state in states:
            for sid in ("A", "B"):
                s = state.slots[sid]
                m = case.manifest_by_id.get(s.manifest_id) if s.manifest_id else None
                if m is None:
                    self.assertEqual(s.written_pages, {})
                else:
                    self.assertTrue(set(s.written_pages).issubset(set(m.pages)))

    def test_counter_never_decreases_across_any_prefix(self):
        case = _exhaustive_case(pages=3)
        cuts, states = all_prefix_states(case)
        prev = case.initial_state.counter
        for state in states:
            self.assertGreaterEqual(state.counter, prev)
            prev = state.counter

    def test_budget_accounting_balances_with_program_writes(self):
        case = _exhaustive_case(pages=4)
        initial_budget = sum(case.initial_state.sector_budgets.values())
        capacity = {s.sector_id: s.capacity for s in case.sectors}
        _, states = all_prefix_states(case)
        # This sequence contains no erase events, so the identity is exact.
        for state in states:
            remaining = sum(state.sector_budgets.values())
            self.assertEqual(remaining + state.program_writes, initial_budget)
            self.assertEqual(sum(s.erase_count for s in state.slots.values()), 0)
        # And the sector-level invariant holds per sector.
        for state in states:
            for sector_id, budget in state.sector_budgets.items():
                self.assertGreaterEqual(budget, 0)
                self.assertLessEqual(budget, capacity[sector_id])

    def test_full_state_space_three_pages_two_generations(self):
        # Brute-force agreement across two independent random-free sequences.
        for builder in (_exhaustive_case, _exhaustive_trial_case):
            case = builder(pages=3)
            _, states = all_prefix_states(case)
            for state in states:
                engine = boot_decision(state, case)
                ref_outcome, _ = reference_boot(state, case)
                self.assertEqual(engine["outcome"], ref_outcome)


def _exhaustive_case(pages=3, revoke_at=None):
    page_ids = small_pages(pages)
    sectors = sectors_def(page_ids, max(1, pages // 2 + 1))
    # Fix sector sizes to cover all pages (sectors_def chunks evenly).
    old = manifest_pages(page_ids, "gen1")
    new = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[:1]},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids},
    ]
    if revoke_at is not None:
        events.insert(revoke_at, {"type": "revoke", "manifest_id": "M1"})
    events += [
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "r1"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_candidate", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_publish_active", "manifest_id": "M2", "slot": "B"},
    ]
    doc = {
        "schema_version": 1,
        "case_id": f"diff-{pages}",
        "device_group": GROUP,
        "policy": {"fallback": "maintain"},
        "max_power_losses": 2,
        "sectors": sectors,
        "manifests": [m1, m2],
        "initial": {
            "counter": 1,
            "sector_budgets": {s["sector_id"]: s["capacity"] for s in sectors},
            "revoked_manifests": [],
            "slots": {
                "A": initial_slot("M1", 1, old, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
                "B": initial_slot(None, 0, {}),
            },
        },
        "events": events,
    }
    return load_case(doc)


def _exhaustive_trial_case(pages=3):
    page_ids = small_pages(pages)
    sectors = sectors_def(page_ids, max(1, pages // 2 + 1))
    old = manifest_pages(page_ids, "gen1")
    new = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids},
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        # No health yet: cut states here must keep booting A.
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "r-trial"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
    ]
    doc = {
        "schema_version": 1,
        "case_id": f"diff-trial-{pages}",
        "device_group": GROUP,
        "policy": {"fallback": "maintain"},
        "max_power_losses": 2,
        "sectors": sectors,
        "manifests": [m1, m2],
        "initial": {
            "counter": 1,
            "sector_budgets": {s["sector_id"]: s["capacity"] for s in sectors},
            "revoked_manifests": [],
            "slots": {
                "A": initial_slot("M1", 1, old, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
                "B": initial_slot(None, 0, {}),
            },
        },
        "events": events,
    }
    return load_case(doc)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
