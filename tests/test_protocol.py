"""Protocol-level tests: update lifecycle, markers, trials, counter rules."""

from __future__ import annotations

import unittest

from boot_replay.engine import apply_event, boot_decision, run_steps
from boot_replay.loader import load_case

from ._helpers import GROUP, initial_slot, manifest, manifest_pages, sectors_def, sig_for, small_pages


def two_slot_doc(tmp_path=None):
    pages = small_pages(4)
    sectors = sectors_def(pages, 2)
    old = manifest_pages(pages, "gen1")
    new = manifest_pages(pages, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new, "AUTH-2")
    return {
        "schema_version": 1,
        "case_id": "unit-protocol",
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
                "A": initial_slot("M1", 1, old, ready=True, active=True, sig=sig_for(m1), readback=pages),
                "B": initial_slot(None, 0, {}),
            },
        },
        "events": [],
    }


def happy_events(manifest_id="M2", slot="B", pages=None, receipt="rcpt-1"):
    pages = pages or small_pages(4)
    return [
        {"type": "update", "manifest_id": manifest_id, "slot": slot},
        {"type": "program", "manifest_id": manifest_id, "slot": slot, "pages": pages},
        {"type": "verify", "manifest_id": manifest_id, "slot": slot},
        {"type": "mark_ready", "manifest_id": manifest_id, "slot": slot},
        {"type": "trial_start", "manifest_id": manifest_id, "slot": slot},
        {"type": "health", "manifest_id": manifest_id, "slot": slot, "receipt_id": receipt},
        {"type": "trial_end", "manifest_id": manifest_id, "slot": slot},
        {"type": "switch_candidate", "manifest_id": manifest_id, "slot": slot},
        {"type": "switch_confirm_health", "manifest_id": manifest_id, "slot": slot},
        {"type": "counter_raise", "manifest_id": manifest_id, "slot": slot},
        {"type": "switch_publish_active", "manifest_id": manifest_id, "slot": slot},
    ]


def run_doc(events, doc=None):
    doc = doc or two_slot_doc()
    doc["events"] = events
    case = load_case(doc)
    state = case.initial_state.clone()
    results = []
    for i, ev in enumerate(events):
        state, result, steps = apply_event(state, case, ev, i)
        if steps:
            state, _ = run_steps(state, steps)
        results.append(result)
    return case, state, results


class ProtocolTests(unittest.TestCase):
    def test_full_happy_lifecycle_promotes_b(self):
        case, state, results = run_doc(happy_events())
        self.assertTrue(all(r.status == "applied" for r in results))
        self.assertEqual(state.counter, 2)
        self.assertTrue(state.slots["B"].active)
        self.assertFalse(state.slots["A"].active)
        decision = boot_decision(state, case)
        self.assertEqual(decision["outcome"], "formal_boot")
        self.assertEqual(decision["slot"], "B")
        self.assertEqual(decision["generation"], 2)

    def test_ready_requires_full_readback(self):
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": small_pages(4)[:2]},
            {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("incomplete", results[-1].reason)

    def test_mark_ready_without_verify_rejected(self):
        pages = small_pages(4)
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages},
            {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("read back", results[-1].reason)

    def test_trial_cannot_serve_external_traffic(self):
        events = happy_events()[:5]  # stop right after trial_start
        case, state, results = run_doc(events)
        self.assertEqual(results[-1].status, "applied")
        b = state.slots["B"]
        self.assertIsNotNone(b.trial)
        self.assertTrue(b.trial["isolation"])
        self.assertFalse(b.trial["external_service"])
        # While in trial B is not formally bootable; A keeps serving.
        decision = boot_decision(state, case)
        self.assertEqual(decision["slot"], "A")

    def test_counter_raise_needs_surviving_bootable_copy(self):
        # Remove A's trustworthiness by revoking M1 before the raise: the
        # engine must refuse to strand the device with no bootable copy.
        events = happy_events()[:9] + [
            {"type": "revoke", "manifest_id": "M1"},
            {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
        ]
        case, state, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("no complete trusted bootable copy", results[-1].reason)
        self.assertEqual(state.counter, 1)  # counter did not move

    def test_counter_is_monotonic(self):
        events = happy_events()
        # Re-raising the same generation after completion must be rejected:
        # the slot already lost its candidate marker on publish.
        events.append({"type": "counter_raise", "manifest_id": "M2", "slot": "B"})
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("candidate marker", results[-1].reason)

    def test_switch_steps_are_individually_gated(self):
        for stop_at in range(8, 11):
            events = happy_events()[:stop_at]
            _, state, _ = run_doc(events)
            b = state.slots["B"]
            if stop_at == 8:
                self.assertTrue(b.candidate)
                self.assertFalse((b.health or {}).get("confirmed"))
            elif stop_at == 9:
                self.assertTrue((b.health or {}).get("confirmed"))
                self.assertEqual(state_counter := state.counter, 1)
            elif stop_at == 10:
                self.assertEqual(state.counter, 2)
                self.assertFalse(b.active)

    def test_publish_active_requires_counter_floor(self):
        events = happy_events()[:9] + [
            # Try to publish before raising the counter.
            {"type": "switch_publish_active", "manifest_id": "M2", "slot": "B"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("counter floor", results[-1].reason)

    def test_revocation_during_candidate_blocks_confirmation(self):
        events = happy_events()[:8] + [
            {"type": "revoke", "manifest_id": "M2"},
            {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        ]
        _, state, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("revoked", results[-1].reason)
        self.assertEqual(state.counter, 1)

    def test_late_health_receipt_after_trial_closed(self):
        events = happy_events()[:7] + [
            {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "late-rcpt"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")
        self.assertIn("late", results[-1].reason)

    def test_health_receipt_is_generation_bound(self):
        pages = small_pages(4)
        # Finish an M2 trial, then a stale receipt referencing M1 is rejected.
        events = happy_events()[:7]
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages},
            {"type": "verify", "manifest_id": "M2", "slot": "B"},
            {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
            {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
            {"type": "health", "manifest_id": "M1", "slot": "B", "receipt_id": "stale"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")

    def test_retry_matches_original_application(self):
        pages = small_pages(4)
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages[:2]},
            # Retry of the same application: session reopen is idempotent.
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages},
        ]
        case, state, results = run_doc(events)
        # The idempotent reopen is an applied macro event with zero new
        # micro-steps; the second program only writes the two missing pages.
        self.assertEqual([r.status for r in results], ["applied", "applied", "applied", "applied"])
        self.assertEqual(results[2].steps, [])
        self.assertEqual(len(state.slots["B"].written_pages), 4)
        self.assertEqual(state.program_writes, 4)
        # A different manifest against the open session is refused.
        state2, result2, steps2 = apply_event(
            state, case, {"type": "update", "manifest_id": "M1", "slot": "B"}, 99
        )
        self.assertEqual(result2.status, "rejected")
        self.assertIn("open write session", result2.reason)

    def test_old_pages_cannot_mix_into_new_generation(self):
        pages = small_pages(4)
        new = manifest_pages(pages, "gen2")
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages[:1]},
            # Erase is required before a different generation can use the slot.
            {"type": "update", "manifest_id": "M1", "slot": "B"},
        ]
        _, _, results = run_doc(events)
        self.assertEqual(results[-1].status, "rejected")

    def test_erase_refuses_active_slot(self):
        doc = two_slot_doc()
        doc["events"] = [{"type": "erase", "slot": "A", "sector_id": "S0"}]
        case = load_case(doc)
        _, result, steps = apply_event(case.initial_state.clone(), case, doc["events"][0], 0)
        self.assertEqual(result.status, "rejected")
        self.assertIn("external traffic", result.reason)

    def test_erase_restores_budget_and_clears_partial_markers(self):
        pages = small_pages(4)
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages[:2]},
            {"type": "erase", "slot": "B", "sector_id": "S0"},
        ]
        case, state, results = run_doc(events)
        self.assertEqual(results[-1].status, "applied")
        self.assertEqual(state.sector_budgets["S0"], 2)
        self.assertEqual(state.slots["B"].erase_count, 1)
        self.assertNotIn("p0", state.slots["B"].written_pages)

    def test_written_complete_is_not_bootable_until_published(self):
        # All pages written and even read back, but READY/signature were never
        # published: fully written != trusted bootable.
        pages = small_pages(4)
        events = [
            {"type": "update", "manifest_id": "M2", "slot": "B"},
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": pages},
            {"type": "verify", "manifest_id": "M2", "slot": "B"},
        ]
        case, state, _ = run_doc(events)
        b = state.slots["B"]
        self.assertTrue(b.is_complete(case))
        self.assertFalse(b.ready)
        self.assertFalse(b.trusted_complete(case, state.revoked_manifests))
        decision = boot_decision(state, case)
        self.assertEqual(decision["slot"], "A")

    def test_incomplete_region_is_never_a_rollback_target(self):
        # Both slots incomplete: the boot rule must safe-halt rather than pick
        # a partial image.
        pages = small_pages(4)
        new = manifest_pages(pages, "gen2")
        doc = two_slot_doc()
        doc["initial"]["slots"]["A"] = {
            "generation": 1, "manifest_id": "M1",
            "written_pages": {p: doc["manifests"][0]["pages"][p] for p in pages[:1]},
            "ready": False, "sig_entry": None, "candidate": False,
            "active": False, "trial": None, "health": None, "session": None,
            "readback_verified": [], "erase_count": 0,
        }
        doc["initial"]["slots"]["B"] = {
            "generation": 2, "manifest_id": "M2",
            "written_pages": {p: new[p] for p in pages[:2]},
            "ready": False, "sig_entry": None, "candidate": False,
            "active": False, "trial": None, "health": None, "session": None,
            "readback_verified": [], "erase_count": 0,
        }
        doc["events"] = []
        case = load_case(doc)
        decision = boot_decision(case.initial_state.clone(), case)
        self.assertEqual(decision["outcome"], "safe_halt")
        for reason in decision["slot_reasons"]:
            self.assertEqual(reason["reason"], "incomplete")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
