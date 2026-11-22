"""Tests for the approved-action repair planner and its cost optimization."""

from __future__ import annotations

import unittest

from boot_replay.check import check
from boot_replay.loader import load_case
from boot_replay.repair import repair

from .test_protocol import happy_events, run_doc, two_slot_doc


class RepairPlannerTests(unittest.TestCase):
    def test_repair_completes_switch_when_only_active_marker_missing(self):
        # Drive the protocol up to counter_raise, then start repair from the
        # resulting persisted state.
        case, state, _ = run_doc(happy_events()[:10])
        self.assertEqual(state.counter, 2)
        self.assertTrue(state.slots["B"].candidate)
        doc = _doc_from_state(case, state, events=[])
        report = repair(load_case(doc))
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["final_boot"]["outcome"], "formal_boot")
        self.assertTrue(report["cut_verification"]["pass"])

    def test_repair_rebuilds_inactive_slot_from_half_image(self):
        case = load_generated_case("half-each")
        report = repair(case)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["final_boot"]["outcome"], "formal_boot")
        # A full update requires erasing the sectors holding stale half pages.
        self.assertGreaterEqual(report["cost"]["sector_erases"], 1)
        self.assertTrue(report["cut_verification"]["pass"])

    def test_repair_cost_ordering_prefers_fewer_erases(self):
        case = load_generated_case("half-each")
        report = repair(case)
        costs = [
            (a["sector_erases"], a["action_count"], tuple(a["action_id_sequence"]))
            for a in [report["cost"], *report["alternatives"]]
        ]
        self.assertEqual(costs, sorted(costs))

    def test_repair_never_targets_the_active_slot(self):
        # Whatever slot carries the active marker in the initial state must
        # never appear as an erase/update/program target in the repair plan.
        case = load_generated_case("counter-no-active")
        active = next(
            sid for sid, s in case.initial_state.slots.items() if s.active
        )
        report = repair(case)
        for event in report["repair_events"]:
            if event.get("slot") == active:
                self.assertNotIn(event["type"], ("erase", "update", "program"))

    def test_repair_under_halt_allowed_accepts_empty_sequence(self):
        doc = two_slot_doc()
        doc["policy"] = {"fallback": "halt_allowed"}
        doc["initial"]["slots"]["A"] = {
            "generation": 1, "manifest_id": None, "written_pages": {},
            "ready": False, "sig_entry": None, "candidate": False,
            "active": False, "trial": None, "health": None, "session": None,
            "readback_verified": [], "erase_count": 0,
        }
        doc["events"] = []
        report = repair(load_case(doc))
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["cost"]["action_count"], 0)

    def test_repaired_sequence_passes_full_check(self):
        case = load_generated_case("half-each")
        report = repair(case)
        # Replay the emitted events onto the initial state and re-run check on
        # the resulting case to prove the repair is check-passing end to end.
        from boot_replay.replay import replay
        doc = _case_doc(case)
        doc["events"] = report["repair_events"]
        repaired = load_case(doc)
        replay_report = replay(repaired)
        self.assertEqual(replay_report["boot_snapshots"][-1]["outcome"], "formal_boot")
        check_report = check(repaired)
        self.assertEqual(check_report["status"], "pass")

    def test_no_repair_when_every_authorization_revoked(self):
        doc = two_slot_doc()
        doc["initial"]["revoked_manifests"] = ["M1", "M2"]
        doc["events"] = []
        report = repair(load_case(doc))
        self.assertEqual(report["status"], "no_repair")


def load_generated_case(name):
    from ._helpers import load_generated
    return load_generated(name)


def _case_doc(case):
    return {
        "schema_version": 1,
        "case_id": case.case_id,
        "device_group": case.device_group,
        "policy": {"fallback": case.policy.fallback},
        "max_power_losses": case.max_power_losses,
        "sectors": [
            {"sector_id": s.sector_id, "pages": s.pages, "capacity": s.capacity}
            for s in case.sectors
        ],
        "manifests": [
            {
                "manifest_id": m.manifest_id,
                "version": m.version,
                "device_group": m.device_group,
                "authorized_generation": m.authorized_generation,
                "pages": m.pages,
                "auth_id": m.auth_id,
                "signer": m.signer,
            }
            for m in case.manifests
        ],
        "initial": _initial_payload(case, case.initial_state),
        "events": [],
    }


def _doc_from_state(case, state, events):
    doc = _case_doc(case)
    doc["initial"] = _initial_payload(case, state)
    doc["events"] = events
    return doc


def _initial_payload(case, state):
    return {
        "counter": state.counter,
        "sector_budgets": dict(state.sector_budgets),
        "revoked_manifests": sorted(state.revoked_manifests),
        "slots": {
            sid: {
                "generation": s.generation,
                "manifest_id": s.manifest_id,
                "written_pages": dict(s.written_pages),
                "ready": s.ready,
                "sig_entry": s.sig_entry,
                "candidate": s.candidate,
                "active": s.active,
                "trial": s.trial,
                "health": s.health,
                "session": s.session,
                "readback_verified": sorted(s.readback_verified),
                "erase_count": s.erase_count,
            }
            for sid, s in state.slots.items()
        },
    }


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
