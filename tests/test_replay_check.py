"""Tests for the bounded power-loss cut enumeration and check verdict."""

from __future__ import annotations

import unittest

from boot_replay.check import check
from boot_replay.engine import boot_decision
from boot_replay.replay import micro_cuts, replay, state_after_cut

from ._helpers import load_generated
from .test_protocol import small_pages, two_slot_doc


class ReplayScenarioTests(unittest.TestCase):
    def test_happy_16x64_structure(self):
        case = load_generated("happy-16x64")
        report = replay(case)
        self.assertEqual(report["summary"]["events"], 16)
        self.assertEqual(report["summary"]["program_writes"], 64)
        self.assertEqual(report["summary"]["rejected"], 0)
        self.assertEqual(report["summary"]["active_slot"], "B")

    def test_every_cut_state_is_a_deep_copy(self):
        case = load_generated("batch-resume")
        cuts = micro_cuts(case)
        self.assertGreater(len(cuts), 0)
        first = cuts[0]
        s1, _ = state_after_cut(case, first["event_index"], first["prefix"])
        s2, _ = state_after_cut(case, first["event_index"], first["prefix"])
        self.assertEqual(s1.canonical(), s2.canonical())
        s1.counter = 999
        self.assertNotEqual(s1.canonical(), s2.canonical())

    def test_power_loss_mid_program_is_resumable(self):
        case = load_generated("batch-resume")
        report = replay(case)
        self.assertEqual(report["summary"]["rejected"], 0)
        final = report["boot_snapshots"][-1]
        self.assertEqual(final["outcome"], "formal_boot")
        self.assertEqual(final["slot"], "B")

    def test_half_each_never_boots_an_incomplete_region(self):
        case = load_generated("half-each")
        decision = boot_decision(case.initial_state.clone(), case)
        self.assertEqual(decision["outcome"], "safe_halt")
        for reason in decision["slot_reasons"]:
            self.assertIn(reason["reason"], ("incomplete", "no_manifest"))

    def test_revoked_old_image_forces_safe_halt(self):
        case = load_generated("revoked-old-halt")
        report = replay(case)
        final = report["boot_snapshots"][-1]
        self.assertEqual(final["outcome"], "safe_halt")
        self.assertTrue(
            any(r["reason"] == "authorization_revoked" for r in final["slot_reasons"])
        )


class CheckEnumerationTests(unittest.TestCase):
    def test_happy_path_passes_all_cuts(self):
        report = check(load_generated("happy-16x64"))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["failure_count"], 0)

    def test_check_evaluates_zero_one_and_two_loss_combos(self):
        report = check(load_generated("counter-no-active"))
        # 1 zero-loss + n single-loss + every two-cut pair on *distinct*
        # macro events (two losses inside one event collapse to one).
        n = report["summary"]["cut_points"]
        cuts = micro_cuts(load_generated("counter-no-active"))
        distinct_pairs = 0
        for i in range(n):
            for j in range(i + 1, n):
                if cuts[i]["event_index"] != cuts[j]["event_index"]:
                    distinct_pairs += 1
        expected = 1 + n + distinct_pairs
        self.assertEqual(report["summary"]["scenarios_evaluated"], expected)

    def test_counter_no_active_recovers_to_formal_boot(self):
        report = check(load_generated("counter-no-active"))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["baseline_boot"]["outcome"], "formal_boot")

    def test_revoke_race_keeps_old_image_serviceable(self):
        report = check(load_generated("revoke-race"))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["baseline_boot"]["slot"], "A")

    def test_safe_halt_scenarios_are_listed_with_witnesses(self):
        report = check(load_generated("revoked-old-halt"))
        self.assertGreater(report["summary"]["safe_halts"], 0)
        for halt in report["safe_halt_scenarios"]:
            self.assertEqual(halt["boot"]["outcome"], "safe_halt")
            self.assertIn("slot_reasons", halt["boot"])

    def test_maintain_policy_failure_when_trusted_image_stranded(self):
        # Counter already at 2; B holds a trusted gen-2 image but never got the
        # candidate/active markers (so it is not selectable), and A holds a
        # still-trusted gen-1 image stranded below the floor.  Nothing is
        # formally bootable -> maintain policy must report a failure with the
        # below-floor witness.
        from boot_replay.loader import load_case
        from boot_replay.model import page_summary

        pages = small_pages(4)
        doc = two_slot_doc()
        old_pages = doc["manifests"][0]["pages"]
        new_pages = doc["manifests"][1]["pages"]
        doc["initial"]["counter"] = 2
        doc["initial"]["slots"]["A"] = {
            "generation": 1,
            "manifest_id": "M1",
            "written_pages": old_pages,
            "ready": True,
            "sig_entry": {
                "manifest_id": "M1", "version": 1, "generation": 1,
                "auth_id": "AUTH-1", "signer": "signer-AUTH-1",
                "digest_witness": page_summary(old_pages),
            },
            "candidate": False, "active": False, "trial": None, "health": None,
            "session": None, "readback_verified": pages, "erase_count": 0,
        }
        doc["initial"]["slots"]["B"] = {
            "generation": 2,
            "manifest_id": "M2",
            # Only half the new image persisted: incomplete regions can never
            # be rollback targets, so B cannot be selected either.
            "written_pages": {p: new_pages[p] for p in pages[:2]},
            "ready": False,
            "sig_entry": None,
            "candidate": False, "active": False, "trial": None, "health": None,
            "session": None, "readback_verified": [], "erase_count": 0,
        }
        doc["events"] = []
        report = check(load_case(doc))
        self.assertEqual(report["status"], "fail")
        failure = report["shortest_failure"]
        self.assertIn("availability_violation", failure["violation"])
        self.assertEqual(failure["boot"]["trusted_below_floor"], ["A"])

    def test_halt_allowed_policy_accepts_identical_state(self):
        doc = two_slot_doc()
        doc["policy"] = {"fallback": "halt_allowed"}
        doc["events"] = []
        from boot_replay.loader import load_case
        case = load_case(doc)
        report = check(case)
        self.assertIn(report["status"], ("pass", "pass_with_halts"))


def initial_slot_empty():
    return {
        "generation": 0,
        "manifest_id": None,
        "written_pages": {},
        "ready": False,
        "sig_entry": None,
        "candidate": False,
        "active": False,
        "trial": None,
        "health": None,
        "session": None,
        "readback_verified": [],
        "erase_count": 0,
    }


class PrefixCutTests(unittest.TestCase):
    def test_prefix_zero_loses_every_micro_step(self):
        case = load_generated("happy-16x64")
        cuts = micro_cuts(case)
        first_program = next(c for c in cuts if c["event_type"] == "program")
        state, applied = state_after_cut(
            case, first_program["event_index"], 0
        )
        # The update session opened, but no page of the program batch persisted.
        self.assertEqual(state.program_writes, 0)
        self.assertIsNotNone(state.slots["B"].session)

    def test_full_prefix_equals_clean_replay(self):
        case = load_generated("batch-resume")
        cuts = micro_cuts(case)
        last = cuts[-1]
        state, _ = state_after_cut(case, last["event_index"], last["prefix"])
        clean = replay(case)
        self.assertEqual(
            state.canonical(),
            _canonical_from_report(clean),
        )


def _canonical_from_report(report):
    from boot_replay.model import DeviceState, SlotState
    raw = report["final_state"]
    slots = {}
    for sid, s in raw["slots"].items():
        slots[sid] = SlotState(
            slot_id=sid,
            generation=s["generation"],
            manifest_id=s["manifest_id"],
            written_pages=dict(s["written_pages"]),
            ready=s["ready"],
            sig_entry=s["sig_entry"],
            candidate=s["candidate"],
            active=s["active"],
            trial=s["trial"],
            health=s["health"],
            session=s["session"],
            readback_verified=list(s["readback_verified"]),
            erase_count=s["erase_count"],
        )
    return DeviceState(
        slots=slots,
        counter=raw["counter"],
        revoked_manifests=set(raw["revoked_manifests"]),
        sector_budgets=dict(raw["sector_budgets"]),
        program_writes=raw["program_writes"],
    ).canonical()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
