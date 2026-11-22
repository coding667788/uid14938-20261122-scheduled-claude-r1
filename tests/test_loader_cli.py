"""Loader validation (field-level error paths) and CLI determinism tests."""

from __future__ import annotations

import copy
import io
import json
import unittest

from boot_replay.cli import dumps, main
from boot_replay.errors import CaseError
from boot_replay.loader import load_case

from ._helpers import load_generated


class LoaderErrorTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(
            json.dumps(_case_dict(load_generated("late-health")))
        )

    def test_unknown_event_type_points_at_event(self):
        self.doc["events"][0]["type"] = "bogus"
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.events[0].type")

    def test_bad_type_names_concrete_field(self):
        self.doc["initial"]["counter"] = "1"
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.initial.counter")

    def test_duplicate_manifest_id(self):
        self.doc["manifests"][1]["manifest_id"] = self.doc["manifests"][0]["manifest_id"]
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertIn("duplicate manifest_id", ctx.exception.detail)

    def test_manifest_wrong_device_group(self):
        self.doc["manifests"][0]["device_group"] = "other-group"
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.manifests[0].device_group")

    def test_unknown_page_in_event(self):
        self.doc["events"][1]["pages"] = ["nope"]
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.events[1].pages[0]")

    def test_duplicate_health_receipt(self):
        ids = [e.get("receipt_id") for e in self.doc["events"] if "receipt_id" in e]
        self.doc["events"].append(
            {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": ids[0]}
        )
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertIn("duplicate health receipt", ctx.exception.detail)

    def test_ready_slot_must_be_complete(self):
        self.doc["initial"]["slots"]["A"]["ready"] = True
        self.doc["initial"]["slots"]["A"]["written_pages"].pop("p0")
        self.doc["initial"]["slots"]["A"]["readback_verified"].remove("p0")
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.initial.slots.A.ready")

    def test_two_active_markers_rejected(self):
        self.doc["initial"]["slots"]["B"] = copy.deepcopy(
            self.doc["initial"]["slots"]["A"]
        )
        self.doc["initial"]["slots"]["B"]["active"] = True
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.initial.slots")

    def test_budget_below_zero_rejected(self):
        self.doc["initial"]["sector_budgets"]["S0"] = -1
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertIn("S0", ctx.exception.path)

    def test_unknown_revoked_manifest(self):
        self.doc["initial"]["revoked_manifests"] = ["ghost"]
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertIn("revoked_manifests[0]", ctx.exception.path)

    def test_unsupported_schema_version(self):
        self.doc["schema_version"] = 99
        with self.assertRaises(CaseError) as ctx:
            load_case(self.doc)
        self.assertEqual(ctx.exception.path, "$.schema_version")


class CliTests(unittest.TestCase):
    def test_dumps_is_deterministic(self):
        payload = {"b": 1, "a": {"z": [1, 2], "y": "x"}}
        self.assertEqual(dumps(payload), dumps(payload))
        self.assertIn("\n", dumps(payload) + "\n")

    def test_cli_writes_json_error_for_bad_case(self, tmp_path=None):
        import tempfile, os
        bad = {"schema_version": 1}
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(bad, fh)
            buf = io.StringIO()
            import sys
            old = sys.stdout
            sys.stdout = buf
            try:
                code = main(["replay", path])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["error"], "case_error")
            self.assertIn("path", payload)
        finally:
            os.remove(path)

    def test_cli_usage_error(self):
        import sys
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            code = main([])
        finally:
            sys.stdout = old
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(buf.getvalue())["error"], "usage")


def _case_dict(case):
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
        "initial": {
            "counter": case.initial_state.counter,
            "sector_budgets": dict(case.initial_state.sector_budgets),
            "revoked_manifests": sorted(case.initial_state.revoked_manifests),
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
                for sid, s in case.initial_state.slots.items()
            },
        },
        "events": case.events,
    }


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
