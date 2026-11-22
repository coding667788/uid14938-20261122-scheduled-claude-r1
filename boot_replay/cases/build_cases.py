"""Deterministic synthetic CASE.json generation.

Running this module writes the shipped replayable examples into
``cases/generated/``::

    python -m boot_replay.cases.build_cases

All digests, receipt ids and budgets are derived from fixed strings so the
output byte-for-byte reproduces.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..model import page_summary

CASES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "cases",
    "generated",
)


def digest(page_id: str, tag: str) -> str:
    return "sha256:" + page_summary({page_id: f"digest-{tag}-{page_id}"})


def manifest_pages(page_ids: list[str], tag: str) -> dict[str, str]:
    return {pid: digest(pid, tag) for pid in page_ids}


def sectors_def(page_ids: list[str], pages_per_sector: int, capacity: int | None = None) -> list[dict[str, Any]]:
    out = []
    for i in range(0, len(page_ids), pages_per_sector):
        chunk = page_ids[i : i + pages_per_sector]
        sid = f"S{i // pages_per_sector}"
        out.append(
            {
                "sector_id": sid,
                "pages": chunk,
                "capacity": capacity if capacity is not None else len(chunk),
            }
        )
    return out


def manifest(mid: str, version: int, group: str, generation: int, pages: dict[str, str], auth: str) -> dict[str, Any]:
    return {
        "manifest_id": mid,
        "version": version,
        "device_group": group,
        "authorized_generation": generation,
        "pages": pages,
        "auth_id": auth,
        "signer": f"signer-{auth}",
    }


def initial_slot(
    mid: str | None,
    generation: int,
    pages: dict[str, str],
    *,
    ready: bool = False,
    active: bool = False,
    candidate: bool = False,
    sig: dict[str, Any] | None = None,
    session: dict[str, Any] | None = None,
    readback: list[str] | None = None,
    health: dict[str, Any] | None = None,
    trial: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "generation": generation,
        "manifest_id": mid,
        "written_pages": dict(sorted(pages.items())),
        "ready": ready,
        "sig_entry": sig,
        "candidate": candidate,
        "active": active,
        "trial": trial,
        "health": health,
        "session": session,
        "readback_verified": sorted(readback or []),
        "erase_count": 0,
    }


def sig_for(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "manifest_id": m["manifest_id"],
        "version": m["version"],
        "generation": m["authorized_generation"],
        "auth_id": m["auth_id"],
        "signer": m["signer"],
        "digest_witness": page_summary(m["pages"]),
    }


def write_case(name: str, doc: dict[str, Any]) -> str:
    os.makedirs(CASES_DIR, exist_ok=True)
    path = os.path.join(CASES_DIR, name)
    text = json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


# ---------------------------------------------------------------------------
# Case builders
# ---------------------------------------------------------------------------

GROUP = "grp-fleet-7"


def build_happy_16x64() -> dict[str, Any]:
    """The headline 16-action / 64-page fully successful update."""
    page_ids = [f"p{i:02d}" for i in range(64)]
    # 6 sectors (11+11+11+11+10+10 pages): 1 update + 6 batched program
    # events + 9 switch/trial protocol events = exactly 16 declared actions
    # over 64 pages.
    sector_sizes = [11, 11, 11, 11, 10, 10]
    assert sum(sector_sizes) == 64
    sectors = []
    cursor = 0
    for idx, size in enumerate(sector_sizes):
        sectors.append(
            {
                "sector_id": f"S{idx}",
                "pages": page_ids[cursor : cursor + size],
                "capacity": size,
            }
        )
        cursor += size
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", version=1, group=GROUP, generation=1, pages=old_pages, auth="AUTH-1")
    m2 = manifest("M2", version=2, group=GROUP, generation=2, pages=new_pages, auth="AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
    ]
    for sec in sectors:
        events.append(
            {"type": "program", "manifest_id": "M2", "slot": "B", "pages": list(sec["pages"])}
        )
    events += [
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "rcpt-M2-1"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_candidate", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_publish_active", "manifest_id": "M2", "slot": "B"},
    ]
    assert len(events) == 16, len(events)
    return _doc(
        "happy-16x64",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot(
                "M1", 1, old_pages, ready=True, active=True, sig=sig_for(m1),
                readback=list(old_pages),
            ),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
    )


def build_counter_no_active() -> dict[str, Any]:
    """Counter raised but active marker never written (crash between the two)."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids},
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "rcpt-M2-1"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_candidate", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
        # Deliberate stop: B is candidate+trusted at generation 2, counter=2,
        # but no slot carries the active marker.
    ]
    return _doc(
        "counter-no-active",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot("M1", 1, old_pages, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
    )


def build_half_each() -> dict[str, Any]:
    """Both partitions hold only half an image: neither may be a rollback target."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    half_b = {p: new_pages[p] for p in page_ids[:2]}
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[:2]},
        {"type": "power_loss"},
    ]
    return _doc(
        "half-each",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            # A was erased mid-update too and only got its first two pages back.
            "A": initial_slot("M1", 1, {p: old_pages[p] for p in page_ids[:2]}),
            "B": initial_slot(
                "M2", 2, half_b,
                session={
                    "manifest_id": "M2", "target_slot": "B", "version": 2,
                    "authorized_generation": 2, "generation_at_open": 0,
                    "remaining_pages": page_ids[2:], "written_in_session": page_ids[:2],
                },
            ),
        },
        events=events,
    )


def build_retry_mixed_pages() -> dict[str, Any]:
    """Retried update must refuse to mix old-generation pages into the slot."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    # B already switched to generation 2 content on p0; a retry tries to push
    # generation-1 pages (digests differ -> rejected, committed version unchanged).
    events = [
        {"type": "update", "manifest_id": "M1", "slot": "B"},
        {"type": "program", "manifest_id": "M1", "slot": "B", "pages": page_ids},
    ]
    return _doc(
        "retry-mixed-pages",
        sectors,
        [m1, m2],
        counter=2,
        slots={
            "A": initial_slot(None, 0, {}),
            "B": initial_slot(
                "M2", 2, {p: new_pages[p] for p in page_ids[:1]},
                session={
                    "manifest_id": "M2", "target_slot": "B", "version": 2,
                    "authorized_generation": 2, "generation_at_open": 2,
                    "remaining_pages": page_ids[1:], "written_in_session": page_ids[:1],
                },
            ),
        },
        events=events,
    )


def build_late_health() -> dict[str, Any]:
    """Health receipt arriving after the trial closed must be rejected."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, manifest_pages(page_ids, "gen1"), "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids},
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "rcpt-late"},
    ]
    return _doc(
        "late-health",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot("M1", 1, m1["pages"], ready=True, active=True, sig=sig_for(m1), readback=page_ids),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
    )


def build_revoke_race() -> dict[str, Any]:
    """Revocation lands between READY and the switch: confirm/counter must stop."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids},
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "rcpt-M2-1"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_candidate", "manifest_id": "M2", "slot": "B"},
        {"type": "revoke", "manifest_id": "M2"},
        {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
    ]
    return _doc(
        "revoke-race",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot("M1", 1, old_pages, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
    )


def build_revoked_old_halt() -> dict[str, Any]:
    """Old image revoked while incomplete: the only security result is safe halt."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[:2]},
        {"type": "revoke", "manifest_id": "M1"},
        {"type": "power_loss"},
    ]
    return _doc(
        "revoked-old-halt",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot("M1", 1, old_pages, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
        policy={"fallback": "maintain"},
    )


def build_batch_resume() -> dict[str, Any]:
    """Batched writes interrupted repeatedly; resume finishes the same version."""
    page_ids = ["p0", "p1", "p2", "p3", "p4", "p5"]
    sectors = sectors_def(page_ids, 3)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    events = [
        {"type": "update", "manifest_id": "M2", "slot": "B"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[:2]},
        {"type": "power_loss"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[2:4]},
        {"type": "power_loss"},
        {"type": "program", "manifest_id": "M2", "slot": "B", "pages": page_ids[4:]},
        {"type": "verify", "manifest_id": "M2", "slot": "B"},
        {"type": "mark_ready", "manifest_id": "M2", "slot": "B"},
        {"type": "trial_start", "manifest_id": "M2", "slot": "B"},
        {"type": "health", "manifest_id": "M2", "slot": "B", "receipt_id": "rcpt-M2-1"},
        {"type": "trial_end", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_candidate", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_confirm_health", "manifest_id": "M2", "slot": "B"},
        {"type": "counter_raise", "manifest_id": "M2", "slot": "B"},
        {"type": "switch_publish_active", "manifest_id": "M2", "slot": "B"},
    ]
    return _doc(
        "batch-resume",
        sectors,
        [m1, m2],
        counter=1,
        slots={
            "A": initial_slot("M1", 1, old_pages, ready=True, active=True, sig=sig_for(m1), readback=page_ids),
            "B": initial_slot(None, 0, {}),
        },
        events=events,
    )


def _doc(
    case_id: str,
    sectors: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
    *,
    counter: int,
    slots: dict[str, dict[str, Any]],
    events: list[dict[str, Any]],
    policy: dict[str, str] | None = None,
    max_power_losses: int = 2,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "case_id": case_id,
        "device_group": GROUP,
        "policy": policy or {"fallback": "maintain"},
        "max_power_losses": max_power_losses,
        "sectors": sectors,
        "manifests": manifests,
        "initial": {
            "counter": counter,
            "sector_budgets": {s["sector_id"]: s["capacity"] for s in sectors},
            "revoked_manifests": [],
            "slots": slots,
        },
        "events": events,
    }


def build_stranded_floor() -> dict[str, Any]:
    """Maintain-policy failure: trusted old image stranded below the floor."""
    page_ids = ["p0", "p1", "p2", "p3"]
    sectors = sectors_def(page_ids, 2)
    old_pages = manifest_pages(page_ids, "gen1")
    new_pages = manifest_pages(page_ids, "gen2")
    m1 = manifest("M1", 1, GROUP, 1, old_pages, "AUTH-1")
    m2 = manifest("M2", 2, GROUP, 2, new_pages, "AUTH-2")
    doc = _doc(
        "stranded-floor",
        sectors,
        [m1, m2],
        counter=2,
        slots={
            "A": initial_slot(
                "M1", 1, old_pages, ready=True, active=False, sig=sig_for(m1),
                readback=page_ids,
            ),
            "B": initial_slot(
                "M2", 2, {p: new_pages[p] for p in page_ids[:2]},
            ),
        },
        events=[],
    )
    return doc


def build_halt_allowed() -> dict[str, Any]:
    """Same stranded state, but halt_allowed policy makes the stop acceptable."""
    doc = build_stranded_floor()
    doc = json.loads(json.dumps(doc))
    doc["case_id"] = "halt-allowed"
    doc["policy"] = {"fallback": "halt_allowed"}
    return doc


BUILDERS = [
    build_happy_16x64,
    build_counter_no_active,
    build_half_each,
    build_retry_mixed_pages,
    build_late_health,
    build_revoke_race,
    build_revoked_old_halt,
    build_batch_resume,
    build_stranded_floor,
    build_halt_allowed,
]


def build_all() -> list[str]:
    paths = []
    for builder in BUILDERS:
        doc = builder()
        paths.append(write_case(f"{doc['case_id']}.json", doc))
    return paths


if __name__ == "__main__":  # pragma: no cover
    for p in build_all():
        print(p)
