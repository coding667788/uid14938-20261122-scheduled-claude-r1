"""Load and validate CASE.json documents.

Validation is strict: unknown event types, wrong types, duplicate ids,
inconsistent slot state and budget mistakes all raise :class:`CaseError`
whose ``path`` points at the exact JSON field or ``events[i]`` entry.
"""

from __future__ import annotations

from typing import Any

from .errors import require, require_type
from .model import (
    SLOT_IDS,
    CaseConfig,
    DeviceState,
    Manifest,
    Policy,
    Sector,
    SlotState,
)

SCHEMA_VERSION = 1
EVENT_TYPES = {
    "update",
    "program",
    "verify",
    "mark_ready",
    "trial_start",
    "health",
    "trial_end",
    "switch_candidate",
    "switch_confirm_health",
    "counter_raise",
    "switch_publish_active",
    "revoke",
    "erase",
    "power_loss",
}


def load_case(doc: dict[str, Any]) -> CaseConfig:
    require_type(doc, dict, "$")
    require("schema_version" in doc, "$", "missing field schema_version")
    require_type(doc["schema_version"], int, "$.schema_version")
    require(
        doc["schema_version"] == SCHEMA_VERSION,
        "$.schema_version",
        f"unsupported schema_version {doc['schema_version']}, expected {SCHEMA_VERSION}",
    )
    for name in ("case_id", "device_group", "sectors", "manifests", "initial", "events"):
        require(name in doc, f"$.{name}", f"missing field {name}")

    require_type(doc["case_id"], str, "$.case_id")
    require_type(doc["device_group"], str, "$.device_group")
    require(bool(doc["case_id"].strip()), "$.case_id", "case_id must be non-empty")

    policy = _load_policy(doc.get("policy", {}))
    max_pl = doc.get("max_power_losses", 2)
    require_type(max_pl, int, "$.max_power_losses")
    require(max_pl >= 0, "$.max_power_losses", "must be >= 0")
    require(max_pl <= 2, "$.max_power_losses", "check semantics are bounded to <= 2")

    sectors, page_sector = _load_sectors(doc["sectors"])
    manifests, manifest_by_id = _load_manifests(doc["manifests"], doc["device_group"], page_sector)
    initial = _load_initial(doc["initial"], sectors, manifests, manifest_by_id, page_sector)
    events = _load_events(doc["events"], manifest_by_id, page_sector, set(initial.slots.keys()))

    return CaseConfig(
        schema_version=SCHEMA_VERSION,
        case_id=doc["case_id"],
        device_group=doc["device_group"],
        policy=policy,
        max_power_losses=max_pl,
        sectors=sectors,
        manifests=manifests,
        initial_state=initial,
        events=events,
        manifest_by_id=manifest_by_id,
        page_sector=page_sector,
        repair_depth=int(doc.get("repair_depth", 12)),
    )


def _load_policy(raw: Any) -> Policy:
    require_type(raw, dict, "$.policy")
    fallback = raw.get("fallback", "maintain")
    require_type(fallback, str, "$.policy.fallback")
    require(
        fallback in ("maintain", "halt_allowed"),
        "$.policy.fallback",
        "must be 'maintain' or 'halt_allowed'",
    )
    return Policy(fallback=fallback)


def _load_sectors(raw: Any) -> tuple[list[Sector], dict[str, str]]:
    require_type(raw, list, "$.sectors")
    require(len(raw) > 0, "$.sectors", "at least one sector is required")
    sectors: list[Sector] = []
    page_sector: dict[str, str] = {}
    seen_sector: set[str] = set()
    seen_page: set[str] = set()
    for i, sec in enumerate(raw):
        path = f"$.sectors[{i}]"
        require_type(sec, dict, path)
        for name in ("sector_id", "pages", "capacity"):
            require(name in sec, f"{path}.{name}", f"missing field {name}")
        sid = sec["sector_id"]
        require_type(sid, str, f"{path}.sector_id")
        require(sid not in seen_sector, f"{path}.sector_id", f"duplicate sector_id {sid}")
        seen_sector.add(sid)
        require_type(sec["pages"], list, f"{path}.pages")
        require(len(sec["pages"]) > 0, f"{path}.pages", "sector must contain pages")
        pages: list[str] = []
        for j, page_id in enumerate(sec["pages"]):
            pp = f"{path}.pages[{j}]"
            require_type(page_id, str, pp)
            require(page_id not in seen_page, pp, f"duplicate page {page_id} across sectors")
            seen_page.add(page_id)
            pages.append(page_id)
            page_sector[page_id] = sid
        cap = sec["capacity"]
        require_type(cap, int, f"{path}.capacity")
        require(cap >= len(pages), f"{path}.capacity", "capacity must cover all listed pages")
        sectors.append(Sector(sector_id=sid, pages=pages, capacity=cap))
    return sectors, page_sector


def _load_manifests(
    raw: Any, device_group: str, page_sector: dict[str, str]
) -> tuple[list[Manifest], dict[str, Manifest]]:
    require_type(raw, list, "$.manifests")
    require(len(raw) > 0, "$.manifests", "at least one manifest is required")
    manifests: list[Manifest] = []
    by_id: dict[str, Manifest] = {}
    for i, m in enumerate(raw):
        path = f"$.manifests[{i}]"
        require_type(m, dict, path)
        for name in (
            "manifest_id",
            "version",
            "device_group",
            "authorized_generation",
            "pages",
            "auth_id",
            "signer",
        ):
            require(name in m, f"{path}.{name}", f"missing field {name}")
        mid = m["manifest_id"]
        require_type(mid, str, f"{path}.manifest_id")
        require(mid not in by_id, f"{path}.manifest_id", f"duplicate manifest_id {mid}")
        require_type(m["version"], int, f"{path}.version")
        require(m["version"] > 0, f"{path}.version", "version must be positive")
        require_type(m["device_group"], str, f"{path}.device_group")
        require(
            m["device_group"] == device_group,
            f"{path}.device_group",
            f"manifest targets group {m['device_group']!r}, case group is {device_group!r}",
        )
        require_type(m["authorized_generation"], int, f"{path}.authorized_generation")
        require(
            m["authorized_generation"] > 0,
            f"{path}.authorized_generation",
            "generation must be positive",
        )
        require_type(m["auth_id"], str, f"{path}.auth_id")
        require(bool(m["auth_id"].strip()), f"{path}.auth_id", "auth_id must be non-empty")
        require_type(m["signer"], str, f"{path}.signer")
        require_type(m["pages"], dict, f"{path}.pages")
        require(len(m["pages"]) > 0, f"{path}.pages", "manifest must list pages")
        pages: dict[str, str] = {}
        for page_id, digest in m["pages"].items():
            require_type(page_id, str, f"{path}.pages key")
            require_type(digest, str, f"{path}.pages.{page_id}")
            require(
                page_id in page_sector,
                f"{path}.pages.{page_id}",
                "page is not declared in any sector",
            )
            require(bool(digest), f"{path}.pages.{page_id}", "digest must be non-empty")
            pages[page_id] = digest
        manifest = Manifest(
            manifest_id=mid,
            version=m["version"],
            device_group=m["device_group"],
            authorized_generation=m["authorized_generation"],
            pages=pages,
            auth_id=m["auth_id"],
            signer=m["signer"],
        )
        manifests.append(manifest)
        by_id[mid] = manifest
    return manifests, by_id


def _load_initial(
    raw: Any,
    sectors: list[Sector],
    manifests: list[Manifest],
    by_id: dict[str, Manifest],
    page_sector: dict[str, str],
) -> DeviceState:
    require_type(raw, dict, "$.initial")
    for name in ("counter", "sector_budgets", "slots"):
        require(name in raw, f"$.initial.{name}", f"missing field {name}")
    counter = raw["counter"]
    require_type(counter, int, "$.initial.counter")
    require(counter >= 0, "$.initial.counter", "counter cannot be negative")

    require_type(raw["sector_budgets"], dict, "$.initial.sector_budgets")
    sector_ids = {s.sector_id for s in sectors}
    budgets: dict[str, int] = {}
    for sid, budget in raw["sector_budgets"].items():
        require(sid in sector_ids, f"$.initial.sector_budgets.{sid}", "unknown sector")
        require_type(budget, int, f"$.initial.sector_budgets.{sid}")
        require(budget >= 0, f"$.initial.sector_budgets.{sid}", "budget cannot be negative")
        budgets[sid] = budget
    for s in sectors:
        require(
            s.sector_id in budgets,
            f"$.initial.sector_budgets.{s.sector_id}",
            "missing initial budget for sector",
        )

    require_type(raw["slots"], dict, "$.initial.slots")
    slots: dict[str, SlotState] = {}
    for slot_id in SLOT_IDS:
        require(slot_id in raw["slots"], f"$.initial.slots.{slot_id}", "missing slot state")
        slots[slot_id] = _load_slot(raw["slots"][slot_id], slot_id, by_id, page_sector)

    revoked_raw = raw.get("revoked_manifests", [])
    require_type(revoked_raw, list, "$.initial.revoked_manifests")
    revoked: set[str] = set()
    for i, mid in enumerate(revoked_raw):
        p = f"$.initial.revoked_manifests[{i}]"
        require_type(mid, str, p)
        require(mid in by_id, p, "unknown manifest_id")
        require(mid not in revoked, p, "duplicate revocation")
        revoked.add(mid)

    # Cross-slot consistency.
    active = [s for s in slots.values() if s.active]
    require(len(active) <= 1, "$.initial.slots", "at most one active marker is allowed")
    state = DeviceState(
        slots=slots,
        counter=counter,
        revoked_manifests=revoked,
        sector_budgets=budgets,
    )
    for slot in slots.values():
        if slot.formally_bootable(_case_view(by_id), counter, revoked):
            pass
    return state


def _case_view(by_id: dict[str, Manifest]) -> CaseConfig:
    # Predicates only consult manifest_by_id; a lightweight view is enough.
    return CaseConfig(
        schema_version=SCHEMA_VERSION,
        case_id="_validation",
        device_group="",
        policy=Policy(),
        max_power_losses=2,
        sectors=[],
        manifests=list(by_id.values()),
        initial_state=None,  # type: ignore[arg-type]
        events=[],
        manifest_by_id=by_id,
    )


def _load_slot(
    raw: Any, slot_id: str, by_id: dict[str, Manifest], page_sector: dict[str, str]
) -> SlotState:
    path = f"$.initial.slots.{slot_id}"
    require_type(raw, dict, path)
    gen = raw.get("generation", 0)
    require_type(gen, int, f"{path}.generation")
    require(gen >= 0, f"{path}.generation", "generation cannot be negative")
    mid = raw.get("manifest_id")
    if mid is not None:
        require_type(mid, str, f"{path}.manifest_id")
        require(mid in by_id, f"{path}.manifest_id", "unknown manifest_id")
        m = by_id[mid]
        require(
            gen == m.authorized_generation or gen == 0,
            f"{path}.generation",
            "slot generation must match its manifest's authorized_generation",
        )
    written_raw = raw.get("written_pages", {})
    require_type(written_raw, dict, f"{path}.written_pages")
    written: dict[str, str] = {}
    for page_id, digest in written_raw.items():
        require_type(page_id, str, f"{path}.written_pages key")
        require(page_id in page_sector, f"{path}.written_pages.{page_id}", "unknown page")
        require_type(digest, str, f"{path}.written_pages.{page_id}")
        written[page_id] = digest
    if mid is not None:
        m = by_id[mid]
        for page_id, digest in written.items():
            require(
                page_id in m.pages,
                f"{path}.written_pages.{page_id}",
                "page does not belong to the slot's manifest",
            )
            require(
                digest == m.pages[page_id],
                f"{path}.written_pages.{page_id}",
                "digest disagrees with manifest",
            )
    bool_fields = ("ready", "candidate", "active")
    for bf in bool_fields:
        if bf in raw:
            require_type(raw[bf], bool, f"{path}.{bf}")
    sig = raw.get("sig_entry")
    if sig is not None:
        require_type(sig, dict, f"{path}.sig_entry")
        for name in ("manifest_id", "generation", "auth_id"):
            require(name in sig, f"{path}.sig_entry.{name}", f"missing field {name}")
            require_type(sig[name], str if name != "generation" else int, f"{path}.sig_entry.{name}")
        require(sig["manifest_id"] in by_id, f"{path}.sig_entry.manifest_id", "unknown manifest_id")
    trial = raw.get("trial")
    if trial is not None:
        require_type(trial, dict, f"{path}.trial")
        for name in ("generation", "manifest_id"):
            require(name in trial, f"{path}.trial.{name}", f"missing field {name}")
    health = raw.get("health")
    if health is not None:
        require_type(health, dict, f"{path}.health")
        for name in ("generation", "manifest_id", "receipt_id"):
            require(name in health, f"{path}.health.{name}", f"missing field {name}")
    session = raw.get("session")
    if session is not None:
        require_type(session, dict, f"{path}.session")
        for name in ("manifest_id", "target_slot", "remaining_pages"):
            require(name in session, f"{path}.session.{name}", f"missing field {name}")
        require_type(session["remaining_pages"], list, f"{path}.session.remaining_pages")
    rv = raw.get("readback_verified", [])
    require_type(rv, list, f"{path}.readback_verified")
    for page_id in rv:
        require_type(page_id, str, f"{path}.readback_verified")
        require(page_id in written, f"{path}.readback_verified", "verified page was never written")
    erase_count = raw.get("erase_count", 0)
    require_type(erase_count, int, f"{path}.erase_count")
    require(erase_count >= 0, f"{path}.erase_count", "cannot be negative")
    slot = SlotState(
        slot_id=slot_id,
        generation=gen,
        manifest_id=mid,
        written_pages=written,
        ready=bool(raw.get("ready", False)),
        sig_entry=sig,
        candidate=bool(raw.get("candidate", False)),
        active=bool(raw.get("active", False)),
        trial=trial,
        health=health,
        session=session,
        readback_verified=list(rv),
        erase_count=erase_count,
    )
    if slot.ready:
        require(slot.is_complete(_case_view(by_id)), f"{path}.ready", "READY slot is incomplete")
    return slot


def _load_events(
    raw: Any,
    by_id: dict[str, Manifest],
    page_sector: dict[str, str],
    slot_ids: set[str],
) -> list[dict[str, Any]]:
    require_type(raw, list, "$.events")
    seen_receipts: set[str] = set()
    for i, ev in enumerate(raw):
        path = f"$.events[{i}]"
        require_type(ev, dict, path)
        require("type" in ev, f"{path}.type", "missing event type")
        etype = ev["type"]
        require_type(etype, str, f"{path}.type")
        require(etype in EVENT_TYPES, f"{path}.type", f"unknown event type {etype!r}")
        if etype in ("update", "program", "verify", "mark_ready", "trial_start",
                     "health", "trial_end", "switch_candidate",
                     "switch_confirm_health", "counter_raise",
                     "switch_publish_active"):
            require("manifest_id" in ev, f"{path}.manifest_id", f"{etype} requires manifest_id")
            require_type(ev["manifest_id"], str, f"{path}.manifest_id")
            require(ev["manifest_id"] in by_id, f"{path}.manifest_id", "unknown manifest_id")
        if "slot" in ev:
            require_type(ev["slot"], str, f"{path}.slot")
            require(ev["slot"] in slot_ids, f"{path}.slot", "slot must be 'A' or 'B'")
        if etype == "program":
            require("pages" in ev, f"{path}.pages", "program requires pages")
            require_type(ev["pages"], list, f"{path}.pages")
            for j, page_id in enumerate(ev["pages"]):
                require_type(page_id, str, f"{path}.pages[{j}]")
                require(page_id in page_sector, f"{path}.pages[{j}]", "unknown page")
        if etype == "health":
            require("receipt_id" in ev, f"{path}.receipt_id", "health requires receipt_id")
            require_type(ev["receipt_id"], str, f"{path}.receipt_id")
            require(
                ev["receipt_id"] not in seen_receipts,
                f"{path}.receipt_id",
                "duplicate health receipt id",
            )
            seen_receipts.add(ev["receipt_id"])
        if etype == "erase":
            require("sector_id" in ev, f"{path}.sector_id", "erase requires sector_id")
            require_type(ev["sector_id"], str, f"{path}.sector_id")
            require("slot" in ev, f"{path}.slot", "erase requires target slot")
        if etype == "revoke":
            require("manifest_id" in ev, f"{path}.manifest_id", "revoke requires manifest_id")
    return list(raw)
