"""Shared helpers for the unittest suite."""

from __future__ import annotations

import json
import os

from boot_replay.cases.build_cases import (
    GROUP,
    build_all,
    digest,
    initial_slot,
    manifest,
    manifest_pages,
    sectors_def,
    sig_for,
)
from boot_replay.loader import load_case

GENERATED_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "cases", "generated"
)


def load_generated(name: str):
    path = os.path.join(GENERATED_DIR, f"{name}.json")
    with open(path, "r", encoding="utf-8") as fh:
        return load_case(json.load(fh))


def small_pages(n: int) -> list[str]:
    return [f"p{i}" for i in range(n)]


__all__ = [
    "GROUP",
    "build_all",
    "digest",
    "initial_slot",
    "load_generated",
    "manifest",
    "manifest_pages",
    "sectors_def",
    "sig_for",
    "small_pages",
]
