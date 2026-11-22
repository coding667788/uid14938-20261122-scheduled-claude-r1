"""Command line entry point.

Usage::

    python -m boot_replay replay CASE.json
    python -m boot_replay check  CASE.json
    python -m boot_replay repair CASE.json

Output is reproducible UTF-8 JSON (sorted keys, fixed separators).  Case
errors are emitted as JSON documents on stdout with a non-zero exit code and
a ``path`` pointing at the offending field or event.
"""

from __future__ import annotations

import io
import json
import sys
from typing import Any

from .check import check
from .errors import BootReplayError, CaseError
from .loader import load_case
from .repair import repair
from .replay import replay

COMMANDS = ("replay", "check", "repair")


def dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2 or argv[0] not in COMMANDS:
        sys.stdout.write(
            dumps(
                {
                    "error": "usage",
                    "detail": f"usage: python -m boot_replay {{{'|'.join(COMMANDS)}}} CASE.json",
                }
            )
            + "\n"
        )
        return 2
    command, path = argv
    try:
        with io.open(path, "r", encoding="utf-8") as fh:
            try:
                doc = json.load(fh)
            except json.JSONDecodeError as exc:
                raise CaseError(
                    f"$:{exc.lineno}:{exc.colno}",
                    f"invalid JSON: {exc.msg}",
                ) from exc
        case = load_case(doc)
        if command == "replay":
            payload = replay(case)
        elif command == "check":
            payload = check(case)
        else:
            payload = repair(case)
    except CaseError as exc:
        payload = exc.to_payload()
        sys.stdout.write(dumps(payload) + "\n")
        return 1
    except BootReplayError as exc:
        payload = {"error": "runtime_error", "detail": str(exc)}
        sys.stdout.write(dumps(payload) + "\n")
        return 1
    except FileNotFoundError:
        payload = {"error": "file_not_found", "path": path}
        sys.stdout.write(dumps(payload) + "\n")
        return 1
    sys.stdout.write(dumps(payload) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
