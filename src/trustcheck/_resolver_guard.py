from __future__ import annotations

import sys
from pathlib import Path

BLOCKED_PROCESS_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.startfile",
    }
)


class StrictResolverViolation(RuntimeError):
    pass


def install_guard() -> None:
    sys.addaudithook(_deny_child_process)


def _deny_child_process(event: str, arguments: tuple[object, ...]) -> None:
    del arguments
    if event in BLOCKED_PROCESS_EVENTS:
        raise StrictResolverViolation(
            "strict resolver blocked child-process creation; a source build, "
            "build-backend metadata hook, VCS command, or external credential "
            "helper may have been requested"
        )


def sitecustomize_source() -> str:
    events = tuple(sorted(BLOCKED_PROCESS_EVENTS))
    return f'''\
"""Trustcheck strict resolver guard, generated at runtime."""
from __future__ import annotations

import sys

BLOCKED_PROCESS_EVENTS = frozenset({events!r})


class StrictResolverViolation(RuntimeError):
    pass


def _deny_child_process(event, arguments):
    del arguments
    if event in BLOCKED_PROCESS_EVENTS:
        raise StrictResolverViolation(
            "strict resolver blocked child-process creation; a source build, "
            "build-backend metadata hook, VCS command, or external credential "
            "helper may have been requested"
        )


sys.addaudithook(_deny_child_process)
'''


def write_sitecustomize(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    sitecustomize = directory / "sitecustomize.py"
    sitecustomize.write_text(sitecustomize_source(), encoding="utf-8")
    return sitecustomize


def main() -> int:
    install_guard()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
