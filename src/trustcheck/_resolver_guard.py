from __future__ import annotations

# Strict mode installs a process-creation audit guard before invoking pip.
import sys
from collections.abc import Sequence

from pip._internal.cli.main import main as pip_main

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


def _deny_child_process(event: str, arguments: tuple[object, ...]) -> None:
    del arguments
    if event in BLOCKED_PROCESS_EVENTS:
        raise StrictResolverViolation(
            "strict resolver blocked child-process creation; a source build, "
            "build-backend metadata hook, VCS command, or external credential "
            "helper may have been requested"
        )


def main(arguments: Sequence[str] | None = None) -> int:
    pip_arguments = list(arguments if arguments is not None else sys.argv[1:])
    sys.addaudithook(_deny_child_process)
    return pip_main(pip_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
