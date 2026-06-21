from __future__ import annotations

import subprocess
import sys
import time

import psutil

MARKER = "__trustcheck_max_rss_kib__="


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: measure_command.py COMMAND [ARG ...]")
    process = subprocess.Popen(sys.argv[1:])  # nosec B603
    observed = psutil.Process(process.pid)
    peak = 0
    while process.poll() is None:
        try:
            processes = [observed, *observed.children(recursive=True)]
            peak = max(peak, sum(item.memory_info().rss for item in processes))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        time.sleep(0.01)
    print(f"{MARKER}{peak // 1024}", file=sys.stderr)
    return int(process.returncode or 0)


if __name__ == "__main__":
    raise SystemExit(main())
