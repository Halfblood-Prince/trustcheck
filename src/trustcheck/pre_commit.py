from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .cli import EXIT_OK, _merge_exit_codes
from .cli import main as trustcheck_main
from .lockfiles import is_supported_lockfile

DEPENDENCY_FILENAMES = {
    "requirements.txt",
    "requirements.in",
    "pyproject.toml",
}


def _is_dependency_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        is_supported_lockfile(path)
        or name in DEPENDENCY_FILENAMES
        or (name.startswith("requirements-") and path.suffix.lower() in {".txt", ".in"})
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run fast, hash-aware Trustcheck scans for changed dependency files."
    )
    parser.add_argument("filenames", nargs="*")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--cache-dir")
    args = parser.parse_args(argv)

    files = sorted(
        {
            path.resolve()
            for raw in args.filenames
            if (path := Path(raw)).is_file() and _is_dependency_file(path)
        },
        key=lambda path: path.as_posix(),
    )
    result = EXIT_OK
    for path in files:
        command = [
            "scan",
            "--file",
            str(path),
            "--fast",
            "--no-deps",
            "--with-osv",
        ]
        if args.offline:
            command.append("--offline")
        if args.strict:
            command.append("--strict")
        if args.cache_dir:
            command.extend(["--cache-dir", args.cache_dir])
        result = _merge_exit_codes(result, trustcheck_main(command))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
