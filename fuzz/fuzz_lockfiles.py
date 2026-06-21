from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from trustcheck.lockfiles import load_lockfile

LOCKFILE_NAMES = ("uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml")


def test_one_input(data: bytes) -> None:
    if not data:
        return
    name = LOCKFILE_NAMES[data[0] % len(LOCKFILE_NAMES)]
    directory = tempfile.mkdtemp(prefix="trustcheck-fuzz-lock-")
    path = Path(directory, name)
    try:
        path.write_bytes(data[1:])
        try:
            load_lockfile(path)
        except (OSError, UnicodeError, ValueError):
            pass
    finally:
        try:
            path.unlink(missing_ok=True)
            os.rmdir(directory)
        except OSError:
            pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
