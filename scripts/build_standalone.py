from __future__ import annotations

from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).parents[1]
DIST_DIR = ROOT / "dist" / "standalone"
WORK_DIR = ROOT / "build" / "pyinstaller"
SPEC_DIR = WORK_DIR / "spec"


def main() -> int:
    SPEC_DIR.mkdir(parents=True, exist_ok=True)
    arguments = [
        "--clean",
        "--noconfirm",
        "--onefile",
        "--noupx",
        "--name=trustcheck",
        f"--distpath={DIST_DIR}",
        f"--workpath={WORK_DIR}",
        f"--specpath={SPEC_DIR}",
        "--recursive-copy-metadata=trustcheck",
    ]
    for package in (
        "rekor_types",
        "sigstore",
        "sigstore_models",
        "tuf",
    ):
        arguments.append(f"--collect-all={package}")
    arguments.append(str(ROOT / "scripts" / "trustcheck_binary.py"))

    PyInstaller.__main__.run(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
