from __future__ import annotations

import argparse
import glob
import os
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _venv_executable(venv: Path, name: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


def _run(command: list[Path | str]) -> None:
    rendered = " ".join(str(part) for part in command)
    print(f"+ {rendered}", flush=True)
    subprocess.run([str(part) for part in command], cwd=ROOT, check=True)  # nosec B603


def _expand_artifacts(patterns: list[str]) -> list[Path]:
    artifacts: list[Path] = []
    for pattern in patterns:
        pattern_path = Path(pattern)
        search_pattern = pattern_path if pattern_path.is_absolute() else ROOT / pattern
        matches = [Path(match) for match in sorted(glob.glob(str(search_pattern)))]
        if not matches and search_pattern.exists():
            matches = [search_pattern]
        if not matches:
            raise ValueError(f"no distribution artifact matched {pattern!r}")
        artifacts.extend(matches)
    return [artifact.resolve() for artifact in artifacts]


def smoke_test_artifact(artifact: Path, *, runtime_lock: Path, fixture: Path) -> None:
    print(f"Smoke testing {artifact.name} in a clean virtual environment", flush=True)
    with tempfile.TemporaryDirectory(prefix="trustcheck-dist-smoke-") as tempdir:
        venv = Path(tempdir) / "venv"
        _run([sys.executable, "-m", "venv", venv])
        python = _venv_python(venv)
        trustcheck = _venv_executable(venv, "trustcheck")
        _run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "--requirement",
                runtime_lock,
            ]
        )
        _run(
            [
                python,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                artifact,
            ]
        )
        _run([trustcheck, "--version"])
        _run([trustcheck, "scan", "-f", fixture, "--no-deps", "--format", "json"])
        _run([python, "-m", "pip", "check"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Smoke test built Trustcheck distributions in clean environments."
    )
    parser.add_argument("artifacts", nargs="+", help="Distribution artifact path or glob.")
    parser.add_argument(
        "--runtime-lock",
        type=Path,
        default=ROOT / "requirements" / "runtime.lock",
        help="Hash-pinned runtime requirements file.",
    )
    parser.add_argument(
        "--fixture",
        type=Path,
        default=ROOT / "tests" / "fixtures" / "requirements-vulnerable.txt",
        help="Local dependency fixture to scan with the installed trustcheck command.",
    )
    args = parser.parse_args(argv)

    try:
        artifacts = _expand_artifacts(args.artifacts)
        runtime_lock = args.runtime_lock.resolve()
        fixture = args.fixture.resolve()
        for path in (runtime_lock, fixture):
            if not path.exists():
                raise ValueError(f"required file does not exist: {path}")
        for artifact in artifacts:
            smoke_test_artifact(artifact, runtime_lock=runtime_lock, fixture=fixture)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
