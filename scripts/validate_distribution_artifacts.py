from __future__ import annotations

import argparse
import glob
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN_PARTS = {
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tmp-build",
    "build",
    "dist",
    "htmlcov",
    "site",
}
FORBIDDEN_TOP_LEVEL = {
    ".claude-plugin",
    ".codex-plugin",
    ".cursor-plugin",
    "plugins",
}
FORBIDDEN_FILENAMES = {
    ".coverage",
    ".DS_Store",
    "Thumbs.db",
    "coverage.json",
    "coverage.xml",
}
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".dll",
    ".dylib",
    ".exe",
    ".msix",
    ".pyd",
    ".snap",
    ".so",
    ".whl",
    ".zip",
}
SECRET_MARKERS = (
    b"-----BEGIN " b"PRIVATE KEY-----",
    b"-----BEGIN OPENSSH " b"PRIVATE KEY-----",
    b"AWS_SECRET_" b"ACCESS_KEY=",
    b"TWINE_" b"PASSWORD=",
    b"PYPI_" b"TOKEN=",
    b"pypi-" b"AgEI",
)


class ArtifactValidationError(ValueError):
    pass


def _expand_artifacts(patterns: list[str]) -> list[Path]:
    artifacts: list[Path] = []
    for pattern in patterns:
        pattern_path = Path(pattern)
        search_pattern = pattern_path if pattern_path.is_absolute() else Path.cwd() / pattern
        matches = [Path(match) for match in sorted(glob.glob(str(search_pattern)))]
        if not matches and search_pattern.exists():
            matches = [search_pattern]
        if not matches:
            raise ArtifactValidationError(f"no artifact matched {pattern!r}")
        artifacts.extend(path.resolve() for path in matches)
    return artifacts


def _safe_relative_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ArtifactValidationError(f"unsafe archive path: {name}")
    return path


def _sdist_relative_path(path: PurePosixPath) -> PurePosixPath:
    if len(path.parts) < 2:
        raise ArtifactValidationError(
            f"sdist entry is not rooted under a package directory: {path}"
        )
    return PurePosixPath(*path.parts[1:])


def _validate_common_path(relative: PurePosixPath, *, artifact: Path) -> None:
    parts = set(relative.parts)
    if forbidden := sorted(FORBIDDEN_PARTS & parts):
        raise ArtifactValidationError(
            f"{artifact.name} contains generated/cache path {relative} ({', '.join(forbidden)})"
        )
    if relative.parts and relative.parts[0] in FORBIDDEN_TOP_LEVEL:
        raise ArtifactValidationError(
            f"{artifact.name} contains accidental plugin bundle path: {relative}"
        )
    if len(relative.parts) >= 2 and relative.parts[0] == "tests" and relative.parts[1] == "_tmp":
        raise ArtifactValidationError(f"{artifact.name} contains temporary test output: {relative}")
    if relative.name in FORBIDDEN_FILENAMES:
        raise ArtifactValidationError(
            f"{artifact.name} contains local report/editor file: {relative}"
        )
    if relative.suffix.lower() in {".pyc", ".pyo"}:
        raise ArtifactValidationError(f"{artifact.name} contains Python bytecode: {relative}")
    if relative.name.endswith(("~", ".swp", ".swo")):
        raise ArtifactValidationError(f"{artifact.name} contains editor swap file: {relative}")
    if _is_unexpected_binary(relative):
        raise ArtifactValidationError(f"{artifact.name} contains unexpected binary: {relative}")


def _is_unexpected_binary(relative: PurePosixPath) -> bool:
    name = relative.name.lower()
    if name.endswith(".tar.gz"):
        return True
    return relative.suffix.lower() in FORBIDDEN_SUFFIXES


def _validate_secret_markers(relative: PurePosixPath, payload: bytes, *, artifact: Path) -> None:
    if any(marker in payload for marker in SECRET_MARKERS):
        raise ArtifactValidationError(
            f"{artifact.name} contains secret-like material in {relative}"
        )


def _validate_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ArtifactValidationError(
                f"{path.name} must contain exactly one wheel METADATA file"
            )
        if "trustcheck/py.typed" not in names:
            raise ArtifactValidationError(f"{path.name} must contain trustcheck/py.typed")
        if not any(name.startswith("trustcheck/plugin_schemas/") for name in names):
            raise ArtifactValidationError(f"{path.name} must contain plugin IPC schemas")
        for name in names:
            relative = _safe_relative_name(name)
            if name.endswith("/"):
                continue
            _validate_common_path(relative, artifact=path)
            _validate_secret_markers(relative, archive.read(name), artifact=path)


def _validate_sdist(path: Path) -> None:
    with tarfile.open(path) as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        rooted_paths = [_safe_relative_name(member.name) for member in members]
        names = [member.name for member in members]
        package_info = [
            name
            for name in rooted_paths
            if _sdist_relative_path(name) == PurePosixPath("PKG-INFO")
        ]
        if len(package_info) != 1:
            raise ArtifactValidationError(f"{path.name} must contain exactly one PKG-INFO file")
        required_suffixes = {
            "MANIFEST.in",
            "pyproject.toml",
            "scripts/validate_distribution_artifacts.py",
            "scripts/verify_release_version.py",
            "src/trustcheck/_version.py",
            "src/trustcheck/py.typed",
            "tests/test_release_version.py",
        }
        sdist_paths = {_sdist_relative_path(_safe_relative_name(name)).as_posix() for name in names}
        missing = sorted(required_suffixes - sdist_paths)
        if missing:
            raise ArtifactValidationError(
                f"{path.name} is missing required source files: {', '.join(missing)}"
            )
        for member in members:
            rooted = _safe_relative_name(member.name)
            relative = _sdist_relative_path(rooted)
            _validate_common_path(relative, artifact=path)
            extracted = archive.extractfile(member)
            if extracted is not None:
                _validate_secret_markers(relative, extracted.read(), artifact=path)


def validate_artifact(path: Path) -> None:
    if path.name.endswith(".whl"):
        _validate_wheel(path)
        return
    if path.name.endswith(".tar.gz"):
        _validate_sdist(path)
        return
    raise ArtifactValidationError(f"unsupported distribution artifact: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Trustcheck wheel and sdist contents before publication."
    )
    parser.add_argument("artifacts", nargs="+", help="Distribution artifact path or glob.")
    args = parser.parse_args(argv)
    try:
        for artifact in _expand_artifacts(args.artifacts):
            validate_artifact(artifact)
    except (OSError, ArtifactValidationError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
