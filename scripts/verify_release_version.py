from __future__ import annotations

import argparse
import email
import tarfile
import zipfile
from pathlib import Path

from packaging.version import InvalidVersion, Version


def _expected_version(*, tag: str | None, expected: str | None) -> str:
    value = expected if expected is not None else (tag or "").removeprefix("v")
    try:
        normalized = str(Version(value))
    except InvalidVersion as exc:
        raise ValueError(f"invalid expected release version: {value!r}") from exc
    if value != normalized:
        raise ValueError(
            f"expected version must already be normalized: {value!r} != {normalized!r}"
        )
    return normalized


def _wheel_metadata(path: Path) -> bytes:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError(f"wheel must contain exactly one METADATA file: {path}")
        return archive.read(names[0])


def _sdist_metadata(path: Path) -> bytes:
    with tarfile.open(path, "r:*") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.isfile()
            and member.name.endswith("/PKG-INFO")
            and len(Path(member.name).parts) == 2
        ]
        if len(members) != 1:
            raise ValueError(f"sdist must contain exactly one root PKG-INFO file: {path}")
        handle = archive.extractfile(members[0])
        if handle is None:
            raise ValueError(f"unable to read sdist metadata: {path}")
        return handle.read()


def verify_artifact_version(path: Path, expected: str) -> None:
    if path.name.endswith(".whl"):
        raw_metadata = _wheel_metadata(path)
    elif path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")):
        raw_metadata = _sdist_metadata(path)
    else:
        raise ValueError(f"unsupported release artifact: {path}")
    metadata = email.message_from_bytes(raw_metadata)
    name = metadata.get("Name")
    version = metadata.get("Version")
    if name != "trustcheck":
        raise ValueError(f"unexpected project name in {path}: {name!r}")
    if version != expected:
        raise ValueError(
            f"release artifact version does not match tag in {path}: "
            f"expected {expected!r}, found {version!r}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Trustcheck wheel and sdist versions against a release tag."
    )
    version_group = parser.add_mutually_exclusive_group(required=True)
    version_group.add_argument("--tag")
    version_group.add_argument("--expected")
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        expected = _expected_version(tag=args.tag, expected=args.expected)
        for artifact in args.artifacts:
            verify_artifact_version(artifact, expected)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
