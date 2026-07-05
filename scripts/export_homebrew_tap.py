from __future__ import annotations

import argparse
import json
import re
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

PACKAGE_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^\\\s;]+)(?:\s*;[^\\]+)?(?:\s*\\)?$"
)
HASH_LINE = re.compile(r"--hash=sha256:(?P<hash>[0-9a-f]{64})")


FetchJson = Callable[[str, str], Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class LockedPackage:
    name: str
    version: str
    hashes: frozenset[str]


@dataclass(frozen=True, slots=True)
class Distribution:
    filename: str
    url: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ResourcePin:
    name: str
    version: str
    filename: str
    url: str
    sha256: str


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lockfile(path: Path) -> dict[str, LockedPackage]:
    packages: dict[str, LockedPackage] = {}
    current_name: str | None = None
    current_version: str | None = None
    current_hashes: set[str] = set()

    def flush_current() -> None:
        nonlocal current_name, current_version, current_hashes
        if current_name is None or current_version is None:
            return
        if not current_hashes:
            raise ValueError(f"{path}: {current_name}=={current_version} has no hashes")
        packages[canonical_name(current_name)] = LockedPackage(
            name=current_name,
            version=current_version,
            hashes=frozenset(current_hashes),
        )
        current_name = None
        current_version = None
        current_hashes = set()

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        package_match = PACKAGE_LINE.match(line)
        if package_match is not None:
            flush_current()
            current_name = package_match.group("name")
            current_version = package_match.group("version")
            continue
        if current_name is None:
            continue
        for hash_match in HASH_LINE.finditer(line):
            current_hashes.add(hash_match.group("hash"))
    flush_current()
    if not packages:
        raise ValueError(f"{path}: no pinned packages found")
    return packages


def parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        digest, filename = stripped.split(maxsplit=1)
        checksums[Path(filename).name] = digest.lower()
    if not checksums:
        raise ValueError(f"{path}: no checksums found")
    return checksums


def read_pypi_json(project: str, version: str) -> Mapping[str, object]:
    encoded_project = quote(project, safe="")
    encoded_version = quote(version, safe="")
    url = f"https://pypi.org/pypi/{encoded_project}/{encoded_version}/json"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "trustcheck-homebrew-tap-exporter",
        },
    )
    last_error: Exception | None = None
    for attempt in range(1, 7):
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.load(response)
            if not isinstance(payload, dict):
                raise ValueError(f"{project}=={version}: PyPI returned non-object JSON")
            return payload
        except (OSError, URLError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < 6:
                time.sleep(10)
    raise ValueError(f"Unable to read PyPI metadata for {project}=={version}") from last_error


def fetch_sdist(
    project: str,
    version: str,
    fetch_json: FetchJson = read_pypi_json,
) -> Distribution:
    payload = fetch_json(project, version)
    urls = payload.get("urls")
    if not isinstance(urls, list):
        raise ValueError(f"{project}=={version}: PyPI metadata has no urls array")

    candidates: list[Distribution] = []
    for item in urls:
        if not isinstance(item, Mapping) or item.get("packagetype") != "sdist":
            continue
        digests = item.get("digests")
        filename = item.get("filename")
        url = item.get("url")
        if not isinstance(digests, Mapping):
            continue
        sha256 = digests.get("sha256")
        if (
            isinstance(filename, str)
            and isinstance(url, str)
            and isinstance(sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", sha256)
        ):
            candidates.append(Distribution(filename=filename, url=url, sha256=sha256))
    if not candidates:
        raise ValueError(f"{project}=={version}: no PyPI sdist found")
    return sorted(
        candidates,
        key=lambda item: (not item.filename.endswith(".tar.gz"), item.filename),
    )[0]


def render_homebrew_resources(resources: Sequence[ResourcePin]) -> str:
    lines = [
        "# This file is generated by scripts/export_homebrew_tap.py.",
        "# Do not edit manually.",
        "",
    ]
    for resource in resources:
        lines.extend(
            [
                f'resource "{resource.name}" do',
                f'  url "{resource.url}"',
                f'  sha256 "{resource.sha256}"',
                "end",
                "",
            ]
        )
    return "\n".join(lines)


def export_homebrew_tap(
    *,
    runtime_lock: Path,
    build_lock: Path | None,
    checksums: Path,
    output_dir: Path,
    tag: str,
    source_repository: str,
    source_commit: str,
    package_name: str = "trustcheck",
    extra_packages: Sequence[str] = (),
    fetch_json: FetchJson = read_pypi_json,
) -> None:
    version = tag.removeprefix("v")
    runtime_packages = parse_lockfile(runtime_lock)
    build_packages = parse_lockfile(build_lock) if build_lock is not None else {}
    selected_packages = dict(runtime_packages)

    for package in extra_packages:
        key = canonical_name(package)
        if key in selected_packages:
            continue
        try:
            selected_packages[key] = build_packages[key]
        except KeyError as exc:
            raise ValueError(
                f"extra package {package!r} is not pinned in {build_lock}"
            ) from exc

    release_sdist = fetch_sdist(package_name, version, fetch_json)
    release_checksums = parse_checksums(checksums)
    expected_release_hash = release_checksums.get(release_sdist.filename)
    if expected_release_hash != release_sdist.sha256:
        raise ValueError(
            f"{release_sdist.filename} PyPI sha256 does not match {checksums}: "
            f"{release_sdist.sha256} != {expected_release_hash}"
        )

    resources: list[ResourcePin] = []
    for package in sorted(
        selected_packages.values(),
        key=lambda item: canonical_name(item.name),
    ):
        sdist = fetch_sdist(package.name, package.version, fetch_json)
        if sdist.sha256 not in package.hashes:
            raise ValueError(
                f"{package.name}=={package.version} sdist hash is not pinned in lockfile: "
                f"{sdist.sha256}"
            )
        resources.append(
            ResourcePin(
                name=canonical_name(package.name),
                version=package.version,
                filename=sdist.filename,
                url=sdist.url,
                sha256=sdist.sha256,
            )
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(runtime_lock, output_dir / "runtime.lock")
    (output_dir / "resources.rb").write_text(
        render_homebrew_resources(resources),
        encoding="utf-8",
    )
    (output_dir / "release.json").write_text(
        json.dumps(
            {
                "generated_by": "scripts/export_homebrew_tap.py",
                "package": {
                    "name": package_name,
                    "version": version,
                    "tag": tag,
                    "source_repository": source_repository,
                    "source_commit": source_commit,
                    "sdist": asdict(release_sdist),
                },
                "resources": [asdict(resource) for resource in resources],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export trustcheck release pins for the Homebrew tap."
    )
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--build-lock", type=Path)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--package-name", default="trustcheck")
    parser.add_argument("--extra-package", action="append", default=[])
    args = parser.parse_args(argv)

    export_homebrew_tap(
        runtime_lock=args.runtime_lock,
        build_lock=args.build_lock,
        checksums=args.checksums,
        output_dir=args.output_dir,
        tag=args.tag,
        source_repository=args.source_repository,
        source_commit=args.source_commit,
        package_name=args.package_name,
        extra_packages=args.extra_package,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
