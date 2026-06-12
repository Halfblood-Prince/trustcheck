from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.markers import InvalidMarker, Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

SUPPORTED_LOCKFILES = {"pdm.lock", "poetry.lock", "uv.lock"}


@dataclass(frozen=True, slots=True)
class LockfileResolution:
    requirements: list[str]
    versions: dict[str, str]


def is_supported_lockfile(path: Path) -> bool:
    return path.name.lower() in SUPPORTED_LOCKFILES


def load_lockfile(path: Path) -> LockfileResolution:
    try:
        with path.open("rb") as toml_file:
            payload = tomllib.load(toml_file)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid TOML lockfile in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"lockfile must contain a top-level table: {path}")

    packages = payload.get("package")
    if not isinstance(packages, list):
        raise ValueError(f"no supported locked packages found in {path}")

    lockfile_kind = path.name.lower()
    environment = {key: str(value) for key, value in default_environment().items()}
    environment.setdefault("extra", "")
    requirements: list[str] = []
    versions: dict[str, str] = {}

    for index, package in enumerate(packages, 1):
        if not isinstance(package, dict):
            continue
        if not _lock_package_applies(package, environment, path=path, index=index):
            continue
        if not _is_registry_package(package, lockfile_kind):
            continue

        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(version, str) or not version.strip():
            continue

        requirement_text = f"{name.strip()}=={version.strip()}"
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement as exc:
            raise ValueError(f"invalid locked package in {path} at package {index}: {exc}") from exc

        key = canonicalize_name(requirement.name)
        existing_version = versions.get(key)
        if existing_version is not None:
            if existing_version != version.strip():
                raise ValueError(
                    f"multiple active locked versions for {requirement.name!r} in {path}: "
                    f"{existing_version} and {version.strip()}"
                )
            continue

        requirements.append(requirement_text)
        versions[key] = version.strip()

    if not requirements:
        raise ValueError(f"no supported locked packages found in {path}")
    return LockfileResolution(requirements=requirements, versions=versions)


def _lock_package_applies(
    package: dict[str, Any],
    environment: dict[str, str],
    *,
    path: Path,
    index: int,
) -> bool:
    marker_value = package.get("marker")
    if marker_value is None:
        marker_value = package.get("markers")
    if marker_value is None:
        marker_value = package.get("resolution-markers")
    if marker_value is None:
        return True

    marker_expressions: list[str] = []
    if isinstance(marker_value, str):
        marker_expressions.append(marker_value)
    elif isinstance(marker_value, list):
        marker_expressions.extend(item for item in marker_value if isinstance(item, str))
    elif isinstance(marker_value, dict):
        marker_expressions.extend(item for item in marker_value.values() if isinstance(item, str))
    if not marker_expressions:
        return True

    try:
        return any(Marker(expression).evaluate(environment) for expression in marker_expressions)
    except InvalidMarker as exc:
        raise ValueError(f"invalid environment marker in {path} at package {index}: {exc}") from exc


def _is_registry_package(package: dict[str, Any], lockfile_kind: str) -> bool:
    if lockfile_kind == "uv.lock":
        source = package.get("source")
        if source is None:
            return True
        return isinstance(source, dict) and "registry" in source

    if lockfile_kind == "poetry.lock":
        source = package.get("source")
        if not isinstance(source, dict):
            return True
        source_type = str(source.get("type") or "").lower()
        return source_type not in {"directory", "file", "git", "url"}

    return not any(package.get(field) is not None for field in ("editable", "git", "path", "url"))
