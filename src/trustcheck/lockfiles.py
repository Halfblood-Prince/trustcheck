from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import parse

from packaging.markers import InvalidMarker, Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .resolver import ArtifactReference

SUPPORTED_LOCKFILES = {"pdm.lock", "pipfile.lock", "poetry.lock", "uv.lock"}
PYLOCK_NAME = re.compile(r"^pylock(?:\.[^.]+)?\.toml$")
_MARKER_TOKEN = re.compile(
    r"(?P<space>\s+)|"
    r"(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    r"(?P<word>[A-Za-z_][A-Za-z0-9_.-]*)|"
    r"(?P<other>.)"
)


@dataclass(frozen=True, slots=True)
class LockedPackage:
    name: str
    version: str
    requirement: str
    artifacts: tuple[ArtifactReference, ...] = ()
    index_url: str | None = None
    requires_dist: tuple[str, ...] = ()
    source_type: str = "index"


@dataclass(frozen=True, slots=True)
class LockfileResolution:
    requirements: list[str]
    versions: dict[str, str]
    packages: tuple[LockedPackage, ...] = ()
    format: str = "unknown"
    warnings: tuple[str, ...] = ()

    @property
    def artifacts(self) -> dict[str, tuple[ArtifactReference, ...]]:
        return {
            canonicalize_name(package.name): package.artifacts
            for package in self.packages
        }


def is_supported_lockfile(path: Path) -> bool:
    name = path.name.lower()
    return name in SUPPORTED_LOCKFILES or PYLOCK_NAME.fullmatch(name) is not None


def load_lockfile(
    path: Path,
    *,
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    environment: Mapping[str, str] | None = None,
) -> LockfileResolution:
    name = path.name.lower()
    if name == "pipfile.lock":
        return _load_pipfile_lock(
            path,
            groups=groups,
            environment=environment,
        )

    payload = _read_toml_lockfile(path)
    if PYLOCK_NAME.fullmatch(name):
        return _load_pylock(
            path,
            payload,
            extras=extras,
            groups=groups,
            environment=environment,
        )
    return _load_legacy_toml_lockfile(
        path,
        payload,
        environment=environment,
    )


def load_pip_tools_lock(
    path: Path,
    *,
    _seen: set[Path] | None = None,
) -> LockfileResolution | None:
    resolved_path = path.resolve()
    seen = _seen if _seen is not None else set()
    if resolved_path in seen:
        raise ValueError(f"cyclic requirements include involving {resolved_path}")
    seen.add(resolved_path)

    requirements: list[str] = []
    packages: list[LockedPackage] = []
    versions: dict[str, str] = {}
    found_hash = False
    for entry in _logical_requirement_lines(resolved_path):
        include = _included_requirements_path(entry, resolved_path.parent)
        if include is not None:
            if not include.is_file():
                continue
            nested = load_pip_tools_lock(include, _seen=seen)
            if nested is not None:
                found_hash = True
                for package in nested.packages:
                    _add_locked_package(
                        package,
                        packages=packages,
                        requirements=requirements,
                        versions=versions,
                        path=resolved_path,
                    )
            continue
        cleaned = _clean_requirement_entry(entry)
        if cleaned is None:
            continue
        requirement_text, hashes = cleaned
        if hashes:
            found_hash = True
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            continue
        version = _exact_requirement_version(requirement)
        if version is None:
            continue
        artifacts = tuple(
            ArtifactReference(
                hashes=((algorithm, digest),),
                kind="lock-hash",
            )
            for algorithm, digest in hashes
        )
        _add_locked_package(
            LockedPackage(
                name=requirement.name,
                version=version,
                requirement=str(requirement),
                artifacts=artifacts,
            ),
            packages=packages,
            requirements=requirements,
            versions=versions,
            path=resolved_path,
        )
    seen.remove(resolved_path)
    if not found_hash:
        return None
    if not packages:
        raise ValueError(f"no exact hash-pinned requirements found in {resolved_path}")
    return LockfileResolution(
        requirements=requirements,
        versions=versions,
        packages=tuple(packages),
        format="pip-tools",
    )


def _read_toml_lockfile(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as toml_file:
            payload = tomllib.load(toml_file)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid TOML lockfile in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"lockfile must contain a top-level table: {path}")
    return payload


def _load_legacy_toml_lockfile(
    path: Path,
    payload: dict[str, Any],
    *,
    environment: Mapping[str, str] | None,
) -> LockfileResolution:
    packages_payload = payload.get("package")
    if not isinstance(packages_payload, list):
        raise ValueError(f"no supported locked packages found in {path}")

    lockfile_kind = path.name.lower()
    marker_environment = _marker_environment(environment)
    requirements: list[str] = []
    versions: dict[str, str] = {}
    packages: list[LockedPackage] = []

    for index, package in enumerate(packages_payload, 1):
        if not isinstance(package, dict):
            continue
        if not _lock_package_applies(
            package,
            marker_environment,
            path=path,
            index=index,
        ):
            continue
        if not _is_registry_package(package, lockfile_kind):
            continue

        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(version, str) or not version.strip():
            continue
        requirement_text = _validated_exact_requirement(
            name,
            version,
            path=path,
            index=index,
        )
        locked_package = LockedPackage(
            name=name.strip(),
            version=version.strip(),
            requirement=requirement_text,
            artifacts=_legacy_artifacts(
                package,
                payload=payload,
                kind=lockfile_kind,
                path=path,
            ),
            index_url=_legacy_index_url(package, payload, lockfile_kind),
            requires_dist=_legacy_dependencies(package),
        )
        _add_locked_package(
            locked_package,
            packages=packages,
            requirements=requirements,
            versions=versions,
            path=path,
        )

    if not requirements:
        raise ValueError(f"no supported locked packages found in {path}")
    return LockfileResolution(
        requirements=requirements,
        versions=versions,
        packages=tuple(packages),
        format=lockfile_kind,
    )


def _load_pylock(
    path: Path,
    payload: dict[str, Any],
    *,
    extras: Sequence[str],
    groups: Sequence[str],
    environment: Mapping[str, str] | None,
) -> LockfileResolution:
    lock_version = payload.get("lock-version")
    if not isinstance(lock_version, str):
        raise ValueError(f"{path} is missing required lock-version")
    try:
        parsed_lock_version = Version(lock_version)
    except InvalidVersion as exc:
        raise ValueError(f"invalid pylock lock-version {lock_version!r}") from exc
    if parsed_lock_version.major != 1:
        raise ValueError(f"unsupported pylock lock-version {lock_version!r}")
    if not isinstance(payload.get("created-by"), str):
        raise ValueError(f"{path} is missing required created-by")

    marker_environment: dict[str, Any] = dict(_marker_environment(environment))
    declared_extras = _string_list(payload.get("extras"), field_name="extras", path=path)
    declared_groups = _string_list(
        payload.get("dependency-groups"),
        field_name="dependency-groups",
        path=path,
    )
    default_groups = _string_list(
        payload.get("default-groups"),
        field_name="default-groups",
        path=path,
    )
    selected_extras = set(extras)
    selected_groups = set(groups or default_groups)
    unknown_extras = sorted(selected_extras.difference(declared_extras))
    unknown_groups = sorted(selected_groups.difference(declared_groups, default_groups))
    if unknown_extras:
        raise ValueError(f"unknown pylock extra(s): {', '.join(unknown_extras)}")
    if unknown_groups:
        raise ValueError(
            f"unknown pylock dependency group(s): {', '.join(unknown_groups)}"
        )
    marker_environment["extras"] = selected_extras
    marker_environment["dependency_groups"] = selected_groups

    _validate_requires_python(
        payload.get("requires-python"),
        marker_environment,
        context=str(path),
    )
    raw_environments = payload.get("environments")
    if raw_environments is not None:
        environment_markers = _string_list(
            raw_environments,
            field_name="environments",
            path=path,
        )
        if environment_markers and not any(
            _evaluate_marker(
                expression,
                marker_environment,
                context=f"{path} environments",
            )
            for expression in environment_markers
        ):
            raise ValueError(f"target environment is not supported by {path}")

    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, list):
        raise ValueError(f"{path} is missing required packages array")
    requirements: list[str] = []
    versions: dict[str, str] = {}
    packages: list[LockedPackage] = []
    warnings: list[str] = []
    for index, package in enumerate(raw_packages, 1):
        if not isinstance(package, dict):
            raise ValueError(f"invalid pylock package {index}: expected a table")
        marker = package.get("marker")
        if marker is not None:
            if not isinstance(marker, str):
                raise ValueError(f"invalid marker for pylock package {index}")
            if not _evaluate_marker(
                marker,
                marker_environment,
                context=f"{path} package {index}",
            ):
                continue

        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not name:
            raise ValueError(f"pylock package {index} is missing name")
        _validate_requires_python(
            package.get("requires-python"),
            marker_environment,
            context=f"{path} package {name}",
        )
        source_type, artifacts, source_url = _pylock_source(
            package,
            path=path,
            index=index,
        )
        if not isinstance(version, str) or not version:
            warnings.append(
                f"{name}: source tree has no stable version and cannot be audited "
                "as a package release"
            )
            continue
        requirement_text = _validated_exact_requirement(
            name,
            version,
            path=path,
            index=index,
        )
        index_url = package.get("index")
        if index_url is not None and not isinstance(index_url, str):
            raise ValueError(f"invalid index URL for pylock package {name!r}")
        if source_url and not artifacts:
            artifacts = (
                ArtifactReference(
                    filename=_filename_from_location(source_url),
                    url=source_url,
                    kind=source_type,
                ),
            )
        locked_package = LockedPackage(
            name=name,
            version=version,
            requirement=requirement_text,
            artifacts=artifacts,
            index_url=(
                index_url if isinstance(index_url, str) else None
            ),
            requires_dist=_pylock_dependencies(package.get("dependencies")),
            source_type=source_type,
        )
        _add_locked_package(
            locked_package,
            packages=packages,
            requirements=requirements,
            versions=versions,
            path=path,
        )
    if not packages:
        raise ValueError(f"no supported locked packages found in {path}")
    return LockfileResolution(
        requirements=requirements,
        versions=versions,
        packages=tuple(packages),
        format="pylock.toml",
        warnings=tuple(warnings),
    )


def _load_pipfile_lock(
    path: Path,
    *,
    groups: Sequence[str],
    environment: Mapping[str, str] | None,
) -> LockfileResolution:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid Pipfile.lock in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"lockfile must contain a top-level object: {path}")
    meta = payload.get("_meta")
    sources: dict[str, str] = {}
    if isinstance(meta, dict):
        raw_sources = meta.get("sources")
        if isinstance(raw_sources, list):
            for source in raw_sources:
                if not isinstance(source, dict):
                    continue
                name = source.get("name")
                url = source.get("url")
                if isinstance(name, str) and isinstance(url, str):
                    sources[canonicalize_name(name)] = url

    selected_groups = tuple(groups) if groups else ("default", "develop")
    unknown_groups = [
        group for group in selected_groups if group not in {"default", "develop"}
    ]
    if unknown_groups:
        raise ValueError(
            f"unknown Pipfile.lock group(s): {', '.join(unknown_groups)}"
        )
    marker_environment = _marker_environment(environment)
    requirements: list[str] = []
    versions: dict[str, str] = {}
    packages: list[LockedPackage] = []
    for group in selected_groups:
        entries = payload.get(group)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            raise ValueError(f"Pipfile.lock {group!r} must be an object")
        for name, raw_entry in entries.items():
            if not isinstance(raw_entry, dict):
                continue
            if any(
                key in raw_entry
                for key in ("editable", "file", "git", "hg", "path", "svn")
            ):
                continue
            marker = raw_entry.get("markers")
            if isinstance(marker, str) and not _evaluate_marker(
                marker,
                marker_environment,
                context=f"{path} {group}.{name}",
            ):
                continue
            raw_version = raw_entry.get("version")
            if not isinstance(raw_version, str):
                raise ValueError(f"Pipfile.lock entry {name!r} has no exact version")
            requirement = Requirement(f"{name}{raw_version}")
            version = _exact_requirement_version(requirement)
            if version is None:
                raise ValueError(
                    f"Pipfile.lock entry {name!r} is not pinned to one exact version"
                )
            raw_hashes = raw_entry.get("hashes")
            artifacts_list: list[ArtifactReference] = []
            if isinstance(raw_hashes, list):
                for item in raw_hashes:
                    if not isinstance(item, str):
                        continue
                    parsed_hash = _parse_hash(item, context=f"{path} {name}")
                    if parsed_hash is not None:
                        artifacts_list.append(
                            ArtifactReference(
                                hashes=(parsed_hash,),
                                kind="lock-hash",
                            )
                        )
            artifacts = tuple(artifacts_list)
            index_name = raw_entry.get("index")
            index_url = (
                sources.get(canonicalize_name(index_name))
                if isinstance(index_name, str)
                else None
            )
            _add_locked_package(
                LockedPackage(
                    name=requirement.name,
                    version=version,
                    requirement=str(requirement),
                    artifacts=artifacts,
                    index_url=index_url,
                ),
                packages=packages,
                requirements=requirements,
                versions=versions,
                path=path,
            )
    if not packages:
        raise ValueError(f"no supported locked packages found in {path}")
    return LockfileResolution(
        requirements=requirements,
        versions=versions,
        packages=tuple(packages),
        format="Pipfile.lock",
    )


def _pylock_source(
    package: dict[str, Any],
    *,
    path: Path,
    index: int,
) -> tuple[str, tuple[ArtifactReference, ...], str | None]:
    source_keys = [
        key
        for key in ("vcs", "directory", "archive", "sdist", "wheels")
        if package.get(key) is not None
    ]
    if "sdist" in source_keys and "wheels" in source_keys:
        source_keys.remove("wheels")
    if len(source_keys) != 1:
        raise ValueError(
            f"pylock package {index} must specify exactly one source; "
            f"found {', '.join(source_keys) or 'none'}"
        )
    source_type = source_keys[0]
    if source_type == "wheels":
        raw_wheels = package["wheels"]
        if not isinstance(raw_wheels, list) or not raw_wheels:
            raise ValueError(f"pylock package {index} wheels must be a non-empty array")
        return (
            "wheel",
            tuple(
                _pylock_artifact(
                    wheel,
                    path=path,
                    context=f"package {index} wheel {wheel_index}",
                    kind="wheel",
                )
                for wheel_index, wheel in enumerate(raw_wheels, 1)
            ),
            None,
        )
    if source_type == "sdist":
        artifacts = [
            _pylock_artifact(
                package["sdist"],
                path=path,
                context=f"package {index} sdist",
                kind="sdist",
            )
        ]
        raw_wheels = package.get("wheels")
        if raw_wheels is not None:
            if not isinstance(raw_wheels, list):
                raise ValueError(f"pylock package {index} wheels must be an array")
            artifacts.extend(
                _pylock_artifact(
                    wheel,
                    path=path,
                    context=f"package {index} wheel {wheel_index}",
                    kind="wheel",
                )
                for wheel_index, wheel in enumerate(raw_wheels, 1)
            )
        return "index", tuple(artifacts), None
    if source_type == "archive":
        artifact = _pylock_artifact(
            package["archive"],
            path=path,
            context=f"package {index} archive",
            kind="archive",
        )
        return "archive", (artifact,), artifact.url
    if source_type == "directory":
        directory = package["directory"]
        if not isinstance(directory, dict) or not isinstance(directory.get("path"), str):
            raise ValueError(f"invalid pylock directory source at package {index}")
        source_path = _resolve_lock_path(path, directory["path"])
        return "directory", (), source_path.as_uri()

    vcs = package["vcs"]
    if not isinstance(vcs, dict):
        raise ValueError(f"invalid pylock VCS source at package {index}")
    vcs_type = vcs.get("type")
    commit = vcs.get("commit-id")
    if not isinstance(vcs_type, str) or not isinstance(commit, str):
        raise ValueError(f"pylock VCS source at package {index} is incomplete")
    raw_url = vcs.get("url")
    raw_path = vcs.get("path")
    if isinstance(raw_url, str) == isinstance(raw_path, str):
        raise ValueError(
            f"pylock VCS source at package {index} needs exactly one of url or path"
        )
    base = (
        raw_url
        if isinstance(raw_url, str)
        else _resolve_lock_path(path, str(raw_path)).as_uri()
    )
    source_url = f"{vcs_type}+{base}@{commit}"
    subdirectory = vcs.get("subdirectory")
    if isinstance(subdirectory, str) and subdirectory:
        source_url = f"{source_url}#subdirectory={parse.quote(subdirectory)}"
    return "vcs", (), source_url


def _pylock_artifact(
    value: object,
    *,
    path: Path,
    context: str,
    kind: str,
) -> ArtifactReference:
    if not isinstance(value, dict):
        raise ValueError(f"invalid pylock artifact at {context}")
    raw_url = value.get("url")
    raw_path = value.get("path")
    if not isinstance(raw_url, str) and not isinstance(raw_path, str):
        raise ValueError(f"pylock artifact at {context} needs url or path")
    artifact_path = (
        str(_resolve_lock_path(path, raw_path))
        if isinstance(raw_path, str)
        else None
    )
    artifact_url = (
        raw_url
        if isinstance(raw_url, str)
        else Path(artifact_path or "").as_uri()
    )
    hashes = _hash_table(value.get("hashes"), context=context, required=True)
    filename = value.get("name")
    if not isinstance(filename, str) or not filename:
        filename = _filename_from_location(artifact_path or artifact_url)
    size = value.get("size")
    if size is not None and (not isinstance(size, int) or size < 0):
        raise ValueError(f"invalid artifact size at {context}")
    return ArtifactReference(
        filename=filename,
        url=artifact_url,
        path=artifact_path,
        hashes=hashes,
        size=size,
        kind=kind,
    )


def _legacy_artifacts(
    package: dict[str, Any],
    *,
    payload: dict[str, Any],
    kind: str,
    path: Path,
) -> tuple[ArtifactReference, ...]:
    artifacts: list[ArtifactReference] = []
    if kind == "uv.lock":
        sdist = package.get("sdist")
        if isinstance(sdist, dict):
            artifacts.append(_legacy_artifact(sdist, kind="sdist", path=path))
        wheels = package.get("wheels")
        if isinstance(wheels, list):
            artifacts.extend(
                _legacy_artifact(item, kind="wheel", path=path)
                for item in wheels
                if isinstance(item, dict)
            )
    else:
        files = package.get("files")
        if not isinstance(files, list) and kind == "pdm.lock":
            metadata = payload.get("metadata")
            metadata_files = (
                metadata.get("files") if isinstance(metadata, dict) else None
            )
            if isinstance(metadata_files, dict):
                files = metadata_files.get(package.get("name"))
        if isinstance(files, list):
            artifacts.extend(
                _legacy_artifact(item, kind="archive", path=path)
                for item in files
                if isinstance(item, dict)
            )
    return tuple(artifacts)


def _legacy_artifact(
    value: dict[str, Any],
    *,
    kind: str,
    path: Path,
) -> ArtifactReference:
    raw_url = value.get("url")
    raw_path = value.get("path")
    filename = value.get("file") or value.get("name")
    url = raw_url if isinstance(raw_url, str) else None
    local_path = (
        str(_resolve_lock_path(path, raw_path))
        if isinstance(raw_path, str)
        else None
    )
    if not isinstance(filename, str):
        filename = _filename_from_location(url or local_path)
    hashes = _hash_table(value.get("hashes"), context=str(path), required=False)
    raw_hash = value.get("hash")
    if isinstance(raw_hash, str):
        parsed_hash = _parse_hash(raw_hash, context=str(path))
        if parsed_hash is not None:
            hashes = tuple(sorted({*hashes, parsed_hash}))
    size = value.get("size")
    return ArtifactReference(
        filename=filename,
        url=url,
        path=local_path,
        hashes=hashes,
        size=size if isinstance(size, int) and size >= 0 else None,
        kind=kind,
    )


def _legacy_index_url(
    package: dict[str, Any],
    payload: dict[str, Any],
    kind: str,
) -> str | None:
    source = package.get("source")
    if kind == "uv.lock" and isinstance(source, dict):
        registry = source.get("registry")
        return (
            registry if isinstance(registry, str) else None
        )
    if kind == "poetry.lock" and isinstance(source, dict):
        url = source.get("url")
        return url if isinstance(url, str) else None
    if kind == "pdm.lock":
        metadata = payload.get("metadata")
        raw_sources = metadata.get("sources") if isinstance(metadata, dict) else None
        if isinstance(raw_sources, list) and len(raw_sources) == 1:
            source_entry = raw_sources[0]
            if isinstance(source_entry, dict) and isinstance(source_entry.get("url"), str):
                return str(source_entry["url"])
    return None


def _legacy_dependencies(package: dict[str, Any]) -> tuple[str, ...]:
    raw = package.get("dependencies")
    if isinstance(raw, list):
        return tuple(item for item in raw if isinstance(item, str))
    if isinstance(raw, dict):
        return tuple(
            f"{name}{specifier if isinstance(specifier, str) else ''}"
            for name, specifier in raw.items()
        )
    return ()


def _pylock_dependencies(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    dependencies: list[str] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"]
        version = item.get("version")
        dependencies.append(
            f"{name}=={version}" if isinstance(version, str) else name
        )
    return tuple(dependencies)


def _lock_package_applies(
    package: dict[str, Any],
    environment: Mapping[str, Any],
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
        marker_expressions.extend(
            item for item in marker_value if isinstance(item, str)
        )
    elif isinstance(marker_value, dict):
        marker_expressions.extend(
            item for item in marker_value.values() if isinstance(item, str)
        )
    if not marker_expressions:
        return True
    return any(
        _evaluate_marker(
            expression,
            environment,
            context=f"{path} package {index}",
        )
        for expression in marker_expressions
    )


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

    return not any(
        package.get(field) is not None
        for field in ("editable", "git", "path", "url")
    )


def _add_locked_package(
    package: LockedPackage,
    *,
    packages: list[LockedPackage],
    requirements: list[str],
    versions: dict[str, str],
    path: Path,
) -> None:
    key = canonicalize_name(package.name)
    existing_version = versions.get(key)
    if existing_version is not None and existing_version != package.version:
        raise ValueError(
            f"multiple active locked versions for {package.name!r} in {path}: "
            f"{existing_version} and {package.version}"
        )
    if existing_version is not None:
        existing_index = next(
            index
            for index, existing in enumerate(packages)
            if canonicalize_name(existing.name) == key
        )
        existing = packages[existing_index]
        merged_artifacts = tuple(
            dict.fromkeys((*existing.artifacts, *package.artifacts))
        )
        packages[existing_index] = LockedPackage(
            name=existing.name,
            version=existing.version,
            requirement=existing.requirement,
            artifacts=merged_artifacts,
            index_url=existing.index_url or package.index_url,
            requires_dist=tuple(
                dict.fromkeys((*existing.requires_dist, *package.requires_dist))
            ),
            source_type=existing.source_type,
        )
        return
    packages.append(package)
    requirements.append(package.requirement)
    versions[key] = package.version


def _validated_exact_requirement(
    name: str,
    version: str,
    *,
    path: Path,
    index: int,
) -> str:
    requirement_text = f"{name.strip()}=={version.strip()}"
    try:
        Requirement(requirement_text)
    except InvalidRequirement as exc:
        raise ValueError(
            f"invalid locked package in {path} at package {index}: {exc}"
        ) from exc
    return requirement_text


def _marker_environment(
    environment: Mapping[str, str] | None,
) -> dict[str, str]:
    result = {key: str(value) for key, value in default_environment().items()}
    if environment:
        result.update({key: str(value) for key, value in environment.items()})
    result.setdefault("extra", "")
    return result


def _evaluate_marker(
    expression: str,
    environment: Mapping[str, Any],
    *,
    context: str,
) -> bool:
    try:
        compatible_expression = _compatible_set_marker(expression, environment)
        return Marker(compatible_expression).evaluate(environment=dict(environment))
    except (InvalidMarker, KeyError) as exc:
        raise ValueError(f"invalid environment marker in {context}: {exc}") from exc


def _compatible_set_marker(
    expression: str,
    environment: Mapping[str, Any],
) -> str:
    """Reduce PEP 751 set membership for packaging versions older than 25."""
    tokens = [
        (match.lastgroup, match.group(), match.start(), match.end())
        for match in _MARKER_TOKEN.finditer(expression)
        if match.lastgroup != "space"
    ]
    replacements: list[tuple[int, int, str]] = []
    index = 0
    while index < len(tokens):
        kind, text, start, _ = tokens[index]
        if kind != "string" or index + 2 >= len(tokens):
            index += 1
            continue

        operator = tokens[index + 1][1]
        variable_index = index + 2
        if operator == "not" and index + 3 < len(tokens):
            if tokens[index + 2][1] != "in":
                index += 1
                continue
            operator = "not in"
            variable_index = index + 3
        elif operator != "in":
            index += 1
            continue

        variable = tokens[variable_index][1]
        if variable not in {"extras", "dependency_groups"}:
            index += 1
            continue

        value = str(ast.literal_eval(text))
        applies = value in environment[variable]
        if operator == "not in":
            applies = not applies
        comparison = "==" if applies else "!="
        os_name = repr(str(environment["os_name"]))
        replacements.append(
            (start, tokens[variable_index][3], f"os_name {comparison} {os_name}")
        )
        index = variable_index + 1

    for start, end, replacement in reversed(replacements):
        expression = expression[:start] + replacement + expression[end:]
    return expression


def _validate_requires_python(
    value: object,
    environment: Mapping[str, Any],
    *,
    context: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"invalid requires-python in {context}")
    try:
        specifier = SpecifierSet(value)
    except InvalidSpecifier as exc:
        raise ValueError(f"invalid requires-python in {context}: {exc}") from exc
    python_version = str(
        environment.get("python_full_version")
        or environment.get("python_version")
        or ""
    )
    if python_version and not specifier.contains(python_version, prereleases=True):
        raise ValueError(
            f"target Python {python_version} does not satisfy "
            f"requires-python {value!r} in {context}"
        )


def _string_list(value: object, *, field_name: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{field_name} in {path} must be an array of strings")
    return list(value)


def _hash_table(
    value: object,
    *,
    context: str,
    required: bool,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        if required:
            raise ValueError(f"artifact hashes are required at {context}")
        return ()
    hashes: list[tuple[str, str]] = []
    for algorithm, digest in value.items():
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise ValueError(f"invalid artifact hash at {context}")
        parsed_hash = _parse_hash(f"{algorithm}:{digest}", context=context)
        if parsed_hash is not None:
            hashes.append(parsed_hash)
    if required and not hashes:
        raise ValueError(f"artifact hashes are required at {context}")
    return tuple(sorted(hashes))


def _parse_hash(value: str, *, context: str) -> tuple[str, str] | None:
    separator = ":" if ":" in value else "="
    if separator not in value:
        raise ValueError(f"invalid artifact hash at {context}: {value!r}")
    algorithm, digest = value.split(separator, 1)
    normalized_algorithm = algorithm.strip().lower()
    normalized_digest = digest.strip().lower()
    if not re.fullmatch(r"[a-z0-9_+-]+", normalized_algorithm):
        raise ValueError(f"invalid hash algorithm at {context}: {algorithm!r}")
    if not re.fullmatch(r"[0-9a-f]+", normalized_digest):
        raise ValueError(f"invalid hash digest at {context}")
    return normalized_algorithm, normalized_digest


def _logical_requirement_lines(path: Path) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.rstrip()
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment.strip()}".strip()
        if not continued:
            if pending:
                lines.append(pending)
            pending = ""
    if pending:
        lines.append(pending)
    return lines


def _included_requirements_path(entry: str, base_path: Path) -> Path | None:
    match = re.match(r"^\s*(?:-r|--requirement)\s+(.+?)\s*$", entry)
    if match is None:
        return None
    raw_path = match.group(1).strip().strip("\"'")
    path = Path(raw_path)
    return path if path.is_absolute() else base_path / path


def _clean_requirement_entry(
    entry: str,
) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    line = entry.strip()
    if not line or line.startswith("#") or line.startswith(("-", "--")):
        return None
    line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
    hashes = tuple(
        _parse_hash(match.group(1), context="requirements file")
        for match in re.finditer(
            r"(?:^|\s)--hash(?:=|\s+)([A-Za-z0-9_+-]+[:=][0-9A-Fa-f]+)",
            line,
        )
    )
    requirement_text = re.split(
        r"\s+--hash(?:=|\s+)",
        line,
        maxsplit=1,
    )[0].strip()
    return requirement_text, tuple(item for item in hashes if item is not None)


def _exact_requirement_version(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="}:
        return None
    if "*" in specifiers[0].version:
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


def _resolve_lock_path(lockfile: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        path = lockfile.parent / path
    return path.resolve()


def _filename_from_location(location: str | None) -> str | None:
    if not location:
        return None
    parsed = parse.urlsplit(location)
    candidate = parse.unquote(parsed.path) if parsed.scheme else location
    filename = Path(candidate).name
    return filename or None
