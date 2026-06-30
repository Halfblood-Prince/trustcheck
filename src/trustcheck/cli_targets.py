from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Sequence
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .cli_models import EXIT_DATA_ERROR, EXIT_OK, EXIT_UPSTREAM_FAILURE, ScanTarget
from .cli_runtime import _format_upstream_error, _target_marker_environment
from .lockfiles import (
    LockedPackage,
    LockfileResolution,
    is_supported_lockfile,
    load_lockfile,
    load_pip_tools_lock,
)
from .pypi import PypiClient, PypiClientError
from .resolver import (
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
)


def _load_scan_targets(
    path: str,
    client: PypiClient,
    *,
    resolver: PipResolver | None = None,
    constraints: Sequence[str | Path] = (),
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    target_environment: TargetEnvironment | None = None,
    offline: bool = False,
) -> list[ScanTarget]:
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError(f"scan file not found: {path}")

    if is_supported_lockfile(file_path):
        lockfile_resolution = load_lockfile(
            file_path,
            extras=extras,
            groups=groups,
            environment=_target_marker_environment(target_environment),
        )
        return _attach_source_locations(
            _scan_targets_from_lockfile(
                lockfile_resolution,
                resolver=resolver,
            ),
            file_path,
        )

    if file_path.suffix.lower() == ".toml":
        return _attach_source_locations(
            _load_scan_targets_from_toml(
                file_path,
                client,
                resolver=resolver,
                constraints=constraints,
                extras=extras,
                groups=groups,
                target_environment=target_environment,
                offline=offline,
            ),
            file_path,
        )

    if resolver is not None:
        pip_resolution = resolver.resolve_requirements_file(
            file_path,
            constraints=constraints,
            target=target_environment,
            offline=offline,
        )
        pip_tools_resolution = load_pip_tools_lock(file_path)
        return _attach_source_locations(
            _scan_targets_from_resolution(
                pip_resolution,
                lockfile_resolution=pip_tools_resolution,
            ),
            file_path,
        )

    requirement_lines = _read_requirements_file(file_path)
    locked_versions = _locked_versions_from_requirements(
        requirement_lines,
        source_path=file_path,
    )
    return _attach_source_locations(
        _build_scan_targets(
            requirement_lines,
            client,
            source_path=file_path,
            locked_versions=locked_versions,
        ),
        file_path,
    )


def _attach_source_locations(
    targets: list[ScanTarget],
    source_path: Path,
) -> list[ScanTarget]:
    resolved_path = source_path.resolve()
    lines = resolved_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()
    for target in targets:
        target.source_file = str(resolved_path)
        target.source_line = _source_line_for_project(lines, target.project)
    return targets


def _source_line_for_project(
    lines: Sequence[str],
    project: str,
) -> int | None:
    normalized = canonicalize_name(project)
    project_pattern = re.escape(normalized).replace(r"\-", "[-_.]+")
    pattern = re.compile(
        rf"(?<![A-Za-z0-9]){project_pattern}"
        r"(?![A-Za-z0-9])",
        re.IGNORECASE,
    )
    for line_number, line in enumerate(lines, 1):
        if pattern.search(line):
            return line_number
    return None


def _load_scan_targets_from_toml(
    file_path: Path,
    client: PypiClient,
    *,
    resolver: PipResolver | None = None,
    constraints: Sequence[str | Path] = (),
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    target_environment: TargetEnvironment | None = None,
    offline: bool = False,
) -> list[ScanTarget]:
    try:
        with file_path.open("rb") as toml_file:
            payload = tomllib.load(toml_file)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid TOML in {file_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"TOML file must contain a top-level table: {file_path}")

    requirement_lines = _extract_scan_requirements_from_toml(
        payload,
        extras=extras,
        groups=groups,
        base_path=file_path.parent,
    )
    if not requirement_lines:
        raise ValueError(f"no supported package requirements found in {file_path}")

    if resolver is not None:
        resolution = resolver.resolve_requirements(
            requirement_lines,
            constraints=constraints,
            target=target_environment,
            cwd=file_path.parent,
            offline=offline,
        )
        return _scan_targets_from_resolution(resolution)

    return _build_scan_targets(
        requirement_lines,
        client,
        source_path=file_path,
        entry_label="entry",
    )


def _build_scan_targets(
    requirement_lines: list[str],
    client: PypiClient,
    *,
    source_path: Path,
    locked_versions: dict[str, str] | None = None,
    complete_locked_versions: bool = False,
    entry_label: str = "line",
) -> list[ScanTarget]:
    environment = {key: str(value) for key, value in default_environment().items()}
    environment.setdefault("extra", "")
    resolved_versions = locked_versions or {}
    targets: list[ScanTarget] = []
    for line_number, line in enumerate(requirement_lines, 1):
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise ValueError(
                f"invalid requirement in {source_path} at {entry_label} {line_number}: {exc}"
            ) from exc
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        version, failure_message, failure_exit_code = _resolve_scan_target_version_for_scan(
            requirement,
            client,
        )
        targets.append(
            ScanTarget(
                requirement=line,
                project=requirement.name,
                version=version,
                failure_message=failure_message,
                failure_exit_code=failure_exit_code,
                locked_versions=resolved_versions,
                complete_locked_versions=complete_locked_versions,
            )
        )
    if not targets:
        raise ValueError(f"no supported package requirements found in {source_path}")
    return targets


def _scan_targets_from_resolution(
    resolution: Resolution,
    *,
    lockfile_resolution: LockfileResolution | None = None,
) -> list[ScanTarget]:
    if not resolution.distributions:
        raise ResolutionError("dependency resolution produced no distributions")
    versions = resolution.versions
    locked_packages = (
        {
            canonicalize_name(package.name): package
            for package in lockfile_resolution.packages
        }
        if lockfile_resolution is not None
        else {}
    )
    confusion = {
        canonicalize_name(finding.project): finding.indexes
        for finding in resolution.dependency_confusion
    }
    return [
        _scan_target_from_resolved_distribution(
            item,
            versions,
            locked_package=locked_packages.get(canonicalize_name(item.name)),
            dependency_confusion=confusion.get(
                canonicalize_name(item.name),
                (),
            ),
        )
        for item in resolution.distributions
    ]


def _scan_target_from_resolved_distribution(
    item: ResolvedDistribution,
    versions: dict[str, str],
    *,
    locked_package: LockedPackage | None = None,
    dependency_confusion: tuple[str, ...] = (),
) -> ScanTarget:
    artifacts = (
        locked_package.artifacts
        if locked_package is not None and locked_package.artifacts
        else item.artifacts
    )
    return ScanTarget(
        requirement=f"{item.name}=={item.version}",
        project=item.name,
        version=item.version,
        locked_versions=versions,
        complete_locked_versions=True,
        source_url=item.source_url,
        requested=item.requested,
        editable=item.editable,
        vcs=item.vcs,
        vcs_commit=item.vcs_commit,
        artifacts=artifacts,
        index_url=(
            locked_package.index_url
            if locked_package is not None and locked_package.index_url
            else item.index_url
        ),
        requires_dist=(
            locked_package.requires_dist
            if locked_package is not None and locked_package.requires_dist
            else item.requires_dist
        ),
        dependency_confusion=dependency_confusion,
        source_type=(
            "vcs"
            if item.vcs is not None
            else "directory"
            if item.editable
            else "direct"
            if item.is_direct
            else (
                locked_package.source_type
                if locked_package is not None
                else "index"
            )
        ),
    )


def _scan_targets_from_lockfile(
    resolution: LockfileResolution,
    *,
    resolver: PipResolver | None = None,
) -> list[ScanTarget]:
    findings: dict[str, tuple[str, ...]] = {}
    if resolver is not None:
        detected = resolver.check_dependency_confusion(
            [package.name for package in resolution.packages],
            additional_indexes=[
                package.index_url
                for package in resolution.packages
                if package.index_url is not None
            ],
        )
        findings = {
            canonicalize_name(finding.project): finding.indexes
            for finding in detected
        }
    targets = [
        ScanTarget(
            requirement=package.requirement,
            project=package.name,
            version=package.version,
            locked_versions=resolution.versions,
            complete_locked_versions=True,
            source_url=next(
                (
                    artifact.url
                    for artifact in package.artifacts
                    if artifact.url is not None
                ),
                None,
            ),
            artifacts=package.artifacts,
            index_url=package.index_url,
            requires_dist=package.requires_dist,
            dependency_confusion=findings.get(
                canonicalize_name(package.name),
                (),
            ),
            source_type=package.source_type,
        )
        for package in resolution.packages
    ]
    targets.extend(
        ScanTarget(
            requirement=warning,
            project=warning.split(":", 1)[0],
            failure_message=warning,
            failure_exit_code=EXIT_DATA_ERROR,
            locked_versions=resolution.versions,
            complete_locked_versions=True,
        )
        for warning in resolution.warnings
    )
    return targets


def _read_requirements_file(file_path: Path) -> list[str]:
    requirements: list[str] = []
    pending = ""
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.rstrip()
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment.strip()}".strip()
        if continued:
            continue

        line = _strip_requirement_hashes(_clean_requirement_line(pending))
        pending = ""
        if line and not line.startswith(("-", "--")):
            requirements.append(line)

    if pending:
        line = _strip_requirement_hashes(_clean_requirement_line(pending))
        if line and not line.startswith(("-", "--")):
            requirements.append(line)
    return requirements


def _strip_requirement_hashes(line: str) -> str:
    if not line:
        return line
    return re.split(r"\s+--hash(?:=|\s+)", line, maxsplit=1)[0].rstrip()


def _locked_versions_from_requirements(
    requirement_lines: list[str],
    *,
    source_path: Path,
) -> dict[str, str]:
    environment = {key: str(value) for key, value in default_environment().items()}
    environment.setdefault("extra", "")
    versions: dict[str, str] = {}
    for line_number, line in enumerate(requirement_lines, 1):
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        version = _exact_scan_target_version(requirement)
        if version is None:
            continue
        key = canonicalize_name(requirement.name)
        existing_version = versions.get(key)
        if existing_version is not None and existing_version != version:
            raise ValueError(
                f"multiple active locked versions for {requirement.name!r} in "
                f"{source_path}: {existing_version} and {version}"
            )
        versions[key] = version
    return versions


def _extract_scan_requirements_from_toml(
    payload: dict[str, object],
    *,
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    base_path: Path | None = None,
) -> list[str]:
    requirements: list[str] = []
    available_extras: dict[str, tuple[str, object]] = {}
    available_groups: dict[str, tuple[str, object, str]] = {}

    project = payload.get("project")
    if isinstance(project, dict):
        requirements.extend(_collect_requirement_strings(project.get("dependencies")))
        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for name, extra_requirements in optional_dependencies.items():
                key = canonicalize_name(str(name))
                if key in available_extras:
                    raise ValueError(f"duplicate optional dependency extra: {name}")
                available_extras[key] = (str(name), extra_requirements)

    standard_groups = payload.get("dependency-groups")
    if isinstance(standard_groups, dict):
        for name, group_payload in standard_groups.items():
            key = canonicalize_name(str(name))
            if key in available_groups:
                raise ValueError(f"duplicate dependency group: {name}")
            available_groups[key] = (str(name), group_payload, "standard")

    selected_extras = (
        [canonicalize_name(name) for name in extras]
        if extras
        else list(available_extras)
    )
    for extra_key in selected_extras:
        extra_entry = available_extras.get(extra_key)
        if extra_entry is None:
            raise ValueError(f"unknown optional dependency extra: {extra_key}")
        requirements.extend(_collect_requirement_strings(extra_entry[1]))

    tool = payload.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            requirements.extend(
                _extract_poetry_dependency_requirements(
                    poetry.get("dependencies"),
                    base_path=base_path,
                )
            )
            poetry_groups = poetry.get("group")
            if isinstance(poetry_groups, dict):
                for name, group_payload in poetry_groups.items():
                    if not isinstance(group_payload, dict):
                        continue
                    key = canonicalize_name(str(name))
                    if key in available_groups:
                        raise ValueError(
                            f"dependency group {name!r} is defined more than once"
                        )
                    available_groups[key] = (
                        str(name),
                        group_payload.get("dependencies"),
                        "poetry",
                    )
        pdm = tool.get("pdm")
        if isinstance(pdm, dict):
            pdm_groups = pdm.get("dev-dependencies")
            if isinstance(pdm_groups, dict):
                for name, group_payload in pdm_groups.items():
                    key = canonicalize_name(str(name))
                    if key in available_groups:
                        raise ValueError(
                            f"dependency group {name!r} is defined more than once"
                        )
                    available_groups[key] = (
                        str(name),
                        group_payload,
                        "pdm",
                    )

    selected_groups = (
        [canonicalize_name(name) for name in groups]
        if groups
        else list(available_groups)
    )
    for group_key in selected_groups:
        group_entry = available_groups.get(group_key)
        if group_entry is None:
            raise ValueError(f"unknown dependency group: {group_key}")
        if group_entry[2] == "poetry":
            requirements.extend(
                _extract_poetry_dependency_requirements(
                    group_entry[1],
                    base_path=base_path,
                )
            )
        elif group_entry[2] == "pdm":
            requirements.extend(
                _collect_requirement_strings(group_entry[1])
            )
        else:
            requirements.extend(
                _resolve_standard_dependency_group(
                    available_groups,
                    group_key,
                )
            )

    deduped: list[str] = []
    seen: set[str] = set()
    for requirement in requirements:
        if requirement not in seen:
            deduped.append(requirement)
            seen.add(requirement)
    return deduped


def _resolve_standard_dependency_group(
    available_groups: dict[str, tuple[str, object, str]],
    group: str,
    past_groups: tuple[str, ...] = (),
) -> list[str]:
    if group in past_groups:
        chain = " -> ".join((*past_groups, group))
        raise ValueError(f"cyclic dependency group include: {chain}")
    entry = available_groups.get(group)
    if entry is None or entry[2] != "standard":
        raise ValueError(f"unknown standard dependency group: {group}")
    raw_group = entry[1]
    if not isinstance(raw_group, list):
        raise ValueError(f"dependency group {entry[0]!r} must be a list")

    requirements: list[str] = []
    for item in raw_group:
        if isinstance(item, str):
            try:
                Requirement(item)
            except InvalidRequirement as exc:
                raise ValueError(
                    f"invalid requirement in dependency group {entry[0]!r}: {exc}"
                ) from exc
            requirements.append(item)
            continue
        if isinstance(item, dict) and tuple(item) == ("include-group",):
            include_name = item["include-group"]
            if not isinstance(include_name, str):
                raise ValueError(
                    f"dependency group include in {entry[0]!r} must name a group"
                )
            requirements.extend(
                _resolve_standard_dependency_group(
                    available_groups,
                    canonicalize_name(include_name),
                    (*past_groups, group),
                )
            )
            continue
        raise ValueError(f"invalid dependency group item in {entry[0]!r}: {item!r}")
    return requirements


def _collect_requirement_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()]


def _extract_poetry_dependency_requirements(
    value: object,
    *,
    base_path: Path | None = None,
) -> list[str]:
    if not isinstance(value, dict):
        return []
    requirements: list[str] = []
    for name, spec in value.items():
        if str(name).lower() == "python":
            continue
        requirement = _poetry_dependency_to_requirement(
            str(name),
            spec,
            base_path=base_path,
        )
        if requirement:
            requirements.append(requirement)
    return requirements


def _poetry_dependency_to_requirement(
    name: str,
    spec: object,
    *,
    base_path: Path | None = None,
) -> str | None:
    if isinstance(spec, str):
        cleaned = spec.strip()
        if not cleaned or cleaned == "*":
            return name
        translated = _translate_poetry_version_specifier(cleaned)
        if translated is not None:
            return f"{name}{translated}"
        return f"{name}{cleaned}"
    if isinstance(spec, dict):
        extras = spec.get("extras")
        requirement_name = name
        if isinstance(extras, list):
            selected_extras = [
                item for item in extras if isinstance(item, str) and item
            ]
            if selected_extras:
                requirement_name = f"{name}[{','.join(selected_extras)}]"
        marker = spec.get("markers")
        marker_suffix = (
            f"; {marker}"
            if isinstance(marker, str) and marker.strip()
            else ""
        )
        git = spec.get("git")
        if isinstance(git, str) and git.strip():
            url = git.strip()
            if not url.startswith("git+"):
                url = f"git+{url}"
            reference = next(
                (
                    str(spec[key]).strip()
                    for key in ("rev", "tag", "branch")
                    if spec.get(key) is not None and str(spec[key]).strip()
                ),
                None,
            )
            if reference:
                url = f"{url}@{reference}"
            return f"{requirement_name} @ {url}{marker_suffix}"
        direct_url = spec.get("url")
        if isinstance(direct_url, str) and direct_url.strip():
            return f"{requirement_name} @ {direct_url.strip()}{marker_suffix}"
        path = spec.get("path")
        if isinstance(path, str) and path.strip():
            resolved_path = Path(path)
            if not resolved_path.is_absolute() and base_path is not None:
                resolved_path = base_path / resolved_path
            return (
                f"{requirement_name} @ "
                f"{resolved_path.resolve().as_uri()}{marker_suffix}"
            )
        version = spec.get("version")
        if version is None or str(version).strip() in {"", "*"}:
            return f"{requirement_name}{marker_suffix}"
        cleaned = str(version).strip()
        translated = _translate_poetry_version_specifier(cleaned)
        if translated is not None:
            return f"{requirement_name}{translated}{marker_suffix}"
        return f"{requirement_name}{cleaned}{marker_suffix}"
    return None


def _translate_poetry_version_specifier(spec: str) -> str | None:
    if spec.startswith("^"):
        return _expand_poetry_caret_specifier(spec[1:])
    if spec.startswith("~"):
        return _expand_poetry_tilde_specifier(spec[1:])
    return None


def _expand_poetry_caret_specifier(version_text: str) -> str:
    release = _parse_version_release_parts(version_text)
    upper = list(release)
    if release[0] != 0:
        upper[0] += 1
        upper = upper[:1]
    elif len(release) > 1 and release[1] != 0:
        upper[1] += 1
        upper = upper[:2]
    elif len(release) > 2:
        upper[2] += 1
        upper = upper[:3]
    else:
        upper[0] = 1
        upper = upper[:1]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _expand_poetry_tilde_specifier(version_text: str) -> str:
    release = _parse_version_release_parts(version_text)
    upper = list(release)
    if len(upper) == 1:
        upper[0] += 1
        upper = upper[:1]
    else:
        upper[1] += 1
        upper = upper[:2]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _parse_version_release_parts(version_text: str) -> tuple[int, ...]:
    try:
        return Version(version_text).release
    except InvalidVersion:
        return (0,)


def _clean_requirement_line(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", maxsplit=1)[0].rstrip()
    return line


def _resolve_scan_target_version_for_scan(
    requirement: Requirement,
    client: PypiClient,
) -> tuple[str | None, str | None, int]:
    try:
        return _resolve_scan_target_version(requirement, client), None, EXIT_OK
    except PypiClientError as exc:
        return None, _format_upstream_error(exc), EXIT_UPSTREAM_FAILURE
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return (
            None,
            f"error: unable to resolve scan requirement {requirement!s}: {exc}",
            EXIT_DATA_ERROR,
        )


def _resolve_scan_target_version(requirement: Requirement, client: PypiClient) -> str | None:
    exact_version = _exact_scan_target_version(requirement)
    if exact_version is not None:
        return exact_version
    if not requirement.specifier:
        return None

    payload = client.get_project(requirement.name)
    info = payload.get("info") or {}
    releases = payload.get("releases") or {}
    versions: list[Version] = []
    version_map: dict[Version, str] = {}

    if isinstance(releases, dict):
        for raw_version in releases:
            try:
                parsed = Version(str(raw_version))
            except InvalidVersion:
                continue
            if not requirement.specifier.contains(parsed, prereleases=None):
                continue
            versions.append(parsed)
            version_map[parsed] = str(raw_version)

    if versions:
        return version_map[max(versions)]

    fallback = info.get("version")
    if isinstance(fallback, str) and fallback:
        try:
            parsed_fallback = Version(fallback)
        except InvalidVersion:
            parsed_fallback = None
        if parsed_fallback is not None and requirement.specifier.contains(
            parsed_fallback,
            prereleases=None,
        ):
            return fallback
    raise ValueError(f"unable to resolve a compatible version for requirement {requirement!s}")


def _exact_scan_target_version(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1:
        return None
    specifier = specifiers[0]
    if specifier.operator == "===":
        return specifier.version
    if specifier.operator == "==" and not specifier.version.endswith(".*"):
        return specifier.version
    return None
