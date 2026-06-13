from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any
from urllib import parse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .indexes import (
    DependencyConfusionFinding,
    IndexConfiguration,
    IndexError,
    SimpleRepositoryClient,
    redact_url_credentials,
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class ResolutionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TargetEnvironment:
    python_version: str | None = None
    platforms: tuple[str, ...] = ()
    implementation: str | None = None
    abis: tuple[str, ...] = ()

    @property
    def is_cross_target(self) -> bool:
        return any(
            (
                self.python_version,
                self.platforms,
                self.implementation,
                self.abis,
            )
        )


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    filename: str | None = None
    url: str | None = None
    path: str | None = None
    hashes: tuple[tuple[str, str], ...] = ()
    size: int | None = None
    kind: str = "archive"

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "url": (
                redact_url_credentials(self.url)
                if self.url is not None
                else None
            ),
            "path": self.path,
            "hashes": {
                algorithm: digest for algorithm, digest in self.hashes
            },
            "size": self.size,
            "kind": self.kind,
        }


@dataclass(frozen=True, slots=True)
class ResolvedDistribution:
    name: str
    version: str
    requested: bool = False
    requested_extras: tuple[str, ...] = ()
    source_url: str | None = None
    is_direct: bool = False
    is_yanked: bool = False
    editable: bool = False
    vcs: str | None = None
    vcs_commit: str | None = None
    requires_dist: tuple[str, ...] = ()
    artifacts: tuple[ArtifactReference, ...] = ()
    index_url: str | None = None


@dataclass(slots=True)
class Resolution:
    distributions: list[ResolvedDistribution] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    pip_version: str | None = None
    indexes: tuple[str, ...] = ()
    dependency_confusion: tuple[DependencyConfusionFinding, ...] = ()

    @property
    def versions(self) -> dict[str, str]:
        return {
            canonicalize_name(item.name): item.version
            for item in self.distributions
        }

    def requested_distributions(self) -> list[ResolvedDistribution]:
        return [item for item in self.distributions if item.requested]


@dataclass(slots=True)
class PipResolver:
    python_executable: str = sys.executable
    runner: CommandRunner = subprocess.run
    indexes: IndexConfiguration = field(default_factory=IndexConfiguration)
    index_client: SimpleRepositoryClient | None = None
    allow_dependency_confusion: bool = False

    def check_dependency_confusion(
        self,
        projects: Sequence[str],
        *,
        additional_indexes: Sequence[str] = (),
    ) -> tuple[DependencyConfusionFinding, ...]:
        raw_indexes = (*self.indexes.all_urls, *additional_indexes)
        index_urls: list[str] = []
        seen: set[str] = set()
        for index_url in raw_indexes:
            redacted = redact_url_credentials(index_url)
            if redacted not in seen:
                index_urls.append(index_url)
                seen.add(redacted)
        if len(index_urls) < 2:
            return ()
        index_client = self.index_client or SimpleRepositoryClient(
            keyring_provider=self.indexes.keyring_provider,
            python_executable=self.python_executable,
        )
        try:
            findings = index_client.find_dependency_confusion(
                projects,
                index_urls,
            )
        except IndexError as exc:
            raise ResolutionError(f"package index inspection failed: {exc}") from exc
        if findings and not self.allow_dependency_confusion:
            details = "; ".join(
                f"{finding.project} is present on {', '.join(finding.indexes)}"
                for finding in findings
            )
            raise ResolutionError(
                "dependency-confusion risk detected across configured indexes: "
                f"{details}; pass --allow-dependency-confusion only after verifying "
                "the intended source"
            )
        return findings

    def resolve_requirements_file(
        self,
        path: str | Path,
        *,
        constraints: Sequence[str | Path] = (),
        target: TargetEnvironment | None = None,
        offline: bool = False,
    ) -> Resolution:
        requirement_path = Path(path).resolve()
        if not requirement_path.is_file():
            raise ResolutionError(f"requirements file not found: {requirement_path}")
        arguments = ["--requirement", str(requirement_path)]
        for constraint in constraints:
            constraint_path = Path(constraint).resolve()
            if not constraint_path.is_file():
                raise ResolutionError(f"constraints file not found: {constraint_path}")
            arguments.extend(["--constraint", str(constraint_path)])
        return self._resolve(
            arguments,
            target=target,
            cwd=requirement_path.parent,
            offline=offline,
        )

    def resolve_requirements(
        self,
        requirements: Sequence[str],
        *,
        constraints: Sequence[str | Path] = (),
        dependency_groups: Sequence[tuple[str | Path, str]] = (),
        target: TargetEnvironment | None = None,
        cwd: str | Path | None = None,
        offline: bool = False,
    ) -> Resolution:
        arguments = list(requirements)
        for constraint in constraints:
            constraint_path = Path(constraint).resolve()
            if not constraint_path.is_file():
                raise ResolutionError(f"constraints file not found: {constraint_path}")
            arguments.extend(["--constraint", str(constraint_path)])
        for project_file, group in dependency_groups:
            path = Path(project_file).resolve()
            if path.name != "pyproject.toml" or not path.is_file():
                raise ResolutionError(
                    f"dependency group source must be an existing pyproject.toml: {path}"
                )
            arguments.extend(["--group", f"{path}:{group}"])
        if not arguments:
            raise ResolutionError("no requirements or dependency groups were provided")
        return self._resolve(
            arguments,
            target=target,
            cwd=cwd,
            offline=offline,
        )

    def _resolve(
        self,
        install_arguments: Sequence[str],
        *,
        target: TargetEnvironment | None,
        cwd: str | Path | None,
        offline: bool,
    ) -> Resolution:
        target = target or TargetEnvironment()
        command = [
            self.python_executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--quiet",
            "--report",
            "-",
            "--disable-pip-version-check",
            "--no-input",
        ]
        if target.python_version:
            command.extend(["--python-version", target.python_version])
        for platform in target.platforms:
            command.extend(["--platform", platform])
        if target.implementation:
            command.extend(["--implementation", target.implementation])
        for abi in target.abis:
            command.extend(["--abi", abi])
        if target.is_cross_target:
            command.extend(["--only-binary", ":all:"])
        if offline:
            command.append("--no-index")
        else:
            command.extend(self.indexes.pip_arguments())
        command.extend(install_arguments)

        try:
            completed = self.runner(
                command,
                cwd=str(cwd) if cwd is not None else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            raise ResolutionError(f"unable to start pip dependency resolver: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            if not detail:
                detail = f"pip exited with status {completed.returncode}"
            raise ResolutionError(
                "pip dependency resolution failed: "
                f"{redact_url_credentials(detail)}"
            )

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ResolutionError("pip returned an invalid installation report") from exc
        resolution = parse_installation_report(payload)
        if offline:
            return resolution
        return self.annotate_indexes(resolution)

    def annotate_indexes(self, resolution: Resolution) -> Resolution:
        index_urls = self.indexes.all_urls
        resolution.indexes = tuple(
            redact_url_credentials(index_url) for index_url in index_urls
        )
        if not resolution.distributions:
            return resolution

        index_client = self.index_client or SimpleRepositoryClient(
            keyring_provider=self.indexes.keyring_provider,
            python_executable=self.python_executable,
        )
        candidates = [
            item
            for item in resolution.distributions
            if not item.is_direct and not item.editable and item.vcs is None
        ]
        try:
            findings = self.check_dependency_confusion(
                [item.name for item in candidates],
            )
            annotated: list[ResolvedDistribution] = []
            for item in resolution.distributions:
                index_url = (
                    index_client.locate_artifact_index(
                        item.name,
                        item.source_url,
                        index_urls,
                    )
                    if item in candidates
                    else None
                )
                annotated.append(
                    ResolvedDistribution(
                        name=item.name,
                        version=item.version,
                        requested=item.requested,
                        requested_extras=item.requested_extras,
                        source_url=item.source_url,
                        is_direct=item.is_direct,
                        is_yanked=item.is_yanked,
                        editable=item.editable,
                        vcs=item.vcs,
                        vcs_commit=item.vcs_commit,
                        requires_dist=item.requires_dist,
                        artifacts=item.artifacts,
                        index_url=index_url,
                    )
                )
        except IndexError as exc:
            raise ResolutionError(f"package index inspection failed: {exc}") from exc

        resolution.distributions = annotated
        resolution.dependency_confusion = findings
        return resolution


def parse_installation_report(payload: object) -> Resolution:
    if not isinstance(payload, dict):
        raise ResolutionError("pip installation report must be a JSON object")
    if payload.get("version") != "1":
        raise ResolutionError(
            f"unsupported pip installation report version: {payload.get('version')!r}"
        )
    install = payload.get("install")
    if not isinstance(install, list):
        raise ResolutionError("pip installation report is missing the install array")

    resolved: list[ResolvedDistribution] = []
    seen: dict[str, str] = {}
    for index, raw_item in enumerate(install, 1):
        if not isinstance(raw_item, dict):
            raise ResolutionError(f"pip installation report item {index} is not an object")
        metadata = raw_item.get("metadata")
        if not isinstance(metadata, dict):
            raise ResolutionError(
                f"pip installation report item {index} is missing metadata"
            )
        name = metadata.get("name")
        version = metadata.get("version")
        if not isinstance(name, str) or not name.strip():
            raise ResolutionError(
                f"pip installation report item {index} has no package name"
            )
        if not isinstance(version, str) or not version.strip():
            raise ResolutionError(
                f"pip installation report item {index} has no package version"
            )
        try:
            Version(version)
        except InvalidVersion as exc:
            raise ResolutionError(
                f"pip resolved invalid version {version!r} for {name!r}"
            ) from exc

        key = canonicalize_name(name)
        existing = seen.get(key)
        if existing is not None and existing != version:
            raise ResolutionError(
                f"pip resolved multiple versions for {name!r}: {existing} and {version}"
            )
        if existing is not None:
            continue
        seen[key] = version

        download_info = raw_item.get("download_info")
        source_url: str | None = None
        artifacts: tuple[ArtifactReference, ...] = ()
        editable = False
        vcs: str | None = None
        vcs_commit: str | None = None
        if isinstance(download_info, dict):
            raw_url = download_info.get("url")
            if isinstance(raw_url, str) and raw_url:
                source_url = _redact_url_credentials(raw_url)
            archive_info = download_info.get("archive_info")
            if isinstance(archive_info, dict):
                artifact_hashes = _archive_hashes(archive_info)
                artifacts = (
                    ArtifactReference(
                        filename=_filename_from_url(source_url),
                        url=source_url,
                        hashes=artifact_hashes,
                        kind="archive",
                    ),
                )
            directory_info = download_info.get("dir_info")
            if isinstance(directory_info, dict):
                editable = directory_info.get("editable") is True
            vcs_info = download_info.get("vcs_info")
            if isinstance(vcs_info, dict):
                raw_vcs = vcs_info.get("vcs")
                raw_commit = vcs_info.get("commit_id")
                vcs = raw_vcs if isinstance(raw_vcs, str) and raw_vcs else None
                vcs_commit = (
                    raw_commit
                    if isinstance(raw_commit, str) and raw_commit
                    else None
                )
            if (
                not artifacts
                and source_url
                and raw_item.get("is_direct") is True
            ):
                artifacts = (
                    ArtifactReference(
                        filename=_filename_from_url(source_url),
                        url=source_url,
                        kind=(
                            "vcs"
                            if vcs is not None
                            else "directory"
                            if editable
                            else "direct"
                        ),
                    ),
                )

        resolved.append(
            ResolvedDistribution(
                name=name,
                version=version,
                requested=raw_item.get("requested") is True,
                requested_extras=_string_tuple(raw_item.get("requested_extras")),
                source_url=source_url,
                is_direct=raw_item.get("is_direct") is True,
                is_yanked=raw_item.get("is_yanked") is True,
                editable=editable,
                vcs=vcs,
                vcs_commit=vcs_commit,
                requires_dist=_string_tuple(metadata.get("requires_dist")),
                artifacts=artifacts,
            )
        )

    environment = payload.get("environment")
    return Resolution(
        distributions=resolved,
        environment=(
            {
                str(key): str(value)
                for key, value in environment.items()
            }
            if isinstance(environment, dict)
            else {}
        ),
        pip_version=(
            str(payload["pip_version"])
            if payload.get("pip_version") is not None
            else None
        ),
    )


def discover_installed_distributions(
    paths: Sequence[str | Path] = (),
) -> Resolution:
    resolved_paths: list[str] = []
    for raw_path in paths:
        path = Path(raw_path).resolve()
        if not path.is_dir():
            raise ResolutionError(f"site-packages path not found: {path}")
        resolved_paths.append(str(path))
    discovered = (
        distributions(path=resolved_paths)
        if resolved_paths
        else distributions()
    )
    resolved: list[ResolvedDistribution] = []
    seen: dict[str, str] = {}
    for distribution in discovered:
        item = _installed_distribution(distribution)
        key = canonicalize_name(item.name)
        existing = seen.get(key)
        if existing is not None and existing != item.version:
            raise ResolutionError(
                f"multiple installed versions found for {item.name!r}: "
                f"{existing} and {item.version}"
            )
        if existing is not None:
            continue
        seen[key] = item.version
        resolved.append(item)
    resolved.sort(key=lambda item: canonicalize_name(item.name))
    return Resolution(distributions=resolved)


def _installed_distribution(distribution: Distribution) -> ResolvedDistribution:
    name = distribution.metadata["Name"]
    version = distribution.version
    if not isinstance(name, str) or not name.strip():
        raise ResolutionError("installed distribution metadata is missing Name")
    try:
        Version(version)
    except InvalidVersion as exc:
        raise ResolutionError(
            f"installed distribution {name!r} has invalid version {version!r}"
        ) from exc

    direct_url = _read_direct_url(distribution)
    source_url: str | None = None
    artifacts: tuple[ArtifactReference, ...] = ()
    editable = False
    vcs: str | None = None
    vcs_commit: str | None = None
    if direct_url is not None:
        raw_url = direct_url.get("url")
        if isinstance(raw_url, str) and raw_url:
            source_url = _redact_url_credentials(raw_url)
        archive_info = direct_url.get("archive_info")
        if isinstance(archive_info, dict):
            artifacts = (
                ArtifactReference(
                    filename=_filename_from_url(source_url),
                    url=source_url,
                    hashes=_archive_hashes(archive_info),
                    kind="archive",
                ),
            )
        directory_info = direct_url.get("dir_info")
        if isinstance(directory_info, dict):
            editable = directory_info.get("editable") is True
        vcs_info = direct_url.get("vcs_info")
        if isinstance(vcs_info, dict):
            raw_vcs = vcs_info.get("vcs")
            raw_commit = vcs_info.get("commit_id")
            vcs = raw_vcs if isinstance(raw_vcs, str) and raw_vcs else None
            vcs_commit = (
                raw_commit if isinstance(raw_commit, str) and raw_commit else None
            )
        if not artifacts and source_url:
            artifacts = (
                ArtifactReference(
                    filename=_filename_from_url(source_url),
                    url=source_url,
                    kind=(
                        "vcs"
                        if vcs is not None
                        else "directory"
                        if editable
                        else "direct"
                    ),
                ),
            )

    return ResolvedDistribution(
        name=name,
        version=version,
        requested=True,
        source_url=source_url,
        is_direct=direct_url is not None,
        editable=editable,
        vcs=vcs,
        vcs_commit=vcs_commit,
        requires_dist=tuple(distribution.requires or ()),
        artifacts=artifacts,
    )


def _read_direct_url(distribution: Distribution) -> dict[str, Any] | None:
    try:
        raw = distribution.read_text("direct_url.json")
    except (FileNotFoundError, IsADirectoryError, PermissionError, UnicodeError):
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def validate_resolved_requirement(
    requirement_text: str,
    versions: Mapping[str, str],
) -> None:
    try:
        requirement = Requirement(requirement_text)
    except InvalidRequirement as exc:
        raise ResolutionError(f"invalid resolved requirement: {requirement_text}") from exc
    version = versions.get(canonicalize_name(requirement.name))
    if version is None:
        raise ResolutionError(
            f"resolver did not produce a version for {requirement.name!r}"
        )
    if requirement.specifier and not requirement.specifier.contains(
        version,
        prereleases=True,
    ):
        raise ResolutionError(
            f"resolved version {version!r} for {requirement.name!r} "
            f"does not satisfy {requirement.specifier}"
        )


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item)


def _redact_url_credentials(url: str) -> str:
    return redact_url_credentials(url)


def _archive_hashes(archive_info: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    hashes: dict[str, str] = {}
    raw_hashes = archive_info.get("hashes")
    if isinstance(raw_hashes, dict):
        for algorithm, digest in raw_hashes.items():
            if isinstance(algorithm, str) and isinstance(digest, str):
                hashes[algorithm.lower()] = digest.lower()
    raw_hash = archive_info.get("hash")
    if isinstance(raw_hash, str):
        separator = "=" if "=" in raw_hash else ":"
        if separator in raw_hash:
            algorithm, digest = raw_hash.split(separator, 1)
            hashes.setdefault(algorithm.lower(), digest.lower())
    return tuple(sorted(hashes.items()))


def _filename_from_url(url: str | None) -> str | None:
    if not url:
        return None
    filename = Path(parse.unquote(parse.urlsplit(url).path)).name
    return filename or None
