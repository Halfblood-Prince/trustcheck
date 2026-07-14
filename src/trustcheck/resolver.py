from __future__ import annotations

import json
import os
import platform as platform_module
import re
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any, Protocol
from urllib import parse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ._resolver_guard import write_sitecustomize
from .indexes import (
    DependencyConfusionFinding,
    IndexConfiguration,
    IndexError,
    SimpleRepositoryClient,
    redact_url_credentials,
)

# Pip is invoked with a fixed argv list and the shell explicitly disabled.
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ExecutableFinder = Callable[[str], str | None]
WarningHandler = Callable[[str], None]
SANDBOX_MODES = ("off", "warn", "auto", "container", "bubblewrap", "strict")
VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
SOURCE_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
DEFAULT_SANDBOX_IMAGE = (
    "python:3.13-slim@"
    "sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f"
)
MINIMUM_SUPPORTED_PIP = Version("22.2")
PIP_VERSION_PATTERN = re.compile(r"\bpip\s+([0-9][^\s]*)")
DIGEST_PINNED_IMAGE_PATTERN = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")
# This path is mounted as a fresh private tmpfs in each enforced sandbox.
SANDBOX_TEMP_DIRECTORY = "/tmp"  # nosec B108
STRICT_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "CURL_CA_BUNDLE",
        "COMSPEC",
        "HOME",
        "LANG",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)


class RepositoryIndexClient(Protocol):
    def find_dependency_confusion(
        self,
        projects: Sequence[str],
        indexes: Sequence[str],
    ) -> tuple[DependencyConfusionFinding, ...]: ...

    def locate_artifact_index(
        self,
        project: str,
        artifact_url: str | None,
        indexes: Sequence[str],
    ) -> str | None: ...


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
    sandbox_mode: str = "off"
    sandbox_warnings: tuple[str, ...] = ()

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
    index_client: RepositoryIndexClient | None = None
    allow_dependency_confusion: bool = False
    sandbox_mode: str = "auto"
    container_runtime: str | None = None
    container_image: str | None = None
    executable_finder: ExecutableFinder = shutil.which
    warning_handler: WarningHandler | None = None

    def __post_init__(self) -> None:
        if self.sandbox_mode not in SANDBOX_MODES:
            raise ValueError(
                "sandbox_mode must be off, warn, auto, container, bubblewrap, or strict"
            )

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
        inspected_files = [requirement_path]
        for constraint in constraints:
            constraint_path = Path(constraint).resolve()
            if not constraint_path.is_file():
                raise ResolutionError(f"constraints file not found: {constraint_path}")
            arguments.extend(["--constraint", str(constraint_path)])
            inspected_files.append(constraint_path)
        return self._resolve(
            arguments,
            target=target,
            cwd=requirement_path.parent,
            offline=offline,
            risk_reasons=_requirement_file_risks(inspected_files),
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
        risk_reasons = [
            reason
            for requirement in requirements
            for reason in _requirement_risks(requirement)
        ]
        for constraint in constraints:
            constraint_path = Path(constraint).resolve()
            if not constraint_path.is_file():
                raise ResolutionError(f"constraints file not found: {constraint_path}")
            arguments.extend(["--constraint", str(constraint_path)])
            risk_reasons.extend(_requirement_file_risks([constraint_path]))
        for project_file, group in dependency_groups:
            path = Path(project_file).resolve()
            if path.name != "pyproject.toml" or not path.is_file():
                raise ResolutionError(
                    f"dependency group source must be an existing pyproject.toml: {path}"
                )
            arguments.extend(["--group", f"{path}:{group}"])
            risk_reasons.extend(_dependency_group_risks(path, group))
        if not arguments:
            raise ResolutionError("no requirements or dependency groups were provided")
        return self._resolve(
            arguments,
            target=target,
            cwd=cwd,
            offline=offline,
            risk_reasons=risk_reasons,
        )

    def _resolve(
        self,
        install_arguments: Sequence[str],
        *,
        target: TargetEnvironment | None,
        cwd: str | Path | None,
        offline: bool,
        risk_reasons: Sequence[str],
    ) -> Resolution:
        target = target or TargetEnvironment()
        if (
            self.container_image is not None
            and DIGEST_PINNED_IMAGE_PATTERN.fullmatch(self.container_image) is None
        ):
            raise ResolutionError(
                "container resolver sandbox image must be pinned by a full "
                "sha256 digest"
            )
        selected_mode = self._selected_sandbox_mode()
        warnings = self._sandbox_warnings(selected_mode, risk_reasons)
        if selected_mode == "strict" and risk_reasons:
            raise ResolutionError(
                "strict resolver sandbox rejected unsafe requirement input: "
                + "; ".join(dict.fromkeys(risk_reasons))
            )
        run_cwd = Path(cwd).resolve() if cwd is not None else Path.cwd().resolve()
        stage_directory: tempfile.TemporaryDirectory[str] | None = None
        guard_directory: tempfile.TemporaryDirectory[str] | None = None
        subprocess_env: dict[str, str] | None = None
        try:
            sandbox_workspace = run_cwd
            staged_arguments = list(install_arguments)
            if selected_mode in {"container", "bubblewrap"}:
                stage_directory = tempfile.TemporaryDirectory(
                    prefix="trustcheck-resolver-"
                )
                sandbox_workspace = Path(stage_directory.name).resolve()
                staged_arguments = _stage_sandbox_inputs(
                    install_arguments,
                    workspace=run_cwd,
                    destination=sandbox_workspace,
                )

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
            elif selected_mode == "strict":
                command.extend(["--isolated", "--only-binary", ":all:"])
            if offline:
                command.append("--no-index")
            else:
                command.extend(self.indexes.pip_arguments())
            command.extend(staged_arguments)
            if selected_mode == "strict":
                guard_directory = tempfile.TemporaryDirectory(
                    prefix="trustcheck-resolver-guard-"
                )
                guard_path = Path(guard_directory.name).resolve()
                write_sitecustomize(guard_path)
                subprocess_env = _strict_resolver_environment(guard_path)
            command, subprocess_cwd = self._sandbox_command(
                command,
                mode=selected_mode,
                workspace=sandbox_workspace,
            )
            if cwd is None and selected_mode in {"off", "warn", "strict"}:
                subprocess_cwd = None

            completed = self.runner(
                command,
                cwd=subprocess_cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                shell=False,
                env=subprocess_env,
            )
        except OSError as exc:
            raise ResolutionError(f"unable to start pip dependency resolver: {exc}") from exc
        finally:
            if guard_directory is not None:
                guard_directory.cleanup()
            if stage_directory is not None:
                stage_directory.cleanup()
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
        resolution.sandbox_mode = selected_mode
        resolution.sandbox_warnings = warnings
        if offline:
            return resolution
        return self.annotate_indexes(resolution)

    def _selected_sandbox_mode(self) -> str:
        if self.sandbox_mode != "auto":
            return self.sandbox_mode
        if platform_module.system() == "Linux" and self.executable_finder("bwrap"):
            return "bubblewrap"
        if self._container_executable(required=False) is not None:
            return "container"
        return "strict"

    def _sandbox_warnings(
        self,
        selected_mode: str,
        risk_reasons: Sequence[str],
    ) -> tuple[str, ...]:
        messages: list[str] = []
        if selected_mode == "warn":
            detail = (
                " Detected: " + "; ".join(dict.fromkeys(risk_reasons)) + "."
                if risk_reasons
                else ""
            )
            messages.append(
                "resolver sandbox is 'warn'; pip dependency resolution may execute "
                f"build-backend metadata hooks.{detail} Use --sandbox auto, container, "
                "bubblewrap, or strict for enforcement."
            )
        elif self.sandbox_mode == "auto" and selected_mode == "strict":
            messages.append(
                "no supported container or bubblewrap runtime was found; "
                "--sandbox auto fell back to strict wheel-only resolution"
            )
        if self.warning_handler is not None:
            for message in messages:
                self.warning_handler(message)
        return tuple(messages)

    def _sandbox_command(
        self,
        command: Sequence[str],
        *,
        mode: str,
        workspace: Path,
    ) -> tuple[list[str], str | None]:
        if mode in {"off", "warn", "strict"}:
            return list(command), str(workspace)
        if mode == "container":
            return self._container_command(command, workspace), None
        if mode == "bubblewrap":
            return self._bubblewrap_command(command, workspace), None
        raise ResolutionError(f"unsupported resolver sandbox mode: {mode}")

    def _container_executable(self, *, required: bool) -> str | None:
        candidates = (
            (self.container_runtime,)
            if self.container_runtime
            else ("docker", "podman")
        )
        for candidate in candidates:
            if candidate is None:
                continue
            located = self.executable_finder(candidate)
            if located:
                return located
        if required:
            requested = self.container_runtime or "Docker or Podman"
            raise ResolutionError(f"container resolver sandbox requires {requested}")
        return None

    def _container_command(
        self,
        command: Sequence[str],
        workspace: Path,
    ) -> list[str]:
        runtime = self._container_executable(required=True)
        if runtime is None:
            raise ResolutionError("container resolver sandbox runtime is unavailable")
        image = self.container_image or DEFAULT_SANDBOX_IMAGE
        if DIGEST_PINNED_IMAGE_PATTERN.fullmatch(image) is None:
            raise ResolutionError(
                "container resolver sandbox image must be pinned by a full "
                "sha256 digest"
            )
        pip_command = [
            "python",
            *(
                _containerize_argument(argument, workspace)
                for argument in command[1:]
            ),
        ]
        return [
            runtime,
            "run",
            "--rm",
            "--pull=missing",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--network=bridge",
            "--user=65534:65534",
            "--tmpfs",
            f"{SANDBOX_TEMP_DIRECTORY}:rw,nosuid,nodev,size=512m",
            "--env",
            f"HOME={SANDBOX_TEMP_DIRECTORY}",
            "--env",
            f"PIP_CACHE_DIR={SANDBOX_TEMP_DIRECTORY}/pip-cache",
            "--mount",
            f"type=bind,source={workspace},target=/workspace,readonly",
            "--workdir",
            "/workspace",
            image,
            *pip_command,
        ]

    def _bubblewrap_command(
        self,
        command: Sequence[str],
        workspace: Path,
    ) -> list[str]:
        if platform_module.system() != "Linux":
            raise ResolutionError("bubblewrap resolver sandbox is only supported on Linux")
        executable = self.executable_finder("bwrap")
        if executable is None:
            raise ResolutionError("bubblewrap resolver sandbox requires bwrap")
        binds = _bubblewrap_readonly_binds(workspace, Path(self.python_executable))
        wrapped = [
            executable,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--share-net",
            "--clearenv",
            "--setenv",
            "PATH",
            os.defpath,
            "--setenv",
            "HOME",
            f"{SANDBOX_TEMP_DIRECTORY}/home",
            "--setenv",
            "PIP_CACHE_DIR",
            f"{SANDBOX_TEMP_DIRECTORY}/pip-cache",
            "--tmpfs",
            SANDBOX_TEMP_DIRECTORY,
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        for source in binds:
            wrapped.extend(["--ro-bind", str(source), str(source)])
        wrapped.extend(
            [
                "--ro-bind",
                str(workspace),
                "/workspace",
                "--chdir",
                "/workspace",
                command[0],
                *(
                    _containerize_argument(argument, workspace)
                    for argument in command[1:]
                ),
            ]
        )
        return wrapped

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


def _stage_sandbox_inputs(
    arguments: Sequence[str],
    *,
    workspace: Path,
    destination: Path,
) -> list[str]:
    lexical_workspace = workspace.absolute()
    lexical_destination = destination.absolute()
    workspace = workspace.resolve()
    workspace_aliases = tuple(dict.fromkeys((lexical_workspace, workspace)))
    destination = destination.resolve()
    visited_requirement_files: set[Path] = set()
    visited_groups: set[tuple[Path, str]] = set()

    def translate(value: str, target: str | Path) -> str:
        for alias in workspace_aliases:
            value = _translate_workspace_reference(value, alias, target)
        return value

    def staged_path(source: Path) -> Path:
        resolved = source.resolve()
        if not resolved.is_relative_to(workspace):
            raise ResolutionError(
                "resolver sandbox cannot stage an input outside the resolver workspace: "
                f"{resolved}"
            )
        return destination / resolved.relative_to(workspace)

    def copy_local_path(source: Path) -> Path:
        resolved = source.resolve()
        target = staged_path(resolved)
        if not resolved.exists():
            raise ResolutionError(f"resolver sandbox input not found: {resolved}")
        if resolved.is_dir():
            shutil.copytree(
                resolved,
                target,
                dirs_exist_ok=True,
                symlinks=True,
            )
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(resolved, target)
        return target

    def stage_requirement_file(source: Path) -> Path:
        resolved = source.resolve()
        target = staged_path(resolved)
        if resolved in visited_requirement_files:
            return target
        visited_requirement_files.add(resolved)
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ResolutionError(
                f"unable to stage requirement file {resolved}: {exc}"
            ) from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            translate(text, "/workspace"),
            encoding="utf-8",
        )
        for line in _logical_requirement_lines(text):
            nested = _nested_requirement_path(line)
            if nested is not None:
                stage_requirement_file(_resolve_local_path(nested, resolved.parent))
                continue
            local = _local_requirement_path(line, resolved.parent)
            if local is not None:
                copy_local_path(local)
        return target

    def stage_dependency_group(source: Path, group: str) -> Path:
        resolved = source.resolve()
        key = (resolved, group)
        target = staged_path(resolved)
        if key in visited_groups:
            return target
        visited_groups.add(key)
        try:
            text = resolved.read_text(encoding="utf-8")
            payload = tomllib.loads(text)
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ResolutionError(
                f"unable to stage dependency group source {resolved}: {exc}"
            ) from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            translate(text, "/workspace"),
            encoding="utf-8",
        )
        groups = payload.get("dependency-groups")
        selected = groups.get(group) if isinstance(groups, dict) else None
        if isinstance(selected, list):
            for item in selected:
                if isinstance(item, str):
                    local = _local_requirement_path(item, resolved.parent)
                    if local is not None:
                        copy_local_path(local)
                elif isinstance(item, dict):
                    included = item.get("include-group")
                    if isinstance(included, str):
                        stage_dependency_group(resolved, included)
        return target

    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-r", "--requirement", "-c", "--constraint"}:
            if index + 1 < len(arguments):
                stage_requirement_file(
                    _resolve_local_path(arguments[index + 1], workspace)
                )
                index += 2
                continue
        nested = _nested_requirement_path(argument)
        if nested is not None:
            stage_requirement_file(_resolve_local_path(nested, workspace))
            index += 1
            continue
        if argument == "--group" and index + 1 < len(arguments):
            group_path, separator, group = arguments[index + 1].rpartition(":")
            if separator:
                stage_dependency_group(
                    _resolve_local_path(group_path, workspace),
                    group,
                )
            index += 2
            continue
        if argument.startswith("--group="):
            group_path, separator, group = argument[8:].rpartition(":")
            if separator:
                stage_dependency_group(
                    _resolve_local_path(group_path, workspace),
                    group,
                )
            index += 1
            continue
        local = _local_requirement_path(argument, workspace)
        if local is not None:
            copy_local_path(local)
        index += 1

    return [
        translate(argument, lexical_destination)
        for argument in arguments
    ]


def _resolve_local_path(value: str, base: Path) -> Path:
    cleaned = value.strip().strip("\"'")
    parsed = parse.urlsplit(cleaned)
    if parsed.scheme == "file":
        path_text = parse.unquote(parsed.path)
        if re.match(r"^/[a-zA-Z]:/", path_text):
            path_text = path_text[1:]
        candidate = Path(path_text)
    else:
        candidate = Path(cleaned.split("#", maxsplit=1)[0])
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _local_requirement_path(raw_requirement: str, base: Path) -> Path | None:
    raw = raw_requirement.strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        tokens = shlex.split(raw, comments=True, posix=os.name != "nt")
    except ValueError:
        return None
    if not tokens:
        return None
    first = tokens[0]
    candidate: str | None = None
    if first in {"-e", "--editable", "-f", "--find-links"}:
        if len(tokens) < 2:
            return None
        candidate = tokens[1]
    else:
        for prefix in ("-e", "--editable=", "-f", "--find-links="):
            if first.startswith(prefix) and len(first) > len(prefix):
                candidate = first[len(prefix):]
                break
    if candidate is None and first.startswith("-"):
        return None
    if candidate is None:
        requirement_text = re.split(
            r"\s+--hash(?:=|\s)", raw, maxsplit=1
        )[0].strip()
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            candidate = requirement_text
        else:
            if requirement.url is None:
                return None
            if parse.urlsplit(requirement.url).scheme != "file":
                return None
            candidate = requirement.url
    if candidate is None or any(
        candidate.lower().startswith(prefix) for prefix in VCS_PREFIXES
    ):
        return None
    parsed = parse.urlsplit(candidate)
    windows_path = re.match(r"^[a-zA-Z]:[\\/]", candidate) is not None
    if parsed.scheme and parsed.scheme != "file" and not windows_path:
        return None
    path = _resolve_local_path(candidate, base)
    if not path.exists() and "[" in candidate and candidate.endswith("]"):
        path = _resolve_local_path(candidate.rsplit("[", maxsplit=1)[0], base)
    return path


def _translate_workspace_reference(
    value: str,
    workspace: Path,
    target: str | Path,
) -> str:
    if isinstance(target, Path):
        target_path = str(target)
        target_uri = target.as_uri()
        target_separator = os.sep
    else:
        target_path = target
        target_uri = f"file://{target}" if target.startswith("/") else target
        target_separator = "/"
    translated = value.replace(workspace.as_uri(), target_uri)
    for source in dict.fromkeys((str(workspace), workspace.as_posix())):
        translated = translated.replace(
            f"{source}\\", f"{target_path}{target_separator}"
        )
        translated = translated.replace(
            f"{source}/", f"{target_path}{target_separator}"
        )
        translated = translated.replace(source, target_path)
    return translated


def _containerize_argument(argument: str, workspace: Path) -> str:
    try:
        workspace_uri = workspace.as_uri()
    except ValueError:
        workspace_uri = ""
    translated = argument
    if workspace_uri:
        translated = translated.replace(workspace_uri, "file:///workspace")
    translated = translated.replace(str(workspace), "/workspace")
    translated = translated.replace(workspace.as_posix(), "/workspace")
    if "/workspace" in translated:
        translated = translated.replace("\\", "/")
    lowered = translated.lower()
    if "file://" in lowered and "file:///workspace" not in lowered:
        raise ResolutionError(
            "container resolver sandbox cannot mount a local dependency outside "
            "the resolver workspace"
        )
    windows_absolute = re.search(
        r"(?:^|[\s@=])[a-zA-Z]:[\\/]",
        translated,
    )
    posix_absolute = re.search(r"(?:^|[\s@=])/(?!workspace(?:/|$))", translated)
    if (
        windows_absolute is not None
        or posix_absolute is not None
        or (
            Path(translated).is_absolute()
            and not translated.startswith("/workspace")
        )
    ):
        raise ResolutionError(
            "container resolver sandbox cannot access a path outside the resolver workspace"
        )
    return translated


def _bubblewrap_readonly_binds(workspace: Path, python_executable: Path) -> tuple[Path, ...]:
    del workspace
    candidates = [
        Path("/usr"),
        Path("/bin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc"),
        Path(sys.base_prefix),
        Path(sys.prefix),
        python_executable.parent,
    ]
    selected: list[Path] = []
    for candidate in sorted(
        {path.resolve() for path in candidates if path.exists()},
        key=lambda path: len(path.parts),
    ):
        if any(candidate == parent or candidate.is_relative_to(parent) for parent in selected):
            continue
        selected.append(candidate)
    return tuple(selected)


def _requirement_file_risks(paths: Sequence[Path]) -> list[str]:
    risks: list[str] = []
    visited: set[Path] = set()

    def visit(path: Path) -> None:
        resolved = path.resolve()
        if resolved in visited:
            return
        visited.add(resolved)
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ResolutionError(f"unable to inspect requirement file {resolved}: {exc}") from exc
        for line in _logical_requirement_lines(text):
            nested = _nested_requirement_path(line)
            if nested is not None:
                nested_path = (resolved.parent / nested).resolve()
                if not nested_path.is_file():
                    risks.append("nested requirement file could not be inspected")
                    continue
                visit(nested_path)
                continue
            risks.extend(_requirement_risks(line))

    for path in paths:
        visit(path)
    return risks


def _logical_requirement_lines(text: str) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if not continued:
            logical.append(pending)
            pending = ""
    if pending:
        logical.append(pending)
    return logical


def _nested_requirement_path(line: str) -> str | None:
    try:
        tokens = shlex.split(line, comments=True, posix=os.name != "nt")
    except ValueError:
        return None
    if not tokens:
        return None
    first = tokens[0]
    if first in {"-r", "--requirement", "-c", "--constraint"}:
        return tokens[1] if len(tokens) > 1 else None
    for prefix in ("-r", "-c", "--requirement=", "--constraint="):
        if first.startswith(prefix) and len(first) > len(prefix):
            return first[len(prefix):]
    return None


def _requirement_risks(raw_requirement: str) -> list[str]:
    raw = raw_requirement.strip()
    lowered = raw.lower()
    if not raw or raw.startswith("#") or raw.startswith(("--hash", "--index", "--extra")):
        return []
    if lowered.startswith("--no-binary") or re.match(
        r"--only-binary(?:=|\s+):none:(?:\s|$)",
        lowered,
    ):
        return ["pip option overrides strict wheel-only resolution"]
    if lowered == "-e" or lowered.startswith(
        ("-e ", "-e=", "-e.", "-e/", "-e\\", "--editable")
    ):
        return ["editable requirement"]
    if "${" in raw:
        return ["environment-expanded requirement"]
    if any(prefix in lowered for prefix in VCS_PREFIXES):
        return ["VCS requirement"]
    requirement_text = re.split(r"\s+--hash(?:=|\s)", raw, maxsplit=1)[0].strip()
    try:
        requirement = Requirement(requirement_text)
    except InvalidRequirement:
        return _path_requirement_risks(requirement_text)
    if requirement.url is None:
        return []
    return _direct_url_risks(requirement.url)


def _path_requirement_risks(value: str) -> list[str]:
    cleaned = value.split("#", maxsplit=1)[0].strip()
    if cleaned.lower().endswith(".whl"):
        return []
    if cleaned.startswith((".", "/", "~")) or Path(cleaned).is_absolute():
        return ["local path requirement without a prebuilt wheel"]
    if "/" in cleaned or "\\" in cleaned:
        return ["local path requirement without a prebuilt wheel"]
    if cleaned.lower().endswith(SOURCE_ARCHIVE_SUFFIXES):
        return ["source archive requirement"]
    return []


def _direct_url_risks(url: str) -> list[str]:
    lowered = url.lower()
    if any(lowered.startswith(prefix) for prefix in VCS_PREFIXES):
        return ["VCS requirement"]
    parsed = parse.urlsplit(url)
    path = parsed.path.lower()
    if path.endswith(".whl"):
        return []
    if parsed.scheme in {"", "file"}:
        return ["local path requirement without a prebuilt wheel"]
    if path.endswith(SOURCE_ARCHIVE_SUFFIXES):
        return ["source archive requirement"]
    return ["direct URL requirement without a prebuilt wheel"]


def _dependency_group_risks(path: Path, group: str) -> list[str]:
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ResolutionError(f"unable to inspect dependency group source {path}: {exc}") from exc
    groups = payload.get("dependency-groups")
    if not isinstance(groups, dict):
        return []
    selected = groups.get(group)
    if not isinstance(selected, list):
        return []
    return [
        risk
        for item in selected
        if isinstance(item, str)
        for risk in _requirement_risks(item)
    ]


def _strict_resolver_environment(sitecustomize_dir: Path) -> dict[str, str]:
    allowed = {name.upper() for name in STRICT_ENVIRONMENT_ALLOWLIST}
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed or key.upper().startswith("LC_")
    }
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(sitecustomize_dir),
        }
    )
    return environment


def parse_pip_version_text(output: str) -> Version | None:
    match = PIP_VERSION_PATTERN.search(output)
    if match is None:
        return None
    try:
        return Version(match.group(1))
    except InvalidVersion:
        return None


def is_supported_pip_version(version: Version) -> bool:
    return version >= MINIMUM_SUPPORTED_PIP


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
