from __future__ import annotations

import difflib
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final, Literal

import tomlkit
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from tomlkit.items import AoT, Array, InlineTable, Table

from .lockfiles import is_supported_lockfile, load_lockfile, load_pip_tools_lock
from .models import TrustReport, VulnerabilityRecord
from .resolver import ArtifactReference, Resolution, ResolutionError, ResolvedDistribution

REMEDIATION_SCHEMA_VERSION: Final = "1.2.0"
REMEDIATION_SCHEMA_ID: Final = (
    f"urn:trustcheck:remediation:{REMEDIATION_SCHEMA_VERSION}"
)

RemediationStatus = Literal[
    "not-needed",
    "planned",
    "validated",
    "applied",
    "pull-request-created",
    "blocked",
    "failed",
]
ResolveCandidate = Callable[[Sequence[str]], Resolution]
ScanCandidate = Callable[[Resolution], Mapping[str, TrustReport]]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _key(name: str) -> str:
    return str(canonicalize_name(name))


class RemediationError(RuntimeError):
    """Raised when a remediation cannot be prepared or applied safely."""


@dataclass(frozen=True, slots=True)
class RemediationUpgrade:
    project: str
    from_version: str
    to_version: str
    advisory_ids: tuple[str, ...] = ()
    direct: bool = False
    reason: str = ""
    compatibility_confidence: str = "medium"
    breaking_change_warning: str | None = None
    changelog_url: str | None = None
    transitive_explanation: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "advisory_ids": list(self.advisory_ids),
            "direct": self.direct,
            "reason": self.reason,
            "compatibility_confidence": self.compatibility_confidence,
            "breaking_change_warning": self.breaking_change_warning,
            "changelog_url": self.changelog_url,
            "transitive_explanation": self.transitive_explanation,
        }


@dataclass(frozen=True, slots=True)
class BlockedFix:
    project: str
    version: str
    advisory_ids: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "version": self.version,
            "advisory_ids": list(self.advisory_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SemanticEdit:
    path: str
    project: str
    from_version: str
    to_version: str
    kind: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FilePatch:
    path: str
    before_sha256: str
    after_sha256: str
    diff: str
    edits: tuple[SemanticEdit, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "diff": self.diff,
            "edits": [edit.to_dict() for edit in self.edits],
        }


@dataclass(frozen=True, slots=True)
class DependencyGraphNode:
    project: str
    normalized_name: str
    version: str
    requested: bool = False
    source_type: str = "index"
    editable: bool = False
    vcs: str | None = None
    vcs_commit: str | None = None
    index_url: str | None = None
    source_url: str | None = None
    requirements: tuple[str, ...] = ()
    artifacts: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "normalized_name": self.normalized_name,
            "version": self.version,
            "requested": self.requested,
            "source_type": self.source_type,
            "editable": self.editable,
            "vcs": self.vcs,
            "vcs_commit": self.vcs_commit,
            "index_url": self.index_url,
            "source_url": self.source_url,
            "requirements": list(self.requirements),
            "artifacts": list(self.artifacts),
        }


@dataclass(frozen=True, slots=True)
class DependencyGraphEdge:
    parent: str
    child: str
    requirement: str
    marker: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "parent": self.parent,
            "child": self.child,
            "requirement": self.requirement,
            "marker": self.marker,
        }


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    packages: tuple[DependencyGraphNode, ...]
    edges: tuple[DependencyGraphEdge, ...]
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "package_count": len(self.packages),
            "edge_count": len(self.edges),
            "packages": [package.to_dict() for package in self.packages],
            "edges": [edge.to_dict() for edge in self.edges],
        }


@dataclass(frozen=True, slots=True)
class AdvisoryRemoval:
    project: str
    from_version: str
    to_version: str
    advisory_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "project": self.project,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "advisory_ids": list(self.advisory_ids),
        }


@dataclass(frozen=True, slots=True)
class LockfileHashValidation:
    path: str
    format: str
    applicable: bool
    package_count: int = 0
    artifact_count: int = 0
    hashed_artifact_count: int = 0
    valid: bool = True
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "format": self.format,
            "applicable": self.applicable,
            "package_count": self.package_count,
            "artifact_count": self.artifact_count,
            "hashed_artifact_count": self.hashed_artifact_count,
            "valid": self.valid,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class RemediationValidation:
    resolution_passed: bool = False
    rescan_passed: bool = False
    targeted_advisories_removed: bool = False
    no_new_vulnerabilities: bool = False
    no_new_policy_violations: bool = False
    index_provenance_preserved: bool = False
    policy_passed: bool = False
    errors: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return all(
            (
                self.resolution_passed,
                self.rescan_passed,
                self.targeted_advisories_removed,
                self.no_new_vulnerabilities,
                self.no_new_policy_violations,
                self.index_provenance_preserved,
            )
        ) and not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "resolution_passed": self.resolution_passed,
            "rescan_passed": self.rescan_passed,
            "targeted_advisories_removed": self.targeted_advisories_removed,
            "no_new_vulnerabilities": self.no_new_vulnerabilities,
            "no_new_policy_violations": self.no_new_policy_violations,
            "index_provenance_preserved": self.index_provenance_preserved,
            "policy_passed": self.policy_passed,
            "accepted": self.accepted,
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class PostFixResult:
    command: tuple[str, ...]
    reproduced_resolution: bool
    dependency_graph_sha256: str
    reports_sha256: str
    validation: RemediationValidation

    def to_dict(self) -> dict[str, object]:
        return {
            "command": list(self.command),
            "reproduced_resolution": self.reproduced_resolution,
            "dependency_graph_sha256": self.dependency_graph_sha256,
            "reports_sha256": self.reports_sha256,
            "validation": self.validation.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class PullRequestResult:
    created: bool = False
    url: str | None = None
    branch: str | None = None
    worktree: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class RemediationPlan:
    source: str
    status: RemediationStatus = "planned"
    minimal: bool = False
    attempts: int = 0
    max_attempts: int = 256
    upgrades: list[RemediationUpgrade] = field(default_factory=list)
    blocked: list[BlockedFix] = field(default_factory=list)
    planned_edits: list[SemanticEdit] = field(default_factory=list)
    patches: list[FilePatch] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)
    before_graph: DependencyGraph | None = None
    after_graph: DependencyGraph | None = None
    advisory_ids_removed: list[AdvisoryRemoval] = field(default_factory=list)
    lockfile_hash_validation: list[LockfileHashValidation] = field(default_factory=list)
    post_fix_result: PostFixResult | None = None
    validation: RemediationValidation = field(default_factory=RemediationValidation)
    pull_request: PullRequestResult | None = None
    message: str = ""
    minimal_secure_upgrade_proof: dict[str, object] = field(default_factory=dict)
    candidate_resolution: Resolution | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "$schema": REMEDIATION_SCHEMA_ID,
            "schema_version": REMEDIATION_SCHEMA_VERSION,
            "source": self.source,
            "status": self.status,
            "minimal": self.minimal,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "upgrades": [upgrade.to_dict() for upgrade in self.upgrades],
            "blocked": [blocked.to_dict() for blocked in self.blocked],
            "planned_edits": [edit.to_dict() for edit in self.planned_edits],
            "patches": [patch.to_dict() for patch in self.patches],
            "commands": self.commands,
            "dependency_graphs": {
                "before": (
                    self.before_graph.to_dict()
                    if self.before_graph is not None
                    else None
                ),
                "after": (
                    self.after_graph.to_dict()
                    if self.after_graph is not None
                    else None
                ),
            },
            "advisory_ids_removed": [
                item.to_dict() for item in self.advisory_ids_removed
            ],
            "lockfile_hash_validation": [
                item.to_dict() for item in self.lockfile_hash_validation
            ],
            "post_fix_result": (
                self.post_fix_result.to_dict()
                if self.post_fix_result is not None
                else None
            ),
            "validation": self.validation.to_dict(),
            "pull_request": (
                self.pull_request.to_dict()
                if self.pull_request is not None
                else None
            ),
            "message": self.message,
            "minimal_secure_upgrade_proof": self.minimal_secure_upgrade_proof,
        }

    def write_json(self, path: str | Path) -> None:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


@dataclass(frozen=True, slots=True)
class RemediationTarget:
    distribution: ResolvedDistribution
    report: TrustReport
    source_type: str = "index"


@dataclass(slots=True)
class PreparedRemediation:
    plan: RemediationPlan
    root: Path
    source_root: Path
    changed_files: dict[Path, bytes] = field(default_factory=dict)
    _temporary_directory: tempfile.TemporaryDirectory[str] | None = field(
        default=None,
        repr=False,
    )

    def close(self) -> None:
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None

    def __enter__(self) -> PreparedRemediation:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def plan_remediation(
    *,
    source: str | Path,
    baseline: Resolution,
    reports: Mapping[str, TrustReport],
    root_requirements: Sequence[str],
    resolve: ResolveCandidate,
    scan: ScanCandidate,
    source_types: Mapping[str, str] | None = None,
    available_versions: Mapping[str, Sequence[str]] | None = None,
    allow_constraint_changes: bool = False,
    max_attempts: int = 256,
) -> RemediationPlan:
    if max_attempts < 1:
        raise ValueError("max_fix_attempts must be at least 1")
    plan = RemediationPlan(
        source=str(Path(source).resolve()),
        max_attempts=max_attempts,
    )
    distributions = {
        _key(item.name): item for item in baseline.distributions
    }
    normalized_reports = {
        _key(name): report for name, report in reports.items()
    }
    root_names = _root_requirement_names(root_requirements)
    source_types = {
        _key(name): value
        for name, value in (source_types or {}).items()
    }
    available_versions = {
        _key(name): versions
        for name, versions in (available_versions or {}).items()
    }

    candidates: dict[str, tuple[Version, ...]] = {}
    advisory_ids: dict[str, tuple[str, ...]] = {}
    for name, report in normalized_reports.items():
        distribution = distributions.get(name)
        if distribution is None:
            continue
        active = _active_fixable_vulnerabilities(report.vulnerabilities)
        if not active:
            continue
        ids = tuple(sorted({_primary_identifier(item) for item in active}))
        advisory_ids[name] = ids
        immutable_reason = _immutable_reason(
            distribution,
            source_types.get(name, "index"),
        )
        if immutable_reason is not None:
            plan.blocked.append(
                BlockedFix(
                    project=distribution.name,
                    version=distribution.version,
                    advisory_ids=ids,
                    reason=immutable_reason,
                )
            )
            continue
        fixed_versions = _secure_fixed_versions(
            active,
            current=distribution.version,
            available=available_versions.get(name, ()),
        )
        if not fixed_versions:
            plan.blocked.append(
                BlockedFix(
                    project=distribution.name,
                    version=distribution.version,
                    advisory_ids=ids,
                    reason=(
                        "the advisory providers did not supply a valid non-downgrade "
                        "fixed release"
                    ),
                )
            )
            continue
        if name in root_names and not _root_allows_any_candidate(
            root_requirements,
            name,
            fixed_versions,
            allow_constraint_changes=allow_constraint_changes,
        ):
            plan.blocked.append(
                BlockedFix(
                    project=distribution.name,
                    version=distribution.version,
                    advisory_ids=ids,
                    reason=(
                        "the declared requirement excludes every known secure release; "
                        "pass --allow-constraint-changes to permit a minimal range edit"
                    ),
                )
            )
            continue
        candidates[name] = fixed_versions

    if plan.blocked:
        plan.status = "blocked"
        plan.message = "one or more vulnerable dependencies cannot be remediated safely"
        return plan
    if not candidates:
        plan.status = "not-needed"
        plan.minimal = True
        plan.before_graph = dependency_graph_from_resolution(baseline)
        plan.after_graph = dependency_graph_from_resolution(baseline)
        plan.validation = RemediationValidation(
            resolution_passed=True,
            rescan_passed=True,
            targeted_advisories_removed=True,
            no_new_vulnerabilities=True,
            no_new_policy_violations=True,
            index_provenance_preserved=True,
            policy_passed=all(report.policy.passed for report in reports.values()),
        )
        plan.message = "no active fixable vulnerabilities were found"
        return plan

    vulnerable_names = tuple(sorted(candidates))
    unchanged = tuple(
        sorted(name for name in distributions if name not in vulnerable_names)
    )
    baseline_vulnerabilities = _vulnerability_identifiers(normalized_reports)
    baseline_violations = _policy_violations(normalized_reports)
    successful: list[
        tuple[
            tuple[int, int, tuple[Version, ...]],
            Resolution,
            Mapping[str, TrustReport],
            dict[str, Version],
        ]
    ] = []
    exhausted = False

    for relaxed_count in range(len(unchanged) + 1):
        level_complete = True
        for selected_versions in itertools.product(
            *(candidates[name] for name in vulnerable_names)
        ):
            selected = dict(zip(vulnerable_names, selected_versions, strict=True))
            adjusted_roots = _requirements_for_candidate(
                root_requirements,
                selected,
                allow_constraint_changes=allow_constraint_changes,
            )
            for relaxed in itertools.combinations(unchanged, relaxed_count):
                if plan.attempts >= max_attempts:
                    exhausted = True
                    level_complete = False
                    break
                relaxed_set = set(relaxed)
                requirements = list(adjusted_roots)
                requirements.extend(
                    f"{distributions[name].name}=={distributions[name].version}"
                    for name in unchanged
                    if name not in relaxed_set
                )
                requirements.extend(
                    f"{distributions[name].name}=={version}"
                    for name, version in selected.items()
                )
                plan.attempts += 1
                try:
                    resolution = resolve(requirements)
                    if _resolution_has_disallowed_release(
                        baseline,
                        resolution,
                    ):
                        continue
                    candidate_reports = scan(resolution)
                except (ResolutionError, RemediationError, ValueError):
                    continue
                validation = validate_candidate(
                    baseline=baseline,
                    baseline_reports=normalized_reports,
                    candidate=resolution,
                    candidate_reports=candidate_reports,
                    targeted=advisory_ids,
                    baseline_vulnerabilities=baseline_vulnerabilities,
                    baseline_violations=baseline_violations,
                )
                if not validation.accepted:
                    continue
                objective = _candidate_objective(
                    baseline,
                    resolution,
                    selected_versions,
                    direct_names=root_names,
                )
                successful.append(
                    (objective, resolution, candidate_reports, selected)
                )
            if exhausted:
                break
        if successful:
            if not level_complete:
                plan.status = "blocked"
                plan.message = (
                    "the remediation search found a candidate but could not prove "
                    "minimality before --max-fix-attempts was exhausted"
                )
                return plan
            break
        if exhausted:
            plan.status = "blocked"
            plan.message = (
                "the remediation search limit was exhausted before a minimal "
                "secure solution could be proven"
            )
            return plan

    if not successful:
        plan.status = "blocked"
        plan.message = "no constraint-compatible secure resolution was found"
        return plan

    successful.sort(key=lambda item: item[0])
    _, selected_resolution, selected_reports, chosen_versions_map = successful[0]
    plan.minimal = True
    plan.candidate_resolution = selected_resolution
    plan.before_graph = dependency_graph_from_resolution(baseline)
    plan.after_graph = dependency_graph_from_resolution(selected_resolution)
    plan.upgrades = [
        RemediationUpgrade(
            project=distributions[name].name,
            from_version=distributions[name].version,
            to_version=str(version),
            advisory_ids=advisory_ids[name],
            direct=name in root_names,
            reason=(
                "lowest constraint-compatible release that removes all active "
                "fixable advisories in the selected environment"
            ),
            compatibility_confidence=_compatibility_confidence(
                distributions[name].version,
                str(version),
                direct=name in root_names,
            ),
            breaking_change_warning=_breaking_change_warning(
                distributions[name].version,
                str(version),
            ),
            changelog_url=_changelog_url(normalized_reports.get(name)),
            transitive_explanation=(
                None
                if name in root_names
                else _transitive_explanation(name, baseline)
            ),
        )
        for name, version in sorted(chosen_versions_map.items())
    ]
    plan.advisory_ids_removed = [
        AdvisoryRemoval(
            project=upgrade.project,
            from_version=upgrade.from_version,
            to_version=upgrade.to_version,
            advisory_ids=upgrade.advisory_ids,
        )
        for upgrade in plan.upgrades
    ]
    plan.planned_edits = [
        SemanticEdit(
            path=str(Path(source).resolve()),
            project=upgrade.project,
            from_version=upgrade.from_version,
            to_version=upgrade.to_version,
            kind=(
                "direct-requirement"
                if upgrade.direct
                else "resolved-lock-entry"
            ),
        )
        for upgrade in plan.upgrades
    ]
    plan.validation = validate_candidate(
        baseline=baseline,
        baseline_reports=normalized_reports,
        candidate=selected_resolution,
        candidate_reports=selected_reports,
        targeted=advisory_ids,
        baseline_vulnerabilities=baseline_vulnerabilities,
        baseline_violations=baseline_violations,
    )
    plan.status = "validated"
    plan.message = "a minimal secure resolution was validated"
    plan.minimal_secure_upgrade_proof = {
        "proven": True,
        "strategy": "exhaustive-cardinality-then-version search",
        "attempts": plan.attempts,
        "max_attempts": plan.max_attempts,
        "targeted_advisories_removed": plan.validation.targeted_advisories_removed,
        "no_new_vulnerabilities": plan.validation.no_new_vulnerabilities,
        "policy_passed": plan.validation.policy_passed,
        "resolution_reproducible": plan.validation.resolution_passed,
        "selected_upgrades": [
            f"{item.project}=={item.to_version}" for item in plan.upgrades
        ],
    }
    return plan


def _compatibility_confidence(from_version: str, to_version: str, *, direct: bool) -> str:
    try:
        before = Version(from_version)
        after = Version(to_version)
    except InvalidVersion:
        return "low"
    if before.major != after.major:
        return "low"
    if before.minor != after.minor:
        return "medium" if direct else "low"
    return "high"


def _breaking_change_warning(from_version: str, to_version: str) -> str | None:
    try:
        before = Version(from_version)
        after = Version(to_version)
    except InvalidVersion:
        return "Version compatibility could not be classified; review release notes."
    if before.major != after.major:
        return (
            f"Major-version upgrade {from_version} -> {to_version} may contain "
            "backward-incompatible changes."
        )
    return None


def _changelog_url(report: TrustReport | None) -> str | None:
    if report is None:
        return None
    urls = [*report.declared_repository_urls, *report.repository_urls]
    explicit = next(
        (url for url in urls if "changelog" in url.lower() or "releases" in url.lower()),
        None,
    )
    if explicit:
        return explicit
    github = next((url.rstrip("/") for url in urls if "github.com/" in url.lower()), None)
    return f"{github}/releases" if github else None


def _transitive_explanation(project: str, resolution: Resolution) -> str:
    parents: list[str] = []
    for distribution in resolution.distributions:
        for raw_requirement in distribution.requires_dist:
            try:
                requirement = Requirement(raw_requirement)
            except InvalidRequirement:
                continue
            if _key(requirement.name) == project:
                parents.append(f"{distribution.name}=={distribution.version}")
    if parents:
        return "Required transitively by " + ", ".join(sorted(set(parents))) + "."
    return "Transitive dependency selected by the resolved dependency graph."


def validate_candidate(
    *,
    baseline: Resolution,
    baseline_reports: Mapping[str, TrustReport],
    candidate: Resolution,
    candidate_reports: Mapping[str, TrustReport],
    targeted: Mapping[str, Sequence[str]],
    baseline_vulnerabilities: set[tuple[str, str]] | None = None,
    baseline_violations: set[tuple[str, str]] | None = None,
) -> RemediationValidation:
    errors: list[str] = []
    normalized_candidate_reports = {
        _key(name): report
        for name, report in candidate_reports.items()
    }
    targeted_removed = True
    for name, identifiers in targeted.items():
        report = normalized_candidate_reports.get(_key(name))
        if report is None:
            targeted_removed = False
            errors.append(f"candidate scan did not return {name}")
            continue
        active_ids = {
            identifier
            for vulnerability in report.vulnerabilities
            if _is_active(vulnerability)
            for identifier in _all_identifiers(vulnerability)
        }
        remaining = sorted(set(identifiers).intersection(active_ids))
        if remaining:
            targeted_removed = False
            errors.append(
                f"{name} remains affected by {', '.join(remaining)}"
            )

    baseline_vulnerabilities = baseline_vulnerabilities or _vulnerability_identifiers(
        baseline_reports
    )
    candidate_vulnerabilities = _vulnerability_identifiers(
        normalized_candidate_reports
    )
    new_vulnerabilities = sorted(
        candidate_vulnerabilities.difference(baseline_vulnerabilities)
    )
    if new_vulnerabilities:
        errors.append(
            "candidate introduces active vulnerabilities: "
            + ", ".join(f"{name}:{identifier}" for name, identifier in new_vulnerabilities)
        )

    baseline_violations = baseline_violations or _policy_violations(
        baseline_reports
    )
    candidate_violations = _policy_violations(normalized_candidate_reports)
    new_violations = sorted(candidate_violations.difference(baseline_violations))
    if new_violations:
        errors.append(
            "candidate introduces policy violations: "
            + ", ".join(f"{name}:{code}" for name, code in new_violations)
        )

    provenance_preserved = _index_provenance_preserved(baseline, candidate)
    if not provenance_preserved:
        errors.append("candidate changes one or more package index origins")

    return RemediationValidation(
        resolution_passed=bool(candidate.distributions),
        rescan_passed=bool(normalized_candidate_reports),
        targeted_advisories_removed=targeted_removed,
        no_new_vulnerabilities=not new_vulnerabilities,
        no_new_policy_violations=not new_violations,
        index_provenance_preserved=provenance_preserved,
        policy_passed=all(
            report.policy.passed for report in normalized_candidate_reports.values()
        ),
        errors=tuple(errors),
    )


def prepare_remediation(
    target: str | Path,
    plan: RemediationPlan,
    *,
    source_manifest: str | Path | None = None,
    constraint_files: Sequence[str | Path] = (),
    allow_constraint_changes: bool = False,
    runner: CommandRunner = subprocess.run,
    command_timeout: float = 300.0,
) -> PreparedRemediation:
    if plan.status != "validated" or plan.candidate_resolution is None:
        raise RemediationError("only a validated remediation plan can be prepared")
    target_path = Path(target).resolve()
    if not target_path.is_file():
        raise RemediationError(f"remediation target does not exist: {target_path}")
    source_root = _project_root(
        target_path,
        source_manifest,
        constraint_files=constraint_files,
    )
    temporary = tempfile.TemporaryDirectory(prefix="trustcheck-remediation-")
    staged_root = Path(temporary.name) / "project"
    shutil.copytree(
        source_root,
        staged_root,
        ignore=shutil.ignore_patterns(
            ".git",
            ".hg",
            ".svn",
            ".tox",
            ".venv",
            "__pycache__",
        ),
    )
    staged_target = staged_root / target_path.relative_to(source_root)
    manifest_path = (
        Path(source_manifest).resolve()
        if source_manifest is not None
        else _discover_source_manifest(target_path)
    )
    staged_manifest = (
        staged_root / manifest_path.relative_to(source_root)
        if manifest_path is not None
        else None
    )
    staged_constraints = [
        staged_root / Path(path).resolve().relative_to(source_root)
        for path in constraint_files
    ]
    commands: list[list[str]] = []
    for index, constraint in enumerate(staged_constraints):
        _edit_requirements_file(
            constraint,
            plan.upgrades,
            allow_constraint_changes=allow_constraint_changes,
            append_missing=index == 0,
            pin_exact=True,
        )

    kind = _input_kind(target_path)
    if kind == "requirements":
        if _looks_hash_pinned(target_path):
            _run_pip_compile(
                staged_target,
                staged_root=staged_root,
                source_root=source_root,
                upgrades=plan.upgrades,
                commands=commands,
                runner=runner,
                timeout=command_timeout,
                source_manifest=staged_manifest,
            )
        else:
            _edit_requirements_file(
                staged_target,
                plan.upgrades,
                allow_constraint_changes=allow_constraint_changes,
                append_missing=not staged_constraints,
                pin_exact=True,
            )
    elif kind == "pyproject":
        _edit_pyproject(
            staged_target,
            plan.upgrades,
            allow_constraint_changes=allow_constraint_changes,
            append_missing=True,
            pin_exact=True,
        )
    elif kind == "pylock":
        if staged_manifest is not None and staged_manifest.name == "pyproject.toml":
            _edit_pyproject(
                staged_manifest,
                plan.upgrades,
                allow_constraint_changes=allow_constraint_changes,
                append_missing=False,
                pin_exact=False,
            )
        _write_pylock(staged_target, plan.candidate_resolution)
    elif kind in {"uv", "poetry", "pdm"}:
        if staged_manifest is None:
            temporary.cleanup()
            raise RemediationError(
                f"{target_path.name} requires a neighboring pyproject.toml or "
                "--source-manifest"
            )
        _edit_pyproject(
            staged_manifest,
            plan.upgrades,
            allow_constraint_changes=allow_constraint_changes,
            append_missing=False,
            pin_exact=False,
        )
        _run_native_locker(
            kind,
            staged_root=staged_root,
            upgrades=plan.upgrades,
            commands=commands,
            runner=runner,
            timeout=command_timeout,
        )
    else:
        temporary.cleanup()
        raise RemediationError(
            f"automatic remediation is not supported for {target_path.name}"
        )
    changed_files = _collect_changed_files(source_root, staged_root)
    if not changed_files:
        temporary.cleanup()
        raise RemediationError("the validated remediation produced no file changes")
    patches = _build_file_patches(
        source_root,
        changed_files,
        plan.upgrades,
    )
    lockfile_hash_validation = _validate_changed_lockfile_hashes(
        source_root,
        staged_root,
        changed_files,
    )
    invalid_lockfiles = [
        item for item in lockfile_hash_validation if not item.valid
    ]
    if invalid_lockfiles:
        temporary.cleanup()
        detail = "; ".join(
            f"{item.path}: {', '.join(item.errors)}"
            for item in invalid_lockfiles
        )
        raise RemediationError(f"lockfile hash validation failed: {detail}")
    plan.commands = commands
    plan.patches = patches
    plan.lockfile_hash_validation = lockfile_hash_validation
    return PreparedRemediation(
        plan=plan,
        root=staged_root,
        source_root=source_root,
        changed_files=changed_files,
        _temporary_directory=temporary,
    )


def apply_prepared_remediation(prepared: PreparedRemediation) -> None:
    backups: dict[Path, bytes | None] = {}
    staged_paths: list[Path] = []
    try:
        patch_by_path = {patch.path: patch for patch in prepared.plan.patches}
        for relative_path, content in sorted(prepared.changed_files.items()):
            destination = prepared.source_root / relative_path
            patch = patch_by_path.get(relative_path.as_posix())
            if patch is None:
                raise RemediationError(
                    f"missing patch metadata for {relative_path.as_posix()}"
                )
            existing = destination.read_bytes() if destination.exists() else None
            if _sha256(existing or b"") != patch.before_sha256:
                raise RemediationError(
                    f"refusing to overwrite changed file: {destination}"
                )
            backups[destination] = existing
            destination.parent.mkdir(parents=True, exist_ok=True)
            staged = destination.with_name(
                f".{destination.name}.trustcheck-{os.getpid()}.tmp"
            )
            staged.write_bytes(content)
            staged_paths.append(staged)
        for relative_path in sorted(prepared.changed_files):
            destination = prepared.source_root / relative_path
            staged = destination.with_name(
                f".{destination.name}.trustcheck-{os.getpid()}.tmp"
            )
            os.replace(staged, destination)
            staged_paths.remove(staged)
    except Exception:
        for staged in staged_paths:
            staged.unlink(missing_ok=True)
        for destination, original in backups.items():
            if original is None:
                destination.unlink(missing_ok=True)
            else:
                destination.write_bytes(original)
        raise
    prepared.plan.status = "applied"
    prepared.plan.message = "validated remediation was applied atomically"


def create_pull_request(
    prepared: PreparedRemediation,
    *,
    base: str | None = None,
    branch: str | None = None,
    title: str | None = None,
    ready: bool = False,
    runner: CommandRunner = subprocess.run,
    timeout: float = 300.0,
) -> PullRequestResult:
    source_root = prepared.source_root
    _validate_git_identifier(base, "base branch")
    branch = branch or _default_branch_name(prepared.plan.upgrades)
    _validate_git_identifier(branch, "pull request branch")
    title = title or _default_pr_title(prepared.plan.upgrades)
    repository = _run_command(
        ["git", "-C", str(source_root), "rev-parse", "--show-toplevel"],
        runner=runner,
        timeout=timeout,
    )
    repo_root = (
        Path(repository.stdout.strip()).resolve()
        if repository.stdout.strip()
        else source_root
    )
    if not source_root.is_relative_to(repo_root):
        raise RemediationError(
            f"remediation source is outside Git repository {repo_root}"
        )
    source_prefix = source_root.relative_to(repo_root)
    status = _run_command(
        ["git", "-C", str(repo_root), "status", "--porcelain"],
        runner=runner,
        timeout=timeout,
    )
    if status.stdout.strip():
        raise RemediationError(
            "--create-pr requires a clean Git worktree so only validated "
            "dependency files are committed"
        )
    temporary = tempfile.mkdtemp(prefix="trustcheck-pr-")
    worktree = Path(temporary)
    add_command = [
        "git",
        "-C",
        str(repo_root),
        "worktree",
        "add",
        "-b",
        branch,
        str(worktree),
    ]
    if base:
        add_command.append(base)
    _run_command(add_command, runner=runner, timeout=timeout)
    try:
        for relative_path, content in prepared.changed_files.items():
            destination = worktree / source_prefix / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        relative_names = [
            (source_prefix / path).as_posix()
            for path in sorted(prepared.changed_files)
        ]
        _run_command(
            ["git", "-C", str(worktree), "add", "--", *relative_names],
            runner=runner,
            timeout=timeout,
        )
        _run_command(
            [
                "git",
                "-C",
                str(worktree),
                "commit",
                "-m",
                title,
            ],
            runner=runner,
            timeout=timeout,
        )
        _run_command(
            [
                "git",
                "-C",
                str(worktree),
                "push",
                "--set-upstream",
                "origin",
                branch,
            ],
            runner=runner,
            timeout=timeout,
        )
        command = [
            "gh",
            "pr",
            "create",
            "--head",
            branch,
            "--title",
            title,
            "--body",
            _pull_request_body(prepared.plan),
        ]
        if base:
            command.extend(["--base", base])
        if not ready:
            command.append("--draft")
        completed = _run_command(command, runner=runner, timeout=timeout)
        url = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else None
    except Exception as exc:
        result = PullRequestResult(
            created=False,
            branch=branch,
            worktree=str(worktree),
            error=(
                f"{exc}; the branch/worktree was retained for recovery at "
                f"{worktree}"
            ),
        )
        prepared.plan.pull_request = result
        prepared.plan.status = "failed"
        return result

    _run_command(
        ["git", "-C", str(repo_root), "worktree", "remove", str(worktree)],
        runner=runner,
        timeout=timeout,
    )
    result = PullRequestResult(created=True, url=url, branch=branch)
    prepared.plan.pull_request = result
    prepared.plan.status = "pull-request-created"
    prepared.plan.message = "validated remediation was published as a pull request"
    return result


def render_remediation_text(plan: RemediationPlan) -> str:
    lines = [
        f"remediation: {plan.status}",
        f"minimal: {'yes' if plan.minimal else 'no'}",
        f"attempts: {plan.attempts}/{plan.max_attempts}",
    ]
    if plan.minimal_secure_upgrade_proof:
        lines.append(
            "minimal secure upgrade proof: "
            + (
                "proven"
                if plan.minimal_secure_upgrade_proof.get("proven")
                else "not proven"
            )
        )
    if plan.message:
        lines.append(f"message: {plan.message}")
    if plan.upgrades:
        lines.append("upgrades:")
        lines.extend(
            "  - "
            f"{item.project}: {item.from_version} -> {item.to_version} "
            f"({', '.join(item.advisory_ids)}; confidence={item.compatibility_confidence})"
            for item in plan.upgrades
        )
        for item in plan.upgrades:
            if item.breaking_change_warning:
                lines.append(f"    warning: {item.breaking_change_warning}")
            if item.transitive_explanation:
                lines.append(f"    cause: {item.transitive_explanation}")
            if item.changelog_url:
                lines.append(f"    changelog: {item.changelog_url}")
    if plan.blocked:
        lines.append("blocked:")
        lines.extend(
            f"  - {item.project} {item.version}: {item.reason}"
            for item in plan.blocked
        )
    if plan.patches:
        lines.append("patches:")
        lines.extend(f"  - {patch.path}" for patch in plan.patches)
    if plan.pull_request and plan.pull_request.url:
        lines.append(f"pull request: {plan.pull_request.url}")
    return "\n".join(lines)


def dependency_graph_from_resolution(resolution: Resolution) -> DependencyGraph:
    known = {_key(distribution.name) for distribution in resolution.distributions}
    nodes: list[DependencyGraphNode] = []
    edges: list[DependencyGraphEdge] = []
    for distribution in sorted(
        resolution.distributions,
        key=lambda item: (_key(item.name), item.version),
    ):
        normalized = _key(distribution.name)
        source_type = (
            "vcs"
            if distribution.vcs is not None
            else "editable"
            if distribution.editable
            else "direct"
            if distribution.is_direct
            else "index"
        )
        requirements = tuple(sorted(distribution.requires_dist))
        nodes.append(
            DependencyGraphNode(
                project=distribution.name,
                normalized_name=normalized,
                version=distribution.version,
                requested=distribution.requested,
                source_type=source_type,
                editable=distribution.editable,
                vcs=distribution.vcs,
                vcs_commit=distribution.vcs_commit,
                index_url=distribution.index_url,
                source_url=distribution.source_url,
                requirements=requirements,
                artifacts=tuple(
                    artifact.to_dict() for artifact in distribution.artifacts
                ),
            )
        )
        for raw_requirement in requirements:
            requirement = _parse_requirement(raw_requirement)
            if requirement is None:
                continue
            child = _key(requirement.name)
            if child not in known:
                continue
            edges.append(
                DependencyGraphEdge(
                    parent=normalized,
                    child=child,
                    requirement=raw_requirement,
                    marker=(
                        str(requirement.marker)
                        if requirement.marker is not None
                        else None
                    ),
                )
            )
    edges.sort(key=lambda item: (item.parent, item.child, item.requirement))
    payload = {
        "packages": [node.to_dict() for node in nodes],
        "edges": [edge.to_dict() for edge in edges],
    }
    return DependencyGraph(
        packages=tuple(nodes),
        edges=tuple(edges),
        sha256=_stable_json_sha256(payload),
    )


def reports_sha256(reports: Mapping[str, TrustReport]) -> str:
    payload = [
        report.to_dict()
        for _name, report in sorted(
            reports.items(),
            key=lambda item: _key(item[0]),
        )
    ]
    return _stable_json_sha256(payload)


def post_fix_result(
    *,
    command: Sequence[str],
    resolution: Resolution,
    reports: Mapping[str, TrustReport],
    validation: RemediationValidation,
    expected_versions: Mapping[str, str],
) -> PostFixResult:
    graph = dependency_graph_from_resolution(resolution)
    return PostFixResult(
        command=tuple(command),
        reproduced_resolution=resolution.versions == dict(expected_versions),
        dependency_graph_sha256=graph.sha256,
        reports_sha256=reports_sha256(reports),
        validation=validation,
    )


def _active_fixable_vulnerabilities(
    vulnerabilities: Sequence[VulnerabilityRecord],
) -> list[VulnerabilityRecord]:
    return [
        item
        for item in vulnerabilities
        if _is_active(item) and bool(item.fixed_in)
    ]


def _is_active(vulnerability: VulnerabilityRecord) -> bool:
    return not vulnerability.withdrawn and not (
        vulnerability.suppression is not None
        and vulnerability.suppression.status == "active"
    )


def _primary_identifier(vulnerability: VulnerabilityRecord) -> str:
    return vulnerability.id.upper()


def _all_identifiers(vulnerability: VulnerabilityRecord) -> set[str]:
    return {
        vulnerability.id.upper(),
        *(alias.upper() for alias in vulnerability.aliases),
    }


def _secure_fixed_versions(
    vulnerabilities: Sequence[VulnerabilityRecord],
    *,
    current: str,
    available: Sequence[str] = (),
) -> tuple[Version, ...]:
    try:
        current_version = Version(current)
    except InvalidVersion:
        return ()
    minimums: list[Version] = []
    all_versions: set[Version] = set()
    for vulnerability in vulnerabilities:
        versions: list[Version] = []
        for raw_version in vulnerability.fixed_in:
            try:
                parsed = Version(raw_version)
            except InvalidVersion:
                continue
            if parsed >= current_version and not parsed.is_prerelease:
                versions.append(parsed)
                all_versions.add(parsed)
        if not versions:
            return ()
        minimums.append(min(versions))
    lower_bound = max(minimums)
    registry_versions: set[Version] = set()
    for raw_version in available:
        try:
            parsed = Version(raw_version)
        except InvalidVersion:
            continue
        if parsed >= lower_bound and not parsed.is_prerelease:
            registry_versions.add(parsed)
    candidates = sorted(
        registry_versions
        if available
        else {version for version in all_versions if version >= lower_bound}
    )
    if not available and lower_bound not in candidates:
        candidates.insert(0, lower_bound)
    return tuple(candidates)


def _immutable_reason(
    distribution: ResolvedDistribution,
    source_type: str,
) -> str | None:
    if distribution.editable:
        return "editable dependencies are immutable during automated remediation"
    if distribution.vcs is not None or source_type == "vcs":
        return "VCS dependencies require a human-selected commit"
    if source_type in {"directory", "archive", "url", "direct"}:
        return f"{source_type} dependencies are not registry-version upgrade targets"
    return None


def _root_requirement_names(requirements: Sequence[str]) -> set[str]:
    names: set[str] = set()
    for raw in requirements:
        try:
            names.add(_key(Requirement(raw).name))
        except InvalidRequirement:
            continue
    return names


def _root_allows_any_candidate(
    requirements: Sequence[str],
    name: str,
    candidates: Sequence[Version],
    *,
    allow_constraint_changes: bool,
) -> bool:
    matching = [
        requirement
        for raw in requirements
        if (requirement := _parse_requirement(raw)) is not None
        and _key(requirement.name) == name
    ]
    if not matching:
        return True
    for requirement in matching:
        exact = _exact_pin(requirement)
        if exact is not None:
            continue
        if any(
            requirement.specifier.contains(candidate, prereleases=False)
            for candidate in candidates
        ):
            continue
        if not allow_constraint_changes:
            return False
    return True


def _requirements_for_candidate(
    requirements: Sequence[str],
    selected: Mapping[str, Version],
    *,
    allow_constraint_changes: bool,
) -> list[str]:
    adjusted: list[str] = []
    seen: set[str] = set()
    for raw in requirements:
        requirement = _parse_requirement(raw)
        if requirement is None:
            adjusted.append(raw)
            continue
        name = _key(requirement.name)
        target = selected.get(name)
        if target is None:
            adjusted.append(raw)
            continue
        seen.add(name)
        adjusted.append(
            _updated_requirement(
                requirement,
                target,
                allow_constraint_changes=allow_constraint_changes,
            )
        )
    adjusted.extend(
        f"{name}=={version}"
        for name, version in selected.items()
        if name not in seen
    )
    return adjusted


def _parse_requirement(raw: str) -> Requirement | None:
    try:
        return Requirement(raw)
    except InvalidRequirement:
        return None


def _exact_pin(requirement: Requirement) -> Version | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator not in {"==", "==="}:
        return None
    if "*" in specifiers[0].version:
        return None
    try:
        return Version(specifiers[0].version)
    except InvalidVersion:
        return None


def _updated_requirement(
    requirement: Requirement,
    target: Version,
    *,
    allow_constraint_changes: bool,
) -> str:
    if requirement.url is not None:
        raise RemediationError(
            f"direct URL requirement {requirement.name!r} cannot be rewritten safely"
        )
    exact = _exact_pin(requirement)
    if exact is not None:
        specifier = f"=={target}"
    elif requirement.specifier.contains(target, prereleases=False):
        specifier = _raise_lower_bound(str(requirement.specifier), target)
    elif allow_constraint_changes:
        specifier = _minimal_compatible_specifier(
            str(requirement.specifier),
            target,
        )
    else:
        raise RemediationError(
            f"{requirement.name} excludes secure version {target}"
        )
    extras = (
        f"[{','.join(sorted(requirement.extras))}]"
        if requirement.extras
        else ""
    )
    marker = f"; {requirement.marker}" if requirement.marker is not None else ""
    return f"{requirement.name}{extras}{specifier}{marker}"


def _pinned_requirement(
    requirement: Requirement,
    target: Version,
) -> str:
    if requirement.url is not None:
        raise RemediationError(
            f"direct URL requirement {requirement.name!r} cannot be rewritten safely"
        )
    extras = (
        f"[{','.join(sorted(requirement.extras))}]"
        if requirement.extras
        else ""
    )
    marker = f"; {requirement.marker}" if requirement.marker is not None else ""
    return f"{requirement.name}{extras}=={target}{marker}"


def _raise_lower_bound(specifier: str, target: Version) -> str:
    retained: list[str] = []
    for item in SpecifierSet(specifier):
        if item.operator in {">", ">="}:
            continue
        if item.operator == "~=":
            retained.append(f"<{_compatible_upper_bound(item.version)}")
            continue
        if item.operator in {"==", "==="} and "*" not in item.version:
            continue
        retained.append(str(item))
    return ",".join([f">={target}", *retained])


def _compatible_upper_bound(value: str) -> str:
    version = Version(value)
    release = list(version.release)
    if len(release) <= 2:
        return f"{release[0] + 1}.0"
    upper = release[:-1]
    upper[-1] += 1
    return ".".join(str(part) for part in upper)


def _minimal_compatible_specifier(specifier: str, target: Version) -> str:
    retained: list[str] = []
    for item in SpecifierSet(specifier):
        if item.operator in {"!=", "<", "<="}:
            try:
                if item.contains(target, prereleases=False):
                    retained.append(str(item))
            except InvalidVersion:
                continue
    return ",".join([f">={target}", *retained])


def _candidate_objective(
    baseline: Resolution,
    candidate: Resolution,
    selected_versions: Sequence[Version],
    *,
    direct_names: set[str],
) -> tuple[int, int, tuple[Version, ...]]:
    baseline_versions = baseline.versions
    candidate_versions = candidate.versions
    changed = sum(
        1
        for name in set(baseline_versions).union(candidate_versions)
        if baseline_versions.get(name) != candidate_versions.get(name)
    )
    direct_changes = sum(
        1
        for name in direct_names
        if baseline_versions.get(name) != candidate_versions.get(name)
    )
    return changed, direct_changes, tuple(selected_versions)


def _vulnerability_identifiers(
    reports: Mapping[str, TrustReport],
) -> set[tuple[str, str]]:
    return {
        (_key(name), identifier)
        for name, report in reports.items()
        for vulnerability in report.vulnerabilities
        if _is_active(vulnerability)
        for identifier in _all_identifiers(vulnerability)
    }


def _policy_violations(
    reports: Mapping[str, TrustReport],
) -> set[tuple[str, str]]:
    return {
        (_key(name), violation.code)
        for name, report in reports.items()
        for violation in report.policy.violations
    }


def _index_provenance_preserved(
    baseline: Resolution,
    candidate: Resolution,
) -> bool:
    baseline_indexes = {
        _key(item.name): item.index_url
        for item in baseline.distributions
        if item.index_url is not None
    }
    candidate_indexes = {
        _key(item.name): item.index_url
        for item in candidate.distributions
        if item.index_url is not None
    }
    return all(
        candidate_indexes.get(name, index) == index
        for name, index in baseline_indexes.items()
        if name in candidate.versions
    )


def _resolution_has_disallowed_release(
    baseline: Resolution,
    candidate: Resolution,
) -> bool:
    baseline_versions = baseline.versions
    for distribution in candidate.distributions:
        if distribution.is_yanked:
            return True
        try:
            version = Version(distribution.version)
        except InvalidVersion:
            return True
        if (
            version.is_prerelease
            and baseline_versions.get(_key(distribution.name))
            != distribution.version
        ):
            return True
    return False


def _project_root(
    target: Path,
    source_manifest: str | Path | None,
    *,
    constraint_files: Sequence[str | Path] = (),
) -> Path:
    root = target.parent
    if source_manifest is not None:
        manifest_parent = Path(source_manifest).resolve().parent
        if target.is_relative_to(manifest_parent):
            root = manifest_parent
        elif not Path(source_manifest).resolve().is_relative_to(root):
            raise RemediationError(
                "--source-manifest must be inside the remediation project root"
            )
    for raw_path in constraint_files:
        constraint = Path(raw_path).resolve()
        if not constraint.is_relative_to(root):
            raise RemediationError(
                f"constraint file is outside the remediation project root: {constraint}"
            )
    return root


def _discover_source_manifest(target: Path) -> Path | None:
    if target.name == "pyproject.toml":
        return target
    pyproject = target.parent / "pyproject.toml"
    if pyproject.is_file():
        return pyproject
    if target.name.lower() == "requirements.txt":
        source = target.with_suffix(".in")
        if source.is_file():
            return source
    return None


def _input_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "pyproject.toml":
        return "pyproject"
    if re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", name):
        return "pylock"
    if name == "uv.lock":
        return "uv"
    if name == "poetry.lock":
        return "poetry"
    if name == "pdm.lock":
        return "pdm"
    if path.suffix.lower() in {".txt", ".in"}:
        return "requirements"
    return "unsupported"


def _looks_hash_pinned(path: Path) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    return "--hash=" in text or "--require-hashes" in text


def _edit_requirements_file(
    path: Path,
    upgrades: Sequence[RemediationUpgrade],
    *,
    allow_constraint_changes: bool,
    append_missing: bool = True,
    pin_exact: bool = True,
    seen: set[Path] | None = None,
    matched: set[str] | None = None,
) -> None:
    resolved = path.resolve()
    visited = seen if seen is not None else set()
    matched_names = matched if matched is not None else set()
    is_root = seen is None
    if resolved in visited:
        raise RemediationError(f"cyclic requirements include involving {resolved}")
    visited.add(resolved)
    original = path.read_text(encoding="utf-8")
    newline = "\r\n" if "\r\n" in original else "\n"
    trailing_newline = original.endswith(("\n", "\r"))
    lines = original.splitlines()
    upgrade_map = {
        _key(item.project): item for item in upgrades
    }
    changed = False
    for index, line in enumerate(lines):
        include = _requirement_include(line, path.parent)
        if include is not None and include.is_file():
            _edit_requirements_file(
                include,
                upgrades,
                allow_constraint_changes=allow_constraint_changes,
                append_missing=False,
                pin_exact=pin_exact,
                seen=visited,
                matched=matched_names,
            )
            continue
        content, comment = _split_requirement_comment(line)
        stripped = content.strip()
        if not stripped or stripped.startswith("-"):
            continue
        requirement = _parse_requirement(stripped.rstrip("\\").strip())
        if requirement is None:
            continue
        upgrade = upgrade_map.get(_key(requirement.name))
        if upgrade is None:
            continue
        matched_names.add(_key(requirement.name))
        target = Version(upgrade.to_version)
        updated = (
            _pinned_requirement(requirement, target)
            if pin_exact
            else _updated_requirement(
                requirement,
                target,
                allow_constraint_changes=allow_constraint_changes,
            )
        )
        indentation = content[: len(content) - len(content.lstrip())]
        suffix = " \\" if content.rstrip().endswith("\\") else ""
        lines[index] = f"{indentation}{updated}{suffix}{comment}"
        changed = True
    if is_root and append_missing:
        missing = [
            upgrade
            for name, upgrade in upgrade_map.items()
            if name not in matched_names
        ]
        if missing:
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend(
                f"{upgrade.project}=={upgrade.to_version}"
                "  # added by trustcheck remediation"
                for upgrade in missing
            )
            changed = True
    if changed:
        rendered = newline.join(lines)
        if trailing_newline:
            rendered += newline
        path.write_text(rendered, encoding="utf-8", newline="")
    visited.remove(resolved)


def _requirement_include(line: str, base: Path) -> Path | None:
    match = re.match(
        r"^\s*(?:-r|--requirement|-c|--constraint)\s*(?:=|\s)\s*(\S+)",
        line,
    )
    if match is None:
        return None
    return (base / match.group(1)).resolve()


def _split_requirement_comment(line: str) -> tuple[str, str]:
    match = re.search(r"\s+#", line)
    if match is None:
        return line, ""
    return line[: match.start()], line[match.start() :]


def _edit_pyproject(
    path: Path,
    upgrades: Sequence[RemediationUpgrade],
    *,
    allow_constraint_changes: bool,
    append_missing: bool,
    pin_exact: bool,
) -> None:
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    upgrade_map = {
        _key(item.project): item for item in upgrades
    }
    matched: set[str] = set()
    project = document.get("project")
    if isinstance(project, Mapping):
        _edit_requirement_array(
            project.get("dependencies"),
            upgrade_map,
            allow_constraint_changes=allow_constraint_changes,
            matched=matched,
            pin_exact=pin_exact,
        )
        optional = project.get("optional-dependencies")
        if isinstance(optional, Mapping):
            for requirements in optional.values():
                _edit_requirement_array(
                    requirements,
                    upgrade_map,
                    allow_constraint_changes=allow_constraint_changes,
                    matched=matched,
                    pin_exact=pin_exact,
                )
    groups = document.get("dependency-groups")
    if isinstance(groups, Mapping):
        for requirements in groups.values():
            _edit_requirement_array(
                requirements,
                upgrade_map,
                allow_constraint_changes=allow_constraint_changes,
                matched=matched,
                pin_exact=pin_exact,
            )
    tool = document.get("tool")
    if isinstance(tool, Mapping):
        poetry = tool.get("poetry")
        if isinstance(poetry, Mapping):
            _edit_poetry_table(
                poetry.get("dependencies"),
                upgrade_map,
                allow_constraint_changes=allow_constraint_changes,
                matched=matched,
                pin_exact=pin_exact,
            )
            poetry_groups = poetry.get("group")
            if isinstance(poetry_groups, Mapping):
                for group in poetry_groups.values():
                    if isinstance(group, Mapping):
                        _edit_poetry_table(
                            group.get("dependencies"),
                            upgrade_map,
                            allow_constraint_changes=allow_constraint_changes,
                            matched=matched,
                            pin_exact=pin_exact,
                        )
        pdm = tool.get("pdm")
        if isinstance(pdm, Mapping):
            dev_dependencies = pdm.get("dev-dependencies")
            if isinstance(dev_dependencies, Mapping):
                for requirements in dev_dependencies.values():
                    _edit_requirement_array(
                        requirements,
                        upgrade_map,
                        allow_constraint_changes=allow_constraint_changes,
                        matched=matched,
                        pin_exact=pin_exact,
                    )
    if append_missing:
        project = document.get("project")
        dependencies = (
            project.get("dependencies")
            if isinstance(project, Mapping)
            else None
        )
        missing = [
            (name, upgrade)
            for name, upgrade in upgrade_map.items()
            if name not in matched
        ]
        if isinstance(dependencies, Array):
            for _, upgrade in missing:
                dependencies.append(
                    (
                        f"{upgrade.project}=={upgrade.to_version}"
                        if pin_exact
                        else f"{upgrade.project}>={upgrade.to_version}"
                    )
                )
        elif missing and isinstance(tool, Mapping):
            poetry = tool.get("poetry")
            poetry_dependencies = (
                poetry.get("dependencies")
                if isinstance(poetry, Mapping)
                else None
            )
            if isinstance(poetry_dependencies, (Table, InlineTable)):
                for _, upgrade in missing:
                    poetry_dependencies[upgrade.project] = (
                        upgrade.to_version
                        if pin_exact
                        else f">={upgrade.to_version}"
                    )
            elif isinstance(project, (Table, InlineTable)):
                new_dependencies = tomlkit.array()
                new_dependencies.multiline(True)
                for _, upgrade in missing:
                    new_dependencies.append(
                        (
                            f"{upgrade.project}=={upgrade.to_version}"
                            if pin_exact
                            else f"{upgrade.project}>={upgrade.to_version}"
                        )
                    )
                project["dependencies"] = new_dependencies
        elif missing and isinstance(project, (Table, InlineTable)):
            new_dependencies = tomlkit.array()
            new_dependencies.multiline(True)
            for _, upgrade in missing:
                new_dependencies.append(
                    (
                        f"{upgrade.project}=={upgrade.to_version}"
                        if pin_exact
                        else f"{upgrade.project}>={upgrade.to_version}"
                    )
                )
            project["dependencies"] = new_dependencies
    path.write_text(tomlkit.dumps(document), encoding="utf-8", newline="")


def _edit_requirement_array(
    value: object,
    upgrades: Mapping[str, RemediationUpgrade],
    *,
    allow_constraint_changes: bool,
    matched: set[str],
    pin_exact: bool,
) -> None:
    if not isinstance(value, Array):
        return
    for index, raw in enumerate(value):
        if not isinstance(raw, str):
            continue
        requirement = _parse_requirement(raw)
        if requirement is None:
            continue
        upgrade = upgrades.get(_key(requirement.name))
        if upgrade is None:
            continue
        matched.add(_key(requirement.name))
        target = Version(upgrade.to_version)
        value[index] = (
            _pinned_requirement(requirement, target)
            if pin_exact
            else _updated_requirement(
                requirement,
                target,
                allow_constraint_changes=allow_constraint_changes,
            )
        )


def _edit_poetry_table(
    value: object,
    upgrades: Mapping[str, RemediationUpgrade],
    *,
    allow_constraint_changes: bool,
    matched: set[str],
    pin_exact: bool,
) -> None:
    if not isinstance(value, (Table, InlineTable)):
        return
    for raw_name, raw_specifier in list(value.items()):
        name = _key(str(raw_name))
        upgrade = upgrades.get(name)
        if upgrade is None:
            continue
        matched.add(name)
        target = Version(upgrade.to_version)
        if isinstance(raw_specifier, str):
            value[raw_name] = (
                str(target)
                if pin_exact
                else _updated_poetry_specifier(
                    raw_specifier,
                    target,
                    allow_constraint_changes=allow_constraint_changes,
                )
            )
        elif isinstance(raw_specifier, (InlineTable, Table)):
            current = raw_specifier.get("version")
            if isinstance(current, str):
                raw_specifier["version"] = (
                    str(target)
                    if pin_exact
                    else _updated_poetry_specifier(
                        current,
                        target,
                        allow_constraint_changes=allow_constraint_changes,
                    )
                )


def _updated_poetry_specifier(
    value: str,
    target: Version,
    *,
    allow_constraint_changes: bool,
) -> str:
    stripped = value.strip()
    if stripped in {"", "*"}:
        return f">={target}"
    if stripped.startswith("^"):
        specifier = _poetry_caret_specifier(stripped[1:])
    elif stripped.startswith("~") and not stripped.startswith("~="):
        specifier = _poetry_tilde_specifier(stripped[1:])
    else:
        specifier = stripped
    try:
        requirement = Requirement(f"placeholder{specifier}")
    except InvalidRequirement:
        if allow_constraint_changes:
            return f">={target}"
        raise RemediationError(
            f"unsupported Poetry version constraint {value!r}"
        )
    return _updated_requirement(
        requirement,
        target,
        allow_constraint_changes=allow_constraint_changes,
    ).removeprefix("placeholder")


def _poetry_caret_specifier(value: str) -> str:
    version = Version(value)
    release = list(version.release)
    while len(release) < 3:
        release.append(0)
    if release[0]:
        upper = f"{release[0] + 1}.0.0"
    elif release[1]:
        upper = f"0.{release[1] + 1}.0"
    else:
        upper = f"0.0.{release[2] + 1}"
    return f">={version},<{upper}"


def _poetry_tilde_specifier(value: str) -> str:
    version = Version(value)
    release = list(version.release)
    while len(release) < 2:
        release.append(0)
    upper = f"{release[0] + 1}.0" if len(version.release) == 1 else f"{release[0]}.{release[1] + 1}"
    return f">={version},<{upper}"


def _write_pylock(path: Path, resolution: Resolution) -> None:
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    packages = document.get("packages")
    if not isinstance(packages, AoT):
        raise RemediationError(f"{path.name} does not contain a packages array")
    by_name = {
        _key(item.name): item
        for item in resolution.distributions
    }
    seen: set[str] = set()
    for package in packages:
        raw_name = package.get("name")
        if not isinstance(raw_name, str):
            continue
        name = _key(raw_name)
        distribution = by_name.get(name)
        if distribution is None:
            continue
        seen.add(name)
        package["version"] = distribution.version
        if distribution.index_url is not None:
            package["index"] = distribution.index_url
        if distribution.requires_dist:
            dependencies = tomlkit.array()
            dependencies.multiline(False)
            for raw_requirement in distribution.requires_dist:
                requirement = _parse_requirement(raw_requirement)
                if requirement is None:
                    continue
                dependency = tomlkit.inline_table()
                dependency["name"] = requirement.name
                exact = _exact_pin(requirement)
                if exact is not None:
                    dependency["version"] = str(exact)
                dependencies.append(dependency)
            package["dependencies"] = dependencies
        if distribution.artifacts:
            _replace_pylock_artifacts(package, distribution.artifacts)
    missing = sorted(set(by_name).difference(seen))
    for name in missing:
        distribution = by_name[name]
        if not distribution.artifacts:
            raise RemediationError(
                f"cannot add {distribution.name} to PEP 751 output without "
                "a hashed artifact"
            )
        package = tomlkit.table()
        package["name"] = distribution.name
        package["version"] = distribution.version
        if distribution.index_url is not None:
            package["index"] = distribution.index_url
        if distribution.requires_dist:
            dependencies = tomlkit.array()
            dependencies.multiline(False)
            for raw_requirement in distribution.requires_dist:
                requirement = _parse_requirement(raw_requirement)
                if requirement is None:
                    continue
                dependency = tomlkit.inline_table()
                dependency["name"] = requirement.name
                exact = _exact_pin(requirement)
                if exact is not None:
                    dependency["version"] = str(exact)
                dependencies.append(dependency)
            package["dependencies"] = dependencies
        _replace_pylock_artifacts(package, distribution.artifacts)
        packages.append(package)
    path.write_text(tomlkit.dumps(document), encoding="utf-8", newline="")


def _replace_pylock_artifacts(
    package: Table,
    artifacts: Sequence[ArtifactReference],
) -> None:
    for key in ("wheels", "sdist", "archive"):
        if key in package:
            del package[key]
    wheels = [item for item in artifacts if (item.filename or "").endswith(".whl")]
    non_wheels = [item for item in artifacts if item not in wheels]
    if wheels:
        array = tomlkit.aot()
        for artifact in wheels:
            array.append(_pylock_artifact_table(artifact))
        package["wheels"] = array
    if non_wheels:
        key = "sdist" if len(non_wheels) == 1 else "archive"
        package[key] = _pylock_artifact_table(non_wheels[0])


def _pylock_artifact_table(artifact: ArtifactReference) -> Table:
    if not artifact.hashes:
        raise RemediationError(
            f"artifact {artifact.filename or artifact.url or artifact.path} "
            "has no secure hash"
        )
    table = tomlkit.table()
    if artifact.filename:
        table["name"] = artifact.filename
    if artifact.url:
        table["url"] = artifact.url
    elif artifact.path:
        table["path"] = artifact.path
    else:
        raise RemediationError("PEP 751 artifacts require a URL or path")
    if artifact.size is not None:
        table["size"] = artifact.size
    hashes = tomlkit.inline_table()
    for algorithm, digest in artifact.hashes:
        hashes[algorithm] = digest
    table["hashes"] = hashes
    return table


def _run_pip_compile(
    target: Path,
    *,
    staged_root: Path,
    source_root: Path,
    upgrades: Sequence[RemediationUpgrade],
    commands: list[list[str]],
    runner: CommandRunner,
    timeout: float,
    source_manifest: Path | None,
) -> None:
    source = source_manifest
    if source is None:
        possible = target.with_suffix(".in")
        if possible.is_file():
            source = possible
        elif (staged_root / "pyproject.toml").is_file():
            source = staged_root / "pyproject.toml"
    if source is None or not source.is_file():
        raise RemediationError(
            "hash-pinned requirements require a pip-compile source file; "
            "provide --source-manifest"
        )
    del source_root
    command = [
        "pip-compile",
        str(source),
        "--output-file",
        str(target),
        "--generate-hashes",
    ]
    for upgrade in upgrades:
        command.extend(
            ["--upgrade-package", f"{upgrade.project}=={upgrade.to_version}"]
        )
    commands.append(command)
    _run_command(command, cwd=staged_root, runner=runner, timeout=timeout)


def _run_native_locker(
    kind: str,
    *,
    staged_root: Path,
    upgrades: Sequence[RemediationUpgrade],
    commands: list[list[str]],
    runner: CommandRunner,
    timeout: float,
) -> None:
    if kind == "uv":
        command = ["uv", "lock"]
        for upgrade in upgrades:
            command.extend(
                ["--upgrade-package", f"{upgrade.project}=={upgrade.to_version}"]
            )
    elif kind == "poetry":
        command = [
            "poetry",
            "update",
            *(upgrade.project for upgrade in upgrades),
            "--lock",
        ]
    elif kind == "pdm":
        command = [
            "pdm",
            "update",
            "--no-sync",
            *(f"{upgrade.project}=={upgrade.to_version}" for upgrade in upgrades),
        ]
    else:
        raise RemediationError(f"unsupported native locker: {kind}")
    commands.append(command)
    _run_command(command, cwd=staged_root, runner=runner, timeout=timeout)


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    runner: CommandRunner,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = runner(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemediationError(
            f"unable to run {command[0]!r}: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RemediationError(
            f"{command[0]} exited with status {completed.returncode}: {detail}"
        )
    return completed


def _collect_changed_files(
    source_root: Path,
    staged_root: Path,
) -> dict[Path, bytes]:
    relative_paths = {
        path.relative_to(source_root)
        for path in source_root.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and _is_dependency_file(path)
    }
    relative_paths.update(
        path.relative_to(staged_root)
        for path in staged_root.rglob("*")
        if path.is_file() and _is_dependency_file(path)
    )
    changed: dict[Path, bytes] = {}
    for relative in relative_paths:
        source = source_root / relative
        staged = staged_root / relative
        before = source.read_bytes() if source.is_file() else None
        after = staged.read_bytes() if staged.is_file() else None
        if after is not None and before != after:
            changed[relative] = after
    return changed


def _is_dependency_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        name
        in {
            "pipfile.lock",
            "pdm.lock",
            "poetry.lock",
            "pyproject.toml",
            "uv.lock",
        }
        or re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", name) is not None
        or path.suffix.lower() in {".in", ".txt"}
    )


def _build_file_patches(
    source_root: Path,
    changed_files: Mapping[Path, bytes],
    upgrades: Sequence[RemediationUpgrade],
) -> list[FilePatch]:
    patches: list[FilePatch] = []
    for relative, after in sorted(changed_files.items()):
        source = source_root / relative
        before = source.read_bytes() if source.is_file() else b""
        before_text = before.decode("utf-8", errors="replace").splitlines(
            keepends=True
        )
        after_text = after.decode("utf-8", errors="replace").splitlines(
            keepends=True
        )
        diff = "".join(
            difflib.unified_diff(
                before_text,
                after_text,
                fromfile=f"a/{relative.as_posix()}",
                tofile=f"b/{relative.as_posix()}",
            )
        )
        edits = tuple(
            SemanticEdit(
                path=relative.as_posix(),
                project=upgrade.project,
                from_version=upgrade.from_version,
                to_version=upgrade.to_version,
                kind="dependency-upgrade",
            )
            for upgrade in upgrades
            if _key(upgrade.project)
            in _key(diff)
            or relative.name in {
                "uv.lock",
                "poetry.lock",
                "pdm.lock",
            }
        )
        patches.append(
            FilePatch(
                path=relative.as_posix(),
                before_sha256=_sha256(before),
                after_sha256=_sha256(after),
                diff=diff,
                edits=edits,
            )
        )
    return patches


def _validate_changed_lockfile_hashes(
    source_root: Path,
    staged_root: Path,
    changed_files: Mapping[Path, bytes],
) -> list[LockfileHashValidation]:
    validations: list[LockfileHashValidation] = []
    for relative in sorted(changed_files):
        staged = staged_root / relative
        validations.append(
            _validate_lockfile_hashes(
                staged,
                display_path=relative.as_posix(),
                source_root=source_root,
            )
        )
    return validations


def _validate_lockfile_hashes(
    path: Path,
    *,
    display_path: str,
    source_root: Path,
) -> LockfileHashValidation:
    if is_supported_lockfile(path):
        try:
            locked = load_lockfile(path)
        except ValueError as exc:
            return LockfileHashValidation(
                path=display_path,
                format=path.name.lower(),
                applicable=True,
                valid=False,
                errors=(str(exc),),
            )
        return _lockfile_hash_validation_from_artifacts(
            display_path,
            locked.format,
            [
                artifact
                for package in locked.packages
                for artifact in package.artifacts
            ],
            package_count=len(locked.packages),
        )

    pip_tools = load_pip_tools_lock(path)
    if pip_tools is not None:
        return _lockfile_hash_validation_from_artifacts(
            display_path,
            pip_tools.format,
            [
                artifact
                for package in pip_tools.packages
                for artifact in package.artifacts
            ],
            package_count=len(pip_tools.packages),
        )

    return LockfileHashValidation(
        path=display_path,
        format=_input_kind(source_root / display_path),
        applicable=False,
    )


def _lockfile_hash_validation_from_artifacts(
    path: str,
    lock_format: str,
    artifacts: Sequence[ArtifactReference],
    *,
    package_count: int,
) -> LockfileHashValidation:
    errors: list[str] = []
    hashed = 0
    for index, artifact in enumerate(artifacts, 1):
        if not artifact.hashes:
            errors.append(f"artifact {index} has no recorded hash")
            continue
        artifact_valid = True
        for algorithm, digest in artifact.hashes:
            if not algorithm.strip():
                errors.append(f"artifact {index} has an empty hash algorithm")
                artifact_valid = False
            if re.fullmatch(r"[0-9a-fA-F]{32,}", digest) is None:
                errors.append(
                    f"artifact {index} has an invalid {algorithm or 'hash'} digest"
                )
                artifact_valid = False
        if artifact_valid:
            hashed += 1
    return LockfileHashValidation(
        path=path,
        format=lock_format,
        applicable=True,
        package_count=package_count,
        artifact_count=len(artifacts),
        hashed_artifact_count=hashed,
        valid=not errors,
        errors=tuple(errors),
    )


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stable_json_sha256(payload: object) -> str:
    return _sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _validate_git_identifier(value: str | None, label: str) -> None:
    if value is None:
        return
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value):
        raise RemediationError(f"invalid {label}: {value!r}")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise RemediationError(f"invalid {label}: {value!r}")


def _default_branch_name(upgrades: Sequence[RemediationUpgrade]) -> str:
    if len(upgrades) == 1:
        upgrade = upgrades[0]
        slug = _key(upgrade.project)
        version = re.sub(r"[^A-Za-z0-9._-]", "-", upgrade.to_version)
        return f"trustcheck/fix-{slug}-{version}"
    digest = hashlib.sha256(
        "\n".join(
            f"{item.project}=={item.to_version}" for item in upgrades
        ).encode()
    ).hexdigest()[:10]
    return f"trustcheck/fix-dependencies-{digest}"


def _default_pr_title(upgrades: Sequence[RemediationUpgrade]) -> str:
    if len(upgrades) == 1:
        item = upgrades[0]
        return f"Fix {item.project} vulnerabilities by upgrading to {item.to_version}"
    return f"Fix vulnerabilities in {len(upgrades)} Python dependencies"


def _pull_request_body(plan: RemediationPlan) -> str:
    rows = "\n".join(
        f"| `{item.project}` | `{item.from_version}` | `{item.to_version}` | "
        f"{', '.join(f'`{identifier}`' for identifier in item.advisory_ids)} |"
        for item in plan.upgrades
    )
    return "\n".join(
        [
            "## Trustcheck remediation",
            "",
            "| Package | Before | After | Advisories |",
            "| --- | --- | --- | --- |",
            rows,
            "",
            "The dependency graph was re-resolved and rescanned before this "
            "patch was created.",
        ]
    )
