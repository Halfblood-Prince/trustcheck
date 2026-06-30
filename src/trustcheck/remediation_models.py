from __future__ import annotations

import json
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final, Literal

from packaging.utils import canonicalize_name

from .models import TrustReport
from .resolver import Resolution, ResolvedDistribution

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

