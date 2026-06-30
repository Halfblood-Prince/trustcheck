from __future__ import annotations

from dataclasses import dataclass, field

from .resolver import ArtifactReference

EXIT_OK = 0
EXIT_UPSTREAM_FAILURE = 1
EXIT_USAGE = 2
EXIT_DATA_ERROR = 3
EXIT_POLICY_FAILURE = 4
EXIT_REMEDIATION_FAILURE = 5


@dataclass(slots=True)
class ScanTarget:
    requirement: str
    project: str
    version: str | None = None
    failure_message: str | None = None
    failure_exit_code: int = EXIT_OK
    locked_versions: dict[str, str] = field(default_factory=dict)
    complete_locked_versions: bool = False
    source_url: str | None = None
    requested: bool = True
    editable: bool = False
    vcs: str | None = None
    vcs_commit: str | None = None
    artifacts: tuple[ArtifactReference, ...] = ()
    index_url: str | None = None
    requires_dist: tuple[str, ...] = ()
    dependency_confusion: tuple[str, ...] = ()
    source_file: str | None = None
    source_line: int | None = None
    source_type: str = "index"
