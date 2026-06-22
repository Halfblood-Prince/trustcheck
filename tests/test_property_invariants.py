from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings
from hypothesis import strategies as st
from packaging.version import Version

from trustcheck.indexes import IndexProject, SimpleRepositoryClient
from trustcheck.models import (
    CoverageSummary,
    FileProvenance,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from trustcheck.policy import PolicySettings, _apply_suppressions, evaluate_policy
from trustcheck.remediation import (
    _candidate_objective,
    _lockfile_hash_validation_from_artifacts,
    _root_allows_any_candidate,
)
from trustcheck.resolver import ArtifactReference, Resolution, ResolvedDistribution


@settings(deadline=None)
@given(
    lower=st.integers(min_value=0, max_value=50),
    width=st.integers(min_value=1, max_value=20),
    candidate=st.integers(min_value=0, max_value=70),
)
def test_vulnerability_candidate_range_boundaries(
    lower: int,
    width: int,
    candidate: int,
) -> None:
    upper = lower + width
    allowed = _root_allows_any_candidate(
        [f"demo>={lower},<{upper}"],
        "demo",
        [Version(str(candidate))],
        allow_constraint_changes=False,
    )

    assert allowed is (lower <= candidate < upper)


@settings(deadline=None)
@given(days_from_today=st.integers(min_value=-10, max_value=10))
def test_suppression_expiry_changes_only_after_expiry_day(
    days_from_today: int,
) -> None:
    now = datetime(2030, 1, 15, 12, tzinfo=timezone.utc)
    expiry = (now.date() + timedelta(days=days_from_today)).isoformat()
    vulnerability = VulnerabilityRecord(id="CVE-2030-1", summary="example")
    suppression = VulnerabilitySuppression(
        vulnerability_id="cve-2030-1",
        owner="security@example.com",
        justification="property test",
        expires=expiry,
    )

    applied, expired = _apply_suppressions(
        [vulnerability],
        [suppression],
        now=now,
    )

    assert (applied, expired) == ((1, 0) if days_from_today >= 0 else (0, 1))
    assert vulnerability.suppression is not None
    assert vulnerability.suppression.status == (
        "active" if days_from_today >= 0 else "expired"
    )


@settings(deadline=None)
@given(first=st.booleans(), second=st.booleans())
def test_dependency_confusion_requires_multiple_matching_indexes(
    first: bool,
    second: bool,
) -> None:
    indexes = ("https://one.example/simple", "https://two.example/simple")

    class Repository(SimpleRepositoryClient):
        def get_project(self, index_url: str, project: str) -> IndexProject | None:
            present = first if index_url == indexes[0] else second
            return (
                IndexProject(name=project, index_url=index_url)
                if present
                else None
            )

    findings = Repository().find_dependency_confusion(["Demo"], indexes)

    assert bool(findings) is (first and second)


@settings(deadline=None)
@given(verified=st.lists(st.booleans(), min_size=1, max_size=8))
def test_provenance_policy_requires_every_artifact(verified: list[bool]) -> None:
    report = TrustReport(
        project="demo",
        version="1.0",
        summary="property test",
        package_url="https://example.test/demo",
        files=[
            FileProvenance(
                filename=f"demo-{index}.whl",
                url=f"https://example.test/demo-{index}.whl",
                sha256=None,
                has_provenance=value,
                verified=value,
            )
            for index, value in enumerate(verified)
        ],
        coverage=CoverageSummary(
            total_files=len(verified),
            files_with_provenance=sum(verified),
            verified_files=sum(verified),
            status="verified" if all(verified) else "partial",
        ),
        recommendation="verified",
    )

    evaluation = evaluate_policy(
        report,
        PolicySettings(
            require_verified_provenance="all",
            allow_metadata_only=True,
        ),
    )

    assert evaluation.passed is all(verified)


@settings(deadline=None)
@given(changed=st.lists(st.booleans(), min_size=1, max_size=10))
def test_remediation_objective_counts_exact_changes(changed: list[bool]) -> None:
    baseline = Resolution(
        distributions=[
            ResolvedDistribution(name=f"package-{index}", version="1")
            for index in range(len(changed))
        ]
    )
    candidate = Resolution(
        distributions=[
            ResolvedDistribution(
                name=f"package-{index}",
                version="2" if value else "1",
            )
            for index, value in enumerate(changed)
        ]
    )
    direct = {f"package-{index}" for index in range(0, len(changed), 2)}

    total, direct_total, _ = _candidate_objective(
        baseline,
        candidate,
        [Version("2")],
        direct_names=direct,
    )

    assert total == sum(changed)
    assert direct_total == sum(value for index, value in enumerate(changed) if index % 2 == 0)


@settings(deadline=None)
@given(valid_hashes=st.lists(st.booleans(), min_size=1, max_size=10))
def test_lockfile_hash_validation_preserves_every_artifact_hash(
    valid_hashes: list[bool],
) -> None:
    artifacts = [
        ArtifactReference(
            filename=f"artifact-{index}.whl",
            url=f"https://example.test/artifact-{index}.whl",
            hashes=(("sha256", f"{index:064x}"),) if valid else (),
        )
        for index, valid in enumerate(valid_hashes)
    ]

    validation = _lockfile_hash_validation_from_artifacts(
        "requirements.txt",
        "pip-tools",
        artifacts,
        package_count=len(artifacts),
    )

    assert validation.valid is all(valid_hashes)
    assert validation.hashed_artifact_count == sum(valid_hashes)
