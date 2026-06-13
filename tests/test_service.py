from __future__ import annotations

import hashlib
import unittest
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from packaging.requirements import Requirement
from test_artifacts import build_wheel

from trustcheck.attestations import VerificationError
from trustcheck.models import (
    DependencyInspection,
    FileProvenance,
    PolicyViolation,
    RiskFlag,
    TrustReport,
)
from trustcheck.policy import advisory_evaluation_for
from trustcheck.pypi import PypiClientError
from trustcheck.resolver import (
    ArtifactReference,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
)
from trustcheck.service import (
    DiagnosticsCollector,
    _build_dependency_summary,
    _build_publisher_trust_summary,
    _instrument_client,
    _load_package_history,
    _normalize_repo_url,
    _previous_release_version,
    _publisher_repository_url,
    _select_dependency_version,
    inspect_package,
)

AttestationFn = Callable[[object, object], tuple[str, object | None] | None]


def make_project_payload(
    *,
    version: str = "2.2.0",
    project_urls: dict[str, str] | None = None,
    urls: list[dict[str, object]] | None = None,
    vulnerabilities: list[dict[str, object]] | None = None,
    releases: dict[str, list[dict[str, object]]] | None = None,
    requires_dist: list[str] | None = None,
) -> dict[str, object]:
    return {
        "info": {
            "version": version,
            "summary": "gridoptim package",
            "project_urls": project_urls
            if project_urls is not None
            else {
                "Homepage": "https://github.com/Halfblood-Prince/gridoptim",
                "Documentation": "https://docs.example.com/gridoptim",
            },
            "ownership": {
                "organization": "Halfblood-Prince",
                "roles": [{"role": "Owner", "user": "Halfblood-Prince"}],
            },
            "requires_dist": requires_dist,
        },
        "urls": urls
        if urls is not None
        else [
            {
                "filename": "gridoptim-2.2.0-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                "digests": {"sha256": "abc123"},
            }
        ],
        "releases": releases or {version: []},
        "vulnerabilities": vulnerabilities or [],
    }


def make_publisher(
    *,
    kind: str = "GitHub",
    repository: str = "Halfblood-Prince/gridoptim",
    workflow: str = "release.yml",
    environment: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        kind=kind,
        repository=repository,
        workflow=workflow,
        workflow_filepath=workflow,
        environment=environment,
        model_dump=lambda: {
            "kind": kind,
            "repository": repository,
            "workflow": workflow,
            "workflow_filepath": workflow,
            "environment": environment,
        },
    )


def make_attestation(
    verify_impl: AttestationFn | None = None,
) -> SimpleNamespace:
    attestation = SimpleNamespace()
    attestation.verify = verify_impl or (
        lambda identity, dist: (
            "https://docs.pypi.org/attestations/publish/v1",
            None,
        )
    )
    return attestation


def make_provenance(
    *,
    publisher: SimpleNamespace | None = None,
    attestations: list[SimpleNamespace] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        attestation_bundles=[
            SimpleNamespace(
                publisher=publisher or make_publisher(),
                attestations=attestations or [make_attestation()],
            )
        ]
    )


class FakeClient:
    def __init__(
        self,
        *,
        project_payload: dict[str, object] | None = None,
        release_payload: dict[str, object] | None = None,
        release_payloads: dict[str, dict[str, object]] | None = None,
        provenance_payload: dict[str, object] | None = None,
        download_map: dict[str, bytes] | None = None,
        project_error: Exception | None = None,
        release_error: Exception | None = None,
        provenance_errors: dict[str, Exception] | None = None,
    ) -> None:
        self.project_payload = project_payload or make_project_payload()
        self.release_payload = release_payload or make_project_payload()
        self.release_payloads = release_payloads or {}
        self.provenance_payload = provenance_payload or {
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "GitHub",
                        "repository": "Halfblood-Prince/gridoptim",
                        "workflow": "release.yml",
                    },
                    "attestations": [{"kind": "publish"}],
                }
            ]
        }
        self.download_map = download_map or {
            "https://files.pythonhosted.org/packages/gridoptim.whl": b"gridoptim-wheel",
        }
        self.project_error = project_error
        self.release_error = release_error
        self.provenance_errors = provenance_errors or {}

    def get_project(self, project: str) -> dict[str, object]:
        if self.project_error is not None:
            raise self.project_error
        if project in self.release_payloads:
            return self.release_payloads[project]
        assert project == "gridoptim"
        return self.project_payload

    def get_release(self, project: str, version: str) -> dict[str, object]:
        if self.release_error is not None:
            raise self.release_error
        if project in self.release_payloads:
            return self.release_payloads[project]
        assert project == "gridoptim"
        if version in self.release_payloads:
            return self.release_payloads[version]
        return self.release_payload

    def get_provenance(
        self,
        project: str,
        version: str,
        filename: str,
    ) -> dict[str, object]:
        assert project == "gridoptim"
        assert version
        if filename in self.provenance_errors:
            raise self.provenance_errors[filename]
        return self.provenance_payload

    def download_distribution(self, url: str) -> bytes:
        return self.download_map[url]


class LockedDependencyClient:
    def __init__(self) -> None:
        self.request_hook = None
        self.release_calls: list[tuple[str, str]] = []
        self.root_payload = make_project_payload(
            requires_dist=["depalpha>=1.0"],
            releases={"2.2.0": []},
            urls=[],
        )
        self.project_payloads = {
            "depalpha": make_project_payload(
                version="1.9.0",
                requires_dist=["depbeta>=2.0"],
                releases={"1.4.0": [], "1.9.0": []},
                urls=[],
            ),
            "depbeta": make_project_payload(
                version="2.9.0",
                requires_dist=[],
                releases={"2.5.0": [], "2.9.0": []},
                urls=[],
            ),
        }
        self.release_payloads = {
            ("depalpha", "1.4.0"): make_project_payload(
                version="1.4.0",
                requires_dist=["depbeta>=2.0"],
                releases={"1.4.0": []},
                urls=[],
            ),
            ("depbeta", "2.5.0"): make_project_payload(
                version="2.5.0",
                requires_dist=[],
                releases={"2.5.0": []},
                urls=[],
            ),
        }

    def get_project(self, project: str) -> dict[str, object]:
        if project == "gridoptim":
            return self.root_payload
        return self.project_payloads[project]

    def get_release(self, project: str, version: str) -> dict[str, object]:
        self.release_calls.append((project, version))
        return self.release_payloads[(project, version)]


class FakeOsvClient:
    def __init__(self, responses: dict[tuple[str, str], list[dict[str, object]]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []
        self.request_hook = None

    def query(self, project: str, version: str) -> list[dict[str, object]]:
        self.calls.append((project, version))
        return self.responses.get((project, version), [])


class ServiceBranchTests(unittest.TestCase):
    def test_diagnostics_collect_request_and_artifact_failures(self) -> None:
        diagnostics = DiagnosticsCollector()
        diagnostics.on_request_event("request", {})
        diagnostics.on_request_event("retry", {})
        diagnostics.on_request_event("cache_hit", {})
        diagnostics.on_request_event(
            "failure",
            {
                "url": "https://pypi.org/example",
                "attempt": 2,
                "code": "upstream",
                "subcode": "http_error",
                "message": "unavailable",
                "transient": True,
                "status_code": 503,
            },
        )
        diagnostics.add_artifact_failure(
            filename="example.whl",
            stage="verification",
            code="verification",
            subcode="failed",
            message="bad signature",
        )
        report = diagnostics.to_report_diagnostics(
            cast(
                Any,
                SimpleNamespace(
                    timeout=3,
                    max_retries=4,
                    backoff_factor=0.5,
                    offline=True,
                    cache_dir="cache",
                ),
            )
        )

        self.assertEqual(
            (report.request_count, report.retry_count, report.cache_hit_count),
            (1, 1, 1),
        )
        self.assertEqual(report.request_failures[0].status_code, 503)
        self.assertEqual(report.artifact_failures[0].filename, "example.whl")

    def test_instrument_client_preserves_existing_hook(self) -> None:
        events: list[tuple[str, str]] = []

        def previous(event: str, payload: dict[str, object]) -> None:
            del payload
            events.append(("previous", event))

        client = SimpleNamespace(request_hook=previous)

        with _instrument_client(
            client,
            lambda event, payload: events.append(("collector", event)),
        ):
            client.request_hook("request", {})

        self.assertIs(client.request_hook, previous)
        self.assertEqual(
            events,
            [("collector", "request"), ("previous", "request")],
        )

    def test_dependency_version_selection_skips_invalid_versions_and_uses_fallback(self) -> None:
        self.assertEqual(
            _select_dependency_version(
                {
                    "info": {"version": "1.5.0"},
                    "releases": {
                        "not-a-version": [],
                        "0.5.0": [],
                        "1.2.0": [],
                    },
                },
                Requirement("example>=1"),
            ),
            "1.2.0",
        )
        self.assertEqual(
            _select_dependency_version(
                {"info": {"version": "2.0.0"}, "releases": []},
                Requirement("example>=1"),
            ),
            "2.0.0",
        )
        with self.assertRaisesRegex(PypiClientError, "compatible version"):
            _select_dependency_version(
                {"info": {"version": "invalid"}, "releases": {}},
                Requirement("example>=1"),
            )

    def test_dependency_summary_groups_equal_and_unknown_recommendations(self) -> None:
        summary = _build_dependency_summary(
            ["one", "two", "three"],
            [
                DependencyInspection("one", "one", "1", 1, recommendation="verified"),
                DependencyInspection(
                    "two",
                    "two",
                    "1",
                    2,
                    recommendation="review-required",
                ),
                DependencyInspection(
                    "three",
                    "three",
                    "1",
                    2,
                    recommendation="review-required",
                ),
            ],
            requested=True,
        )

        self.assertEqual(summary.total_inspected, 3)
        self.assertEqual(summary.max_depth, 2)
        self.assertEqual(summary.highest_risk_recommendation, "review-required")
        self.assertEqual(summary.highest_risk_projects, ["three", "two"])
        self.assertEqual(summary.verified_projects, ["one"])

    def test_invalid_dependency_requirement_is_reported(self) -> None:
        report = inspect_package(
            "gridoptim",
            client=cast(
                Any,
                FakeClient(
                    project_payload=make_project_payload(
                        requires_dist=["not a valid requirement ???"],
                        urls=[],
                    )
                ),
            ),
            include_dependencies=True,
            locked_versions={"gridoptim": "2.2.0"},
        )

        self.assertEqual(report.dependencies[0].recommendation, "high-risk")
        self.assertIn("invalid dependency requirement", report.dependencies[0].error or "")

    def test_artifact_download_failure_records_both_stages(self) -> None:
        class DownloadFailingClient(FakeClient):
            def download_distribution(self, url: str) -> bytes:
                raise PypiClientError(
                    "download failed",
                    code="upstream",
                    subcode="download_error",
                )

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance()
            report = inspect_package(
                "gridoptim",
                client=cast(Any, DownloadFailingClient()),
                inspect_artifacts=True,
            )

        artifact = report.files[0].artifact
        self.assertTrue(artifact.inspected)
        self.assertEqual(artifact.kind, "wheel")
        self.assertEqual(report.files[0].error, "download failed")
        self.assertEqual(
            [failure.stage for failure in report.diagnostics.artifact_failures],
            ["artifact-download", "provenance-fetch"],
        )


class InspectPackageTests(unittest.TestCase):
    def test_dependency_inspection_uses_complete_resolver_result(self) -> None:
        class FakeResolver:
            def __init__(self) -> None:
                self.calls: list[tuple[list[str], TargetEnvironment | None, bool]] = []

            def resolve_requirements(
                self,
                requirements,
                *,
                target=None,
                offline=False,
            ):
                self.calls.append((list(requirements), target, offline))
                return Resolution(
                    distributions=[
                        ResolvedDistribution("gridoptim", "2.2.0", requested=True),
                        ResolvedDistribution("depalpha", "1.4.0"),
                        ResolvedDistribution("depbeta", "2.5.0"),
                    ]
                )

        root_payload = make_project_payload(
            requires_dist=["depalpha>=1", "excluded>=1"],
        )
        client = FakeClient(
            project_payload=root_payload,
            release_payload=root_payload,
            release_payloads={
                "depalpha": make_project_payload(
                    version="1.4.0",
                    requires_dist=["depbeta>=2"],
                    urls=[],
                ),
                "depbeta": make_project_payload(version="2.5.0", urls=[]),
            },
        )
        resolver = FakeResolver()
        target = TargetEnvironment(python_version="3.12")

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_transitive_dependencies=True,
            resolver=cast(Any, resolver),
            target_environment=target,
        )

        self.assertEqual(
            [(item.project, item.version) for item in report.dependencies],
            [("depalpha", "1.4.0"), ("depbeta", "2.5.0")],
        )
        self.assertEqual(resolver.calls, [(["gridoptim"], target, False)])

    def test_dependency_resolver_failures_are_reported_as_dependency_errors(self) -> None:
        class FailingResolver:
            def resolve_requirements(self, requirements, **kwargs):
                del requirements, kwargs
                raise ResolutionError("conflicting requirements")

        with self.assertRaisesRegex(PypiClientError, "conflicting requirements") as caught:
            inspect_package(
                "gridoptim",
                client=cast(Any, FakeClient()),
                include_dependencies=True,
                resolver=cast(Any, FailingResolver()),
            )
        self.assertEqual(caught.exception.code, "dependency")
        self.assertEqual(caught.exception.subcode, "resolution_failed")

        class MissingRootResolver:
            def resolve_requirements(self, requirements, **kwargs):
                del requirements, kwargs
                return Resolution(
                    distributions=[ResolvedDistribution("dependency", "1.0")]
                )

        with self.assertRaisesRegex(PypiClientError, "root package") as caught:
            inspect_package(
                "gridoptim",
                client=cast(Any, FakeClient()),
                include_dependencies=True,
                resolver=cast(Any, MissingRootResolver()),
            )
        self.assertEqual(caught.exception.subcode, "root_missing")

    def test_complete_resolution_skips_absent_and_duplicate_dependencies(self) -> None:
        root_payload = make_project_payload(
            requires_dist=[
                "depalpha>=1",
                "depalpha>=1",
                "excluded>=1",
            ],
            urls=[],
        )
        client = FakeClient(
            project_payload=root_payload,
            release_payload=root_payload,
            release_payloads={
                "depalpha": make_project_payload(version="1.4.0", urls=[]),
            },
        )
        report = inspect_package(
            "gridoptim",
            version="2.2.0",
            client=cast(Any, client),
            include_dependencies=True,
            locked_versions={"depalpha": "1.4.0"},
            complete_locked_versions=True,
        )
        self.assertEqual(
            [(item.project, item.version) for item in report.dependencies],
            [("depalpha", "1.4.0")],
        )

    def test_legacy_partial_versions_still_apply_inactive_markers(self) -> None:
        root_payload = make_project_payload(
            requires_dist=["skipme>=1; python_version < '3.0'"],
            urls=[],
        )
        report = inspect_package(
            "gridoptim",
            client=cast(
                Any,
                FakeClient(
                    project_payload=root_payload,
                    release_payload=root_payload,
                ),
            ),
            include_dependencies=True,
            locked_versions={"gridoptim": "2.2.0"},
        )
        self.assertEqual(report.dependencies, [])

    def test_dependency_progress_tracks_resolved_artifacts(self) -> None:
        class DependencyArtifactClient(FakeClient):
            def get_provenance(
                self,
                project: str,
                version: str,
                filename: str,
            ) -> dict[str, object]:
                del project, version, filename
                return self.provenance_payload

        root_payload = make_project_payload(
            requires_dist=["depalpha>=1"],
            urls=[],
        )
        dependency_payload = make_project_payload(
            version="1.4.0",
            urls=[
                {
                    "filename": "depalpha-1.4.0-py3-none-any.whl",
                    "url": "https://files.example/depalpha.whl",
                    "digests": {"sha256": "abc123"},
                }
            ],
        )
        client = DependencyArtifactClient(
            project_payload=root_payload,
            release_payload=root_payload,
            release_payloads={"depalpha": dependency_payload},
            download_map={"https://files.example/depalpha.whl": b"dependency"},
        )
        progress_events: list[tuple[str, int, int, bool]] = []
        with (
            patch("trustcheck.service.Provenance") as provenance_model,
            patch("trustcheck.service.hashlib.sha256") as sha256,
        ):
            provenance_model.model_validate.return_value = make_provenance()
            sha256.return_value.hexdigest.return_value = "abc123"
            inspect_package(
                "gridoptim",
                client=cast(Any, client),
                include_dependencies=True,
                locked_versions={"depalpha": "1.4.0"},
                complete_locked_versions=True,
                dependency_progress_callback=lambda *event: progress_events.append(
                    cast(tuple[str, int, int, bool], event)
                ),
            )
        self.assertEqual(
            progress_events,
            [
                ("depalpha", 1, 0, False),
                ("depalpha", 1, 100, True),
            ],
        )

    def test_artifact_diagnostics_cover_invalid_archives_and_sdist_downloads(self) -> None:
        invalid_archive_client = FakeClient(
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"not-a-zip"
            }
        )
        report = inspect_package(
            "gridoptim",
            client=cast(Any, invalid_archive_client),
            inspect_artifacts=True,
        )
        self.assertIn(
            "artifact-inspection",
            {item.stage for item in report.diagnostics.artifact_failures},
        )

        class DownloadFailingClient(FakeClient):
            def download_distribution(self, url: str) -> bytes:
                del url
                raise PypiClientError("download failed")

        sdist_payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.example/gridoptim.tar.gz",
                    "digests": {"sha256": "abc123"},
                }
            ]
        )
        report = inspect_package(
            "gridoptim",
            client=cast(
                Any,
                DownloadFailingClient(
                    project_payload=sdist_payload,
                ),
            ),
            inspect_artifacts=True,
        )
        self.assertEqual(report.files[0].artifact.kind, "sdist")

    def test_empty_attestation_bundle_is_a_verification_failure(self) -> None:
        provenance = SimpleNamespace(
            attestation_bundles=[
                SimpleNamespace(
                    publisher=make_publisher(),
                    attestations=[],
                )
            ]
        )
        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            report = inspect_package(
                "gridoptim",
                client=cast(
                    Any,
                    FakeClient(
                        project_payload=make_project_payload(
                            urls=[
                                {
                                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                                    "url": (
                                        "https://files.pythonhosted.org/packages/"
                                        "gridoptim.whl"
                                    ),
                                    "digests": {},
                                }
                            ]
                        )
                    ),
                ),
            )
        self.assertIn("no attestations", report.files[0].error or "")

    def test_inspect_package_happy_path(self) -> None:
        provenance = make_provenance()
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package(
                    "gridoptim",
                    expected_repository="https://github.com/Halfblood-Prince/gridoptim",
                    client=cast(Any, client),
                )

        self.assertEqual(report.project, "gridoptim")
        self.assertEqual(report.version, "2.2.0")
        self.assertEqual(report.recommendation, "verified")
        self.assertEqual(
            report.declared_repository_urls,
            ["https://github.com/halfblood-prince/gridoptim"],
        )
        self.assertEqual(report.repository_urls, report.declared_repository_urls)
        self.assertTrue(report.files[0].has_provenance)
        self.assertTrue(report.files[0].verified)
        self.assertEqual(report.files[0].verified_attestation_count, 1)
        self.assertEqual(report.coverage.status, "all-verified")
        self.assertEqual(report.publisher_trust.depth_label, "strong")
        self.assertEqual(
            report.files[0].publisher_identities[0].repository,
            "https://github.com/halfblood-prince/gridoptim",
        )
        self.assertEqual(report.risk_flags, [])

    def test_artifact_inspection_flags_tampered_wheel_record(self) -> None:
        wheel = build_wheel(
            project="gridoptim",
            version="2.2.0",
            tamper_module_after_record=True,
        )
        url = "https://files.pythonhosted.org/packages/gridoptim.whl"
        payload = make_project_payload(
            requires_dist=["packaging>=24"],
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": url,
                    "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
                }
            ]
        )
        client = FakeClient(project_payload=payload, download_map={url: wheel})

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance()
            report = inspect_package(
                "gridoptim",
                client=cast(Any, client),
                inspect_artifacts=True,
            )

        self.assertTrue(report.files[0].verified)
        self.assertFalse(report.files[0].artifact.record_valid)
        self.assertIn("wheel_record_invalid", {flag.code for flag in report.risk_flags})
        self.assertEqual(report.recommendation, "high-risk")

    def test_malicious_package_heuristics_affect_risk_recommendation(self) -> None:
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance()
            report = inspect_package(
                "gridoptim",
                client=cast(Any, client),
                dependency_confusion_indexes=(
                    "https://pypi.org/simple",
                    "https://packages.example/simple",
                ),
                trusted_projects=("gridoptimm",),
            )

        codes = {finding.code for finding in report.malicious_package.findings}
        self.assertIn("dependency_confusion_index_collision", codes)
        self.assertIn("typosquatting_name_similarity", codes)
        self.assertGreaterEqual(report.malicious_package.score, 75)
        self.assertIn(
            "malicious_package_heuristics",
            {flag.code for flag in report.risk_flags},
        )
        self.assertEqual(report.recommendation, "high-risk")

    def test_native_artifact_is_review_required_not_high_risk(self) -> None:
        wheel = build_wheel(
            project="gridoptim",
            version="2.2.0",
            native_file=True,
        )
        url = "https://files.pythonhosted.org/packages/gridoptim.whl"
        payload = make_project_payload(
            requires_dist=["packaging>=24"],
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": url,
                    "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
                }
            ]
        )
        client = FakeClient(project_payload=payload, download_map={url: wheel})

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance()
            report = inspect_package(
                "gridoptim",
                client=cast(Any, client),
                inspect_artifacts=True,
            )

        native_flag = next(
            flag
            for flag in report.risk_flags
            if flag.code == "artifact_contains_native_code"
        )
        self.assertEqual(native_flag.severity, "medium")
        self.assertEqual(report.recommendation, "review-required")
        self.assertNotIn(
            "high",
            {flag.severity for flag in report.risk_flags},
        )

    def test_project_lookup_failure_bubbles_up(self) -> None:
        client = FakeClient(project_error=PypiClientError("unable to reach PyPI: timed out"))

        with self.assertRaisesRegex(PypiClientError, "timed out"):
            inspect_package("gridoptim", client=cast(Any, client))

    def test_release_lookup_failure_bubbles_up(self) -> None:
        client = FakeClient(release_error=PypiClientError("resource not found"))

        with self.assertRaisesRegex(PypiClientError, "resource not found"):
            inspect_package("gridoptim", version="9.9.9", client=cast(Any, client))

    def test_provenance_404_marks_file_as_unverified(self) -> None:
        payload = make_project_payload()
        client = FakeClient(
            project_payload=payload,
            provenance_errors={
                "gridoptim-2.2.0-py3-none-any.whl": PypiClientError("resource not found")
            },
        )

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.files[0].error, "resource not found")
        self.assertIn("no_provenance", {flag.code for flag in report.risk_flags})
        self.assertEqual(report.recommendation, "review-required")

    def test_provenance_transient_failure_marks_file_as_unverified(self) -> None:
        payload = make_project_payload()
        client = FakeClient(
            project_payload=payload,
            provenance_errors={
                "gridoptim-2.2.0-py3-none-any.whl": PypiClientError(
                    "PyPI returned HTTP 503 for provenance"
                )
            },
        )

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.files[0].error, "PyPI returned HTTP 503 for provenance")
        self.assertIn(
            "provenance_verification_failed",
            {flag.code for flag in report.risk_flags},
        )

    def test_malformed_provenance_payload_is_reported(self) -> None:
        client = FakeClient(provenance_payload={"oops": []})

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("attestation verification failed", report.files[0].error)

    def test_missing_project_fields_fall_back_cleanly(self) -> None:
        client = FakeClient(project_payload={"urls": [], "vulnerabilities": []})

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.version, "unknown")
        self.assertIsNone(report.summary)
        self.assertEqual(report.declared_repository_urls, [])
        self.assertEqual(report.files, [])
        self.assertEqual(report.recommendation, "review-required")

    def test_multiple_files_per_release_are_all_collected(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"wheel",
                "https://files.pythonhosted.org/packages/gridoptim.tar.gz": b"sdist",
            },
        )
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.side_effect = [
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                    SimpleNamespace(hexdigest=lambda: "def456"),
                ]
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual([file.filename for file in report.files], payload["urls"][0:2][0:2] and [
            "gridoptim-2.2.0-py3-none-any.whl",
            "gridoptim-2.2.0.tar.gz",
        ])
        self.assertTrue(all(file.verified for file in report.files))

    def test_inspect_package_reports_progress_for_each_primary_artifact(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ],
            releases={"2.1.0": [], "2.2.0": []},
        )
        previous_payload = make_project_payload(version="2.1.0")
        client = FakeClient(
            project_payload=payload,
            release_payloads={
                "2.1.0": previous_payload,
                "2.2.0": payload,
            },
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"wheel",
                "https://files.pythonhosted.org/packages/gridoptim.tar.gz": b"sdist",
            },
        )
        provenance = make_provenance()
        progress_events: list[tuple[str, int, int]] = []

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.side_effect = [
                provenance,
                provenance,
                provenance,
            ]
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.side_effect = [
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                    SimpleNamespace(hexdigest=lambda: "def456"),
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                ]
                inspect_package(
                    "gridoptim",
                    version="2.2.0",
                    client=cast(Any, client),
                    progress_callback=lambda filename, current, total: progress_events.append(
                        (filename, current, total)
                    ),
                )

        self.assertEqual(
            progress_events,
            [
                ("gridoptim-2.2.0-py3-none-any.whl", 1, 2),
                ("gridoptim-2.2.0.tar.gz", 2, 2),
            ],
        )

    def test_partial_provenance_coverage_is_high_risk(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"wheel",
                "https://files.pythonhosted.org/packages/gridoptim.tar.gz": b"sdist",
            },
            provenance_errors={"gridoptim-2.2.0.tar.gz": PypiClientError("resource not found")},
        )
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertTrue(report.files[0].verified)
        self.assertFalse(report.files[1].verified)
        self.assertEqual(report.recommendation, "high-risk")
        self.assertEqual(report.files[1].error, "resource not found")
        self.assertEqual(report.coverage.status, "partial")
        self.assertIn("partial_provenance_coverage", {flag.code for flag in report.risk_flags})

    def test_sdist_and_wheel_provenance_consistency_is_reported(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"wheel",
                "https://files.pythonhosted.org/packages/gridoptim.tar.gz": b"sdist",
            },
        )
        provenance = make_provenance(
            publisher=make_publisher(
                repository="Halfblood-Prince/gridoptim",
                workflow="release.yml",
            )
        )

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.side_effect = [
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                    SimpleNamespace(hexdigest=lambda: "def456"),
                ]
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertTrue(report.provenance_consistency.sdist_wheel_consistent)
        self.assertEqual(
            report.provenance_consistency.consistent_repositories,
            ["https://github.com/halfblood-prince/gridoptim"],
        )

    def test_sdist_and_wheel_provenance_mismatch_is_flagged(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "gridoptim-2.2.0-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "gridoptim-2.2.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/gridoptim.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/gridoptim.whl": b"wheel",
                "https://files.pythonhosted.org/packages/gridoptim.tar.gz": b"sdist",
            },
        )
        provenance_model_results = [
            make_provenance(
                publisher=make_publisher(
                    repository="Halfblood-Prince/gridoptim",
                    workflow="release.yml",
                )
            ),
            make_provenance(
                publisher=make_publisher(
                    repository="other/gridoptim",
                    workflow="release.yml",
                )
            ),
        ]

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.side_effect = provenance_model_results
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.side_effect = [
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                    SimpleNamespace(hexdigest=lambda: "def456"),
                ]
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertFalse(report.provenance_consistency.sdist_wheel_consistent)
        self.assertIn(
            "sdist_wheel_provenance_mismatch",
            {flag.code for flag in report.risk_flags},
        )

    def test_release_drift_is_reported_against_previous_version(self) -> None:
        current_payload = make_project_payload(
            version="2.2.0",
            releases={"2.1.0": [], "2.2.0": []},
        )
        previous_release_payload = make_project_payload(version="2.1.0")
        client = FakeClient(
            project_payload=current_payload,
            release_payloads={
                "2.1.0": previous_release_payload,
                "2.2.0": current_payload,
            },
        )
        current_provenance = make_provenance(
            publisher=make_publisher(
                repository="Halfblood-Prince/gridoptim",
                workflow="release.yml",
            )
        )
        previous_provenance = make_provenance(
            publisher=make_publisher(
                repository="Halfblood-Prince/gridoptim-legacy",
                workflow="old-release.yml",
            )
        )

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.side_effect = [
                current_provenance,
                previous_provenance,
            ]
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.side_effect = [
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                    SimpleNamespace(hexdigest=lambda: "abc123"),
                ]
                report = inspect_package(
                    "gridoptim",
                    version="2.2.0",
                    client=cast(Any, client),
                )

        self.assertEqual(report.release_drift.compared_to_version, "2.1.0")
        self.assertTrue(report.release_drift.publisher_repository_drift)
        self.assertTrue(report.release_drift.publisher_workflow_drift)
        self.assertIn("publisher_repository_drift", {flag.code for flag in report.risk_flags})

    def test_vulnerability_parsing_uses_fallbacks(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                vulnerabilities=[
                    {
                        "details": "Detailed advisory text",
                        "aliases": None,
                        "fixed_in": None,
                    },
                    {
                        "id": "PYSEC-1",
                        "summary": "Specific summary",
                        "aliases": ["CVE-2026-0001"],
                        "source": "PyPI",
                        "fixed_in": ["2.0.0"],
                        "link": "https://example.com/advisory",
                    },
                ]
            )
        )

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.vulnerabilities[0].id, "unknown")
        self.assertEqual(report.vulnerabilities[0].summary, "Detailed advisory text")
        self.assertEqual(report.vulnerabilities[0].aliases, [])
        self.assertEqual(report.vulnerabilities[0].fixed_in, [])
        self.assertEqual(report.vulnerabilities[1].id, "PYSEC-1")
        self.assertEqual(report.recommendation, "high-risk")

    def test_osv_detects_known_vulnerable_package(self) -> None:
        client = FakeClient(
            release_payloads={
                "jinja2": make_project_payload(
                    version="2.10",
                    releases={"2.10": []},
                    urls=[],
                )
            }
        )
        osv_client = FakeOsvClient(
            {
                ("jinja2", "2.10"): [
                    {
                        "id": "GHSA-462w-v97r-4m45",
                        "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
                        "summary": "Jinja2 sandbox escape via str.format_map",
                        "database_specific": {"severity": "high"},
                        "affected": [
                            {
                                "package": {
                                    "name": "jinja2",
                                    "ecosystem": "PyPI",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"fixed": "2.10.1"}],
                                    }
                                ],
                            }
                        ],
                        "references": [
                            {
                                "type": "ADVISORY",
                                "url": (
                                    "https://github.com/advisories/"
                                    "GHSA-462w-v97r-4m45"
                                ),
                            }
                        ],
                    }
                ]
            }
        )

        report = inspect_package(
            "jinja2",
            client=cast(Any, client),
            include_osv=True,
            osv_client=cast(Any, osv_client),
        )

        self.assertEqual(osv_client.calls, [("jinja2", "2.10")])
        self.assertEqual(len(report.vulnerabilities), 1)
        self.assertEqual(report.vulnerabilities[0].id, "GHSA-462w-v97r-4m45")
        self.assertIn("CVE-2019-10906", report.vulnerabilities[0].aliases)
        self.assertEqual(report.vulnerabilities[0].source, "OSV")
        self.assertEqual(report.vulnerabilities[0].severity, "HIGH")
        self.assertEqual(report.vulnerabilities[0].fixed_in, ["2.10.1"])
        self.assertEqual(report.recommendation, "high-risk")
        self.assertIn("known_vulnerabilities", {flag.code for flag in report.risk_flags})

    def test_osv_duplicate_cve_is_merged_with_pypi_record(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                vulnerabilities=[
                    {
                        "id": "PYSEC-2019-217",
                        "summary": "PyPI advisory",
                        "aliases": ["CVE-2019-10906"],
                        "fixed_in": ["2.10.1"],
                    }
                ]
            )
        )
        osv_client = FakeOsvClient(
            {
                ("gridoptim", "2.2.0"): [
                    {
                        "id": "GHSA-462w-v97r-4m45",
                        "aliases": ["CVE-2019-10906"],
                        "summary": "GitHub advisory",
                        "database_specific": {"severity": "critical"},
                        "affected": [
                            {
                                "package": {
                                    "name": "gridoptim",
                                    "ecosystem": "PyPI",
                                },
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"fixed": "2.10.2"}],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_osv=True,
            osv_client=cast(Any, osv_client),
        )

        self.assertEqual(len(report.vulnerabilities), 1)
        vulnerability = report.vulnerabilities[0]
        self.assertEqual(vulnerability.id, "PYSEC-2019-217")
        self.assertEqual(vulnerability.source, "PyPI, OSV")
        self.assertEqual(vulnerability.severity, "CRITICAL")
        self.assertEqual(vulnerability.fixed_in, ["2.10.1", "2.10.2"])
        self.assertIn("GHSA-462w-v97r-4m45", vulnerability.aliases)

    def test_repo_normalization_handles_common_edge_cases(self) -> None:
        self.assertEqual(_normalize_repo_url(None), "")
        self.assertEqual(_normalize_repo_url("owner"), "")
        self.assertEqual(
            _normalize_repo_url("git+https://github.com/Halfblood-Prince/Gridoptim.git?ref=main"),
            "https://github.com/halfblood-prince/gridoptim",
        )
        self.assertEqual(
            _normalize_repo_url("git@github.com:Halfblood-Prince/Gridoptim.git"),
            "https://github.com/halfblood-prince/gridoptim",
        )
        self.assertEqual(
            _normalize_repo_url("ssh://git@gitlab.com/Group/SubGroup/Repo.git"),
            "https://gitlab.com/group/subgroup/repo",
        )
        self.assertEqual(
            _normalize_repo_url("https://gitlab.com/group/subgroup/repo/-/tree/main"),
            "https://gitlab.com/group/subgroup/repo",
        )
        self.assertEqual(
            _normalize_repo_url("Halfblood-Prince/gridoptim"),
            "https://github.com/halfblood-prince/gridoptim",
        )
        self.assertEqual(
            _normalize_repo_url("https://docs.example.com/gridoptim"),
            "",
        )
        self.assertEqual(
            _normalize_repo_url("https://github.com/Halfblood-Prince/gridoptim/issues/1"),
            "https://github.com/halfblood-prince/gridoptim",
        )
        self.assertEqual(
            _normalize_repo_url("https://github.com/orgs/example/repositories"),
            "",
        )
        self.assertEqual(
            _normalize_repo_url(
                "https://github.com/Halfblood-Prince/gridoptim/archive/refs/tags/v1.0.0.zip"
            ),
            "",
        )
        self.assertEqual(
            _normalize_repo_url("https://gitlab.com/group/subgroup/repo/-/issues/1"),
            "https://gitlab.com/group/subgroup/repo",
        )
        self.assertEqual(
            _normalize_repo_url("https://gitlab.com/group/subgroup/repo/issues/1"),
            "",
        )
        self.assertEqual(_normalize_repo_url("https://github.com"), "")
        self.assertEqual(_normalize_repo_url("https://gitlab.com/group"), "")
        self.assertIsNone(_publisher_repository_url("GitHub", None))
        self.assertEqual(
            _publisher_repository_url("Other", "organization/project"),
            "organization/project",
        )
        self.assertEqual(
            _publisher_repository_url("GitLab", "group/project"),
            "https://gitlab.com/group/project",
        )
        self.assertEqual(
            _publisher_repository_url("Other", "https://example.com/project"),
            "https://example.com/project",
        )

    def test_publisher_summary_and_previous_release_error_branches(self) -> None:
        summary = _build_publisher_trust_summary(
            [
                FileProvenance(
                    filename="demo.whl",
                    url="https://example.com/demo.whl",
                    sha256=None,
                    has_provenance=True,
                    verified=True,
                )
            ]
        )
        self.assertEqual(summary.depth_label, "moderate")

        class FailingClient:
            def get_project(self, project: str) -> dict[str, object]:
                del project
                raise PypiClientError("unavailable")

        self.assertIsNone(
            _previous_release_version(
                "demo",
                "2.0",
                cast(Any, FailingClient()),
            )
        )
        self.assertIsNone(
            _previous_release_version(
                "demo",
                "2.0",
                cast(Any, SimpleNamespace(get_project=lambda project: {"releases": []})),
            )
        )
        self.assertIsNone(
            _previous_release_version(
                "demo",
                "invalid",
                cast(
                    Any,
                    SimpleNamespace(
                        get_project=lambda project: {"releases": {"1.0": []}}
                    ),
                ),
            )
        )
        self.assertIsNone(
            _load_package_history(
                "demo",
                "2.0",
                cast(Any, FailingClient()),
            ).project_payload
        )

        class PreviousReleaseFailingClient:
            def get_project(self, project: str) -> dict[str, object]:
                del project
                return {"releases": {"1.0": [], "2.0": []}}

            def get_release(self, project: str, version: str) -> dict[str, object]:
                del project, version
                raise PypiClientError("previous release unavailable")

        history = _load_package_history(
            "demo",
            "2.0",
            cast(Any, PreviousReleaseFailingClient()),
        )
        self.assertEqual(history.previous_version, "1.0")
        self.assertIsNone(history.previous_payload)

    def test_expected_repository_matches_slug_style_publisher_identity(self) -> None:
        provenance = make_provenance(
            publisher=make_publisher(repository="Halfblood-Prince/gridoptim")
        )
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package(
                    "gridoptim",
                    expected_repository="https://github.com/Halfblood-Prince/gridoptim",
                    client=cast(Any, client),
                )

        self.assertEqual(report.risk_flags, [])
        self.assertEqual(report.recommendation, "verified")

    def test_homepage_like_urls_do_not_count_as_declared_repo(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                urls=[],
                project_urls={
                    "Homepage": "https://docs.example.com/gridoptim",
                    "Documentation": "https://example.com/docs",
                },
            )
        )

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.declared_repository_urls, [])
        self.assertIn("missing_repository_url", {flag.code for flag in report.risk_flags})
        self.assertIn(
            "It may not be open source or may omit a public repository.",
            next(
                flag.message
                for flag in report.risk_flags
                if flag.code == "missing_repository_url"
            ),
        )

    def test_malformed_project_urls_payload_degrades_to_missing_repository_flag(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                urls=[],
                project_urls={},
            )
        )
        client.project_payload["info"]["project_urls"] = []

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(report.declared_repository_urls, [])
        self.assertIn("missing_repository_url", {flag.code for flag in report.risk_flags})

    def test_explicit_repository_label_wins_over_homepage_label(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                urls=[],
                project_urls={
                    "Homepage": "https://github.com/Halfblood-Prince/gridoptim-docs",
                    "Source": "git@github.com:Halfblood-Prince/gridoptim.git",
                },
            )
        )

        report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertEqual(
            report.declared_repository_urls,
            ["https://github.com/halfblood-prince/gridoptim"],
        )

    def test_invalid_expected_repository_is_reported_explicitly(self) -> None:
        client = FakeClient()
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package(
                    "gridoptim",
                    expected_repository="https://github.com/orgs/example/repositories",
                    client=cast(Any, client),
                )

        self.assertIn("expected_repository_invalid", {flag.code for flag in report.risk_flags})
        self.assertEqual(report.recommendation, "high-risk")

    def test_inspect_package_collects_dependency_reports(self) -> None:
        root_payload = make_project_payload(
            requires_dist=[
                "depalpha>=1.0",
                "depbeta>=2.0; python_version >= '3.11'",
                "skipme>=1.0; python_version < '3.0'",
            ],
            releases={"2.2.0": []},
        )
        depalpha_payload = make_project_payload(
            version="1.4.0",
            requires_dist=["depbeta>=2.0"],
            releases={"1.4.0": []},
            urls=[],
            project_urls={},
        )
        depbeta_payload = make_project_payload(
            version="2.5.0",
            requires_dist=[],
            releases={"2.5.0": []},
            urls=[],
            project_urls={},
            vulnerabilities=[{"id": "PYSEC-9", "summary": "dependency issue"}],
        )
        client = FakeClient(
            project_payload=root_payload,
            release_payloads={
                "depalpha": depalpha_payload,
                "depbeta": depbeta_payload,
            },
        )

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_dependencies=True,
            locked_versions={"depalpha": "1.4.0", "depbeta": "2.5.0"},
            complete_locked_versions=True,
        )

        self.assertEqual(
            report.declared_dependencies,
            [
                "depalpha>=1.0",
                "depbeta>=2.0; python_version >= '3.11'",
                "skipme>=1.0; python_version < '3.0'",
            ],
        )
        self.assertEqual(
            [(item.project, item.version, item.depth) for item in report.dependencies],
            [("depalpha", "1.4.0", 1), ("depbeta", "2.5.0", 1)],
        )
        self.assertTrue(report.dependency_summary.requested)
        self.assertEqual(report.dependency_summary.total_declared, 3)
        self.assertEqual(report.dependency_summary.total_inspected, 2)
        self.assertEqual(report.dependency_summary.max_depth, 1)
        self.assertEqual(report.dependency_summary.highest_risk_recommendation, "high-risk")
        self.assertEqual(report.dependency_summary.high_risk_projects, ["depbeta"])
        self.assertEqual(report.dependency_summary.review_required_projects, ["depalpha"])
        self.assertEqual(report.dependency_summary.metadata_only_projects, [])
        self.assertIn("dependency_high_risk", {flag.code for flag in report.risk_flags})

    def test_inspect_package_transitive_dependency_mode_walks_nested_dependencies(self) -> None:
        root_payload = make_project_payload(
            requires_dist=["depalpha>=1.0"],
            releases={"2.2.0": []},
        )
        depalpha_payload = make_project_payload(
            version="1.4.0",
            requires_dist=["depbeta>=2.0"],
            releases={"1.4.0": []},
            urls=[],
            project_urls={},
        )
        depbeta_payload = make_project_payload(
            version="2.5.0",
            requires_dist=[],
            releases={"2.5.0": []},
            urls=[],
            project_urls={},
        )
        client = FakeClient(
            project_payload=root_payload,
            release_payloads={
                "depalpha": depalpha_payload,
                "depbeta": depbeta_payload,
            },
        )

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_transitive_dependencies=True,
            locked_versions={"depalpha": "1.4.0", "depbeta": "2.5.0"},
            complete_locked_versions=True,
        )

        self.assertEqual(
            [(item.project, item.depth) for item in report.dependencies],
            [("depalpha", 1), ("depbeta", 2)],
        )
        self.assertEqual(report.dependency_summary.total_inspected, 2)
        self.assertEqual(report.dependency_summary.max_depth, 2)

    def test_locked_versions_are_used_for_direct_dependencies(self) -> None:
        client = LockedDependencyClient()

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_dependencies=True,
            locked_versions={"depalpha": "1.4.0", "depbeta": "2.5.0"},
        )

        self.assertEqual(
            [(item.project, item.version, item.depth) for item in report.dependencies],
            [("depalpha", "1.4.0", 1)],
        )
        self.assertEqual(client.release_calls, [("depalpha", "1.4.0")])

    def test_locked_versions_are_used_for_transitive_dependencies(self) -> None:
        client = LockedDependencyClient()

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_transitive_dependencies=True,
            locked_versions={"DepAlpha": "1.4.0", "depbeta": "2.5.0"},
        )

        self.assertEqual(
            [(item.project, item.version, item.depth) for item in report.dependencies],
            [("depalpha", "1.4.0", 1), ("depbeta", "2.5.0", 2)],
        )
        self.assertEqual(
            client.release_calls,
            [("depalpha", "1.4.0"), ("depbeta", "2.5.0")],
        )

    def test_osv_queries_propagate_to_transitive_dependencies(self) -> None:
        client = LockedDependencyClient()
        osv_client = FakeOsvClient(
            {
                ("depbeta", "2.5.0"): [
                    {
                        "id": "GHSA-transitive",
                        "summary": "Transitive vulnerability",
                    }
                ]
            }
        )

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_transitive_dependencies=True,
            include_osv=True,
            osv_client=cast(Any, osv_client),
            locked_versions={"depalpha": "1.4.0", "depbeta": "2.5.0"},
        )

        self.assertEqual(
            osv_client.calls,
            [
                ("gridoptim", "2.2.0"),
                ("depalpha", "1.4.0"),
                ("depbeta", "2.5.0"),
            ],
        )
        depbeta = next(item for item in report.dependencies if item.project == "depbeta")
        self.assertEqual(depbeta.recommendation, "high-risk")

    def test_invalid_or_conflicting_locked_dependency_is_recorded(self) -> None:
        cases = [
            ("not-a-version", "is invalid"),
            ("0.5.0", "does not satisfy"),
        ]
        for locked_version, error_text in cases:
            with self.subTest(locked_version=locked_version):
                client = LockedDependencyClient()
                report = inspect_package(
                    "gridoptim",
                    client=cast(Any, client),
                    include_dependencies=True,
                    locked_versions={"depalpha": locked_version},
                )

                self.assertEqual(report.dependencies[0].recommendation, "high-risk")
                self.assertIn(error_text, report.dependencies[0].error or "")
                self.assertEqual(client.release_calls, [])

    def test_inspect_package_reports_dependency_progress(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                requires_dist=["depalpha>=1.0"],
                releases={"2.2.0": []},
            ),
            release_payloads={
                "depalpha": make_project_payload(version="1.4.0", releases={"1.4.0": []}, urls=[]),
            },
        )
        progress_events: list[tuple[str, int, int, bool]] = []

        inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_dependencies=True,
            locked_versions={"depalpha": "1.4.0"},
            complete_locked_versions=True,
            dependency_progress_callback=(
                lambda project, depth, percent, done: progress_events.append(
                    (project, depth, percent, done)
                )
            ),
        )

        self.assertEqual(
            progress_events,
            [
                ("depalpha", 1, 0, False),
                ("depalpha", 1, 100, True),
            ],
        )

    def test_dependency_resolution_failure_is_recorded(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                requires_dist=["broken>=99"],
                releases={"2.2.0": []},
            ),
            release_payloads={
                "broken": make_project_payload(version="1.0.0", releases={"1.0.0": []}, urls=[]),
            },
        )

        report = inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_dependencies=True,
            locked_versions={"gridoptim": "2.2.0"},
        )

        self.assertEqual(report.dependencies[0].project, "broken")
        self.assertEqual(report.dependencies[0].recommendation, "high-risk")
        self.assertIn("compatible version", report.dependencies[0].error or "")
        self.assertIn("dependency_high_risk", {flag.code for flag in report.risk_flags})

    def test_recommendation_mapping_behavior(self) -> None:
        metadata_only = inspect_package(
            "gridoptim",
            client=cast(Any, FakeClient(project_payload={"info": {}, "urls": []})),
        )
        review_required = inspect_package(
            "gridoptim",
            client=cast(
                Any,
                FakeClient(
                    project_payload=make_project_payload(
                        urls=[],
                        project_urls={},
                    )
                ),
            ),
        )
        high_risk = TrustReport(
            project="gridoptim",
            version="2.2.0",
            summary=None,
            package_url="https://pypi.org/project/gridoptim/2.2.0/",
            risk_flags=[
                RiskFlag(
                    code="unverified_provenance",
                    severity="high",
                    message="artifact verification failed",
                )
            ],
        )
        metadata_only_files = inspect_package(
            "gridoptim",
            client=cast(
                Any,
                FakeClient(project_payload=make_project_payload(urls=[])),
            ),
        )

        self.assertEqual(metadata_only.recommendation, "review-required")
        self.assertEqual(review_required.recommendation, "review-required")
        with self.assertRaisesRegex(PypiClientError, "boom"):
            inspect_package(
                "gridoptim",
                client=cast(Any, FakeClient(project_error=PypiClientError("boom"))),
            )
        self.assertEqual(advisory_evaluation_for(review_required).violations[0].severity, "medium")
        self.assertEqual(review_required.recommendation, "review-required")
        self.assertEqual(metadata_only.recommendation, "review-required")
        self.assertEqual(advisory_evaluation_for(high_risk).violations, [
            PolicyViolation(
                code="unverified_provenance",
                severity="high",
                message="artifact verification failed",
            )
        ])
        self.assertEqual(high_risk.recommendation, "high-risk")
        self.assertEqual(metadata_only_files.recommendation, "metadata-only")

    def test_inspect_package_rejects_tampered_artifact(self) -> None:
        client = FakeClient()
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "tampered"
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("does not match PyPI metadata", report.files[0].error)

    def test_inspect_package_rejects_mismatched_attestation(self) -> None:
        def reject(identity: object, dist: object) -> None:
            raise VerificationError("subject does not match distribution digest")

        provenance = make_provenance(attestations=[make_attestation(reject)])
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("subject does not match distribution digest", report.files[0].error)

    def test_inspect_package_rejects_wrong_publisher_identity(self) -> None:
        def reject(identity: object, dist: object) -> None:
            raise VerificationError(
                "Certificate's Build Config URI does not match expected Trusted Publisher"
            )

        provenance = make_provenance(attestations=[make_attestation(reject)])
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("gridoptim", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("Trusted Publisher", report.files[0].error)

    def test_locked_artifact_hashes_are_verified_before_provenance(self) -> None:
        artifact_bytes = b"locked-wheel"
        sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        sha512 = hashlib.sha512(artifact_bytes).hexdigest()
        url = "https://files.pythonhosted.org/packages/gridoptim.whl"
        client = FakeClient(download_map={url: artifact_bytes})
        expected = (
            ArtifactReference(
                filename="gridoptim-2.2.0-py3-none-any.whl",
                url=url,
                hashes=(("sha256", sha256), ("sha512", sha512)),
                size=len(artifact_bytes),
                kind="wheel",
            ),
        )

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance(
                attestations=[]
            )
            report = inspect_package(
                "gridoptim",
                client=cast(Any, client),
                expected_artifacts=expected,
            )

        self.assertEqual(report.files[0].observed_sha256, sha256)
        self.assertFalse(
            any(
                failure.stage == "lockfile-hash"
                for failure in report.diagnostics.artifact_failures
            )
        )

    def test_locked_artifact_hash_mismatch_is_high_risk(self) -> None:
        url = "https://files.pythonhosted.org/packages/gridoptim.whl"
        client = FakeClient(download_map={url: b"tampered"})
        expected = (
            ArtifactReference(
                filename="gridoptim-2.2.0-py3-none-any.whl",
                hashes=(("sha256", "0" * 64),),
                kind="wheel",
            ),
        )

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = make_provenance(
                attestations=[]
            )
            report = inspect_package(
                "gridoptim",
                client=cast(Any, client),
                expected_artifacts=expected,
            )

        self.assertEqual(report.files[0].sha256, "0" * 64)
        self.assertIn("digest mismatch", report.files[0].error or "")
        self.assertTrue(
            any(
                flag.code == "lockfile_hash_mismatch"
                and flag.severity == "high"
                for flag in report.risk_flags
            )
        )

    def test_locked_artifact_size_and_algorithm_failures_are_reported(self) -> None:
        url = "https://files.pythonhosted.org/packages/gridoptim.whl"
        cases = [
            (
                ArtifactReference(
                    filename="gridoptim-2.2.0-py3-none-any.whl",
                    hashes=(("sha256", hashlib.sha256(b"bytes").hexdigest()),),
                    size=99,
                ),
                "size mismatch",
            ),
            (
                ArtifactReference(
                    filename="gridoptim-2.2.0-py3-none-any.whl",
                    hashes=(("not-a-hash", "a"),),
                ),
                "unsupported hash algorithm",
            ),
        ]
        for artifact, message in cases:
            with self.subTest(message=message):
                client = FakeClient(download_map={url: b"bytes"})
                with patch("trustcheck.service.Provenance") as provenance_model:
                    provenance_model.model_validate.return_value = make_provenance(
                        attestations=[]
                    )
                    report = inspect_package(
                        "gridoptim",
                        client=cast(Any, client),
                        expected_artifacts=(artifact,),
                    )
                self.assertIn(message, report.files[0].error or "")

    def test_locked_artifact_must_match_release_metadata(self) -> None:
        client = FakeClient()
        expected = (
            ArtifactReference(
                filename="different.whl",
                hashes=(("sha256", "a" * 64),),
            ),
        )
        with self.assertRaisesRegex(ValueError, "none of the release artifacts"):
            inspect_package(
                "gridoptim",
                client=cast(Any, client),
                expected_artifacts=expected,
            )
