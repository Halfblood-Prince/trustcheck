from __future__ import annotations

import unittest
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from pypi_attestations import VerificationError

from trustcheck.models import PolicyViolation, RiskFlag, TrustReport
from trustcheck.policy import advisory_evaluation_for
from trustcheck.pypi import PypiClientError
from trustcheck.service import (
    _normalize_repo_url,
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


class InspectPackageTests(unittest.TestCase):
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

    def test_repo_normalization_handles_common_edge_cases(self) -> None:
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
                "depbeta>=2.0; python_version >= '3.10'",
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

        report = inspect_package("gridoptim", client=cast(Any, client), include_dependencies=True)

        self.assertEqual(
            report.declared_dependencies,
            [
                "depalpha>=1.0",
                "depbeta>=2.0; python_version >= '3.10'",
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
        )

        self.assertEqual(
            [(item.project, item.depth) for item in report.dependencies],
            [("depalpha", 1), ("depbeta", 2)],
        )
        self.assertEqual(report.dependency_summary.total_inspected, 2)
        self.assertEqual(report.dependency_summary.max_depth, 2)

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
        progress_events: list[tuple[str, int, int, int]] = []

        inspect_package(
            "gridoptim",
            client=cast(Any, client),
            include_dependencies=True,
            dependency_progress_callback=(
                lambda project, depth, current, total: progress_events.append(
                    (project, depth, current, total)
                )
            ),
        )

        self.assertEqual(progress_events, [("depalpha", 1, 1, 1)])

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

        report = inspect_package("gridoptim", client=cast(Any, client), include_dependencies=True)

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
