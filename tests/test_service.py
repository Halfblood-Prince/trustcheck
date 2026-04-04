from __future__ import annotations

import unittest
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from pypi_attestations import VerificationError

from trustcheck.models import RiskFlag, TrustReport
from trustcheck.pypi import PypiClientError
from trustcheck.service import (
    _normalize_repo_url,
    _recommendation_for,
    inspect_package,
)

AttestationFn = Callable[[object, object], tuple[str, object | None] | None]


def make_project_payload(
    *,
    version: str = "1.2.3",
    project_urls: dict[str, str] | None = None,
    urls: list[dict[str, object]] | None = None,
    vulnerabilities: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "info": {
            "version": version,
            "summary": "Demo package",
            "project_urls": project_urls
            if project_urls is not None
            else {
                "Homepage": "https://github.com/example/demo",
                "Documentation": "https://docs.example.com/demo",
            },
            "ownership": {
                "organization": "example-org",
                "roles": [{"role": "Owner", "user": "alice"}],
            },
        },
        "urls": urls
        if urls is not None
        else [
            {
                "filename": "demo-1.2.3-py3-none-any.whl",
                "url": "https://files.pythonhosted.org/packages/demo.whl",
                "digests": {"sha256": "abc123"},
            }
        ],
        "vulnerabilities": vulnerabilities or [],
    }


def make_publisher(
    *,
    kind: str = "GitHub",
    repository: str = "example/demo",
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
        provenance_payload: dict[str, object] | None = None,
        download_map: dict[str, bytes] | None = None,
        project_error: Exception | None = None,
        release_error: Exception | None = None,
        provenance_errors: dict[str, Exception] | None = None,
    ) -> None:
        self.project_payload = project_payload or make_project_payload()
        self.release_payload = release_payload or make_project_payload()
        self.provenance_payload = provenance_payload or {
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "GitHub",
                        "repository": "example/demo",
                        "workflow": "release.yml",
                    },
                    "attestations": [{"kind": "publish"}],
                }
            ]
        }
        self.download_map = download_map or {
            "https://files.pythonhosted.org/packages/demo.whl": b"demo-wheel",
        }
        self.project_error = project_error
        self.release_error = release_error
        self.provenance_errors = provenance_errors or {}

    def get_project(self, project: str) -> dict[str, object]:
        assert project == "demo"
        if self.project_error is not None:
            raise self.project_error
        return self.project_payload

    def get_release(self, project: str, version: str) -> dict[str, object]:
        assert project == "demo"
        if self.release_error is not None:
            raise self.release_error
        return self.release_payload

    def get_provenance(
        self,
        project: str,
        version: str,
        filename: str,
    ) -> dict[str, object]:
        assert project == "demo"
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
                    "demo",
                    expected_repository="https://github.com/example/demo",
                    client=cast(Any, client),
                )

        self.assertEqual(report.project, "demo")
        self.assertEqual(report.version, "1.2.3")
        self.assertEqual(report.recommendation, "verified")
        self.assertEqual(
            report.declared_repository_urls,
            ["https://github.com/example/demo"],
        )
        self.assertEqual(report.repository_urls, report.declared_repository_urls)
        self.assertTrue(report.files[0].has_provenance)
        self.assertTrue(report.files[0].verified)
        self.assertEqual(report.files[0].verified_attestation_count, 1)
        self.assertEqual(
            report.files[0].publisher_identities[0].repository,
            "https://github.com/example/demo",
        )
        self.assertEqual(report.risk_flags, [])

    def test_project_lookup_failure_bubbles_up(self) -> None:
        client = FakeClient(project_error=PypiClientError("unable to reach PyPI: timed out"))

        with self.assertRaisesRegex(PypiClientError, "timed out"):
            inspect_package("demo", client=cast(Any, client))

    def test_release_lookup_failure_bubbles_up(self) -> None:
        client = FakeClient(release_error=PypiClientError("resource not found"))

        with self.assertRaisesRegex(PypiClientError, "resource not found"):
            inspect_package("demo", version="9.9.9", client=cast(Any, client))

    def test_provenance_404_marks_file_as_unverified(self) -> None:
        payload = make_project_payload()
        client = FakeClient(
            project_payload=payload,
            provenance_errors={
                "demo-1.2.3-py3-none-any.whl": PypiClientError("resource not found")
            },
        )

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.files[0].error, "resource not found")
        self.assertIn("no_provenance", {flag.code for flag in report.risk_flags})
        self.assertEqual(report.recommendation, "high-risk")

    def test_provenance_transient_failure_marks_file_as_unverified(self) -> None:
        payload = make_project_payload()
        client = FakeClient(
            project_payload=payload,
            provenance_errors={
                "demo-1.2.3-py3-none-any.whl": PypiClientError(
                    "PyPI returned HTTP 503 for provenance"
                )
            },
        )

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.files[0].error, "PyPI returned HTTP 503 for provenance")
        self.assertIn(
            "provenance_verification_failed",
            {flag.code for flag in report.risk_flags},
        )

    def test_malformed_provenance_payload_is_reported(self) -> None:
        client = FakeClient(provenance_payload={"oops": []})

        report = inspect_package("demo", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("attestation verification failed", report.files[0].error)

    def test_missing_project_fields_fall_back_cleanly(self) -> None:
        client = FakeClient(project_payload={"urls": [], "vulnerabilities": []})

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.version, "unknown")
        self.assertIsNone(report.summary)
        self.assertEqual(report.declared_repository_urls, [])
        self.assertEqual(report.files, [])
        self.assertEqual(report.recommendation, "review-required")

    def test_multiple_files_per_release_are_all_collected(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "demo-1.2.3-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/demo.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "demo-1.2.3.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/demo.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/demo.whl": b"wheel",
                "https://files.pythonhosted.org/packages/demo.tar.gz": b"sdist",
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
                report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual([file.filename for file in report.files], payload["urls"][0:2][0:2] and [
            "demo-1.2.3-py3-none-any.whl",
            "demo-1.2.3.tar.gz",
        ])
        self.assertTrue(all(file.verified for file in report.files))

    def test_partial_provenance_coverage_is_high_risk(self) -> None:
        payload = make_project_payload(
            urls=[
                {
                    "filename": "demo-1.2.3-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/demo.whl",
                    "digests": {"sha256": "abc123"},
                },
                {
                    "filename": "demo-1.2.3.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/demo.tar.gz",
                    "digests": {"sha256": "def456"},
                },
            ]
        )
        client = FakeClient(
            project_payload=payload,
            download_map={
                "https://files.pythonhosted.org/packages/demo.whl": b"wheel",
                "https://files.pythonhosted.org/packages/demo.tar.gz": b"sdist",
            },
            provenance_errors={"demo-1.2.3.tar.gz": PypiClientError("resource not found")},
        )
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("demo", client=cast(Any, client))

        self.assertTrue(report.files[0].verified)
        self.assertFalse(report.files[1].verified)
        self.assertEqual(report.recommendation, "high-risk")
        self.assertEqual(report.files[1].error, "resource not found")

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

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.vulnerabilities[0].id, "unknown")
        self.assertEqual(report.vulnerabilities[0].summary, "Detailed advisory text")
        self.assertEqual(report.vulnerabilities[0].aliases, [])
        self.assertEqual(report.vulnerabilities[0].fixed_in, [])
        self.assertEqual(report.vulnerabilities[1].id, "PYSEC-1")
        self.assertEqual(report.recommendation, "high-risk")

    def test_repo_normalization_handles_common_edge_cases(self) -> None:
        self.assertEqual(
            _normalize_repo_url("git+https://github.com/Example/Demo.git?ref=main"),
            "https://github.com/example/demo",
        )
        self.assertEqual(
            _normalize_repo_url("git@github.com:Example/Demo.git"),
            "https://github.com/example/demo",
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
            _normalize_repo_url("example/demo"),
            "https://github.com/example/demo",
        )
        self.assertEqual(
            _normalize_repo_url("https://docs.example.com/demo"),
            "",
        )

    def test_expected_repository_matches_slug_style_publisher_identity(self) -> None:
        provenance = make_provenance(
            publisher=make_publisher(repository="example/demo")
        )
        client = FakeClient()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package(
                    "demo",
                    expected_repository="https://github.com/example/demo",
                    client=cast(Any, client),
                )

        self.assertEqual(report.risk_flags, [])
        self.assertEqual(report.recommendation, "verified")

    def test_homepage_like_urls_do_not_count_as_declared_repo(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                urls=[],
                project_urls={
                    "Homepage": "https://docs.example.com/demo",
                    "Documentation": "https://example.com/docs",
                },
            )
        )

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.declared_repository_urls, [])
        self.assertIn("missing_repository_url", {flag.code for flag in report.risk_flags})

    def test_explicit_repository_label_wins_over_homepage_label(self) -> None:
        client = FakeClient(
            project_payload=make_project_payload(
                urls=[],
                project_urls={
                    "Homepage": "https://github.com/example/docs-site",
                    "Source": "git@github.com:Example/Demo.git",
                },
            )
        )

        report = inspect_package("demo", client=cast(Any, client))

        self.assertEqual(report.declared_repository_urls, ["https://github.com/example/demo"])

    def test_recommendation_mapping_behavior(self) -> None:
        metadata_only = inspect_package(
            "demo",
            client=cast(Any, FakeClient(project_payload={"info": {}, "urls": []})),
        )
        review_required = inspect_package(
            "demo",
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
            project="demo",
            version="1.2.3",
            summary=None,
            package_url="https://pypi.org/project/demo/1.2.3/",
            risk_flags=[
                RiskFlag(
                    code="unverified_provenance",
                    severity="high",
                    message="artifact verification failed",
                )
            ],
        )
        metadata_only_files = inspect_package(
            "demo",
            client=cast(
                Any,
                FakeClient(project_payload=make_project_payload(urls=[])),
            ),
        )

        self.assertEqual(metadata_only.recommendation, "review-required")
        self.assertEqual(review_required.recommendation, "review-required")
        with self.assertRaisesRegex(PypiClientError, "boom"):
            inspect_package(
                "demo",
                client=cast(Any, FakeClient(project_error=PypiClientError("boom"))),
            )
        self.assertEqual(_recommendation_for(review_required), "review-required")
        self.assertEqual(_recommendation_for(metadata_only), "review-required")
        self.assertEqual(_recommendation_for(high_risk), "high-risk")
        self.assertEqual(_recommendation_for(metadata_only_files), "metadata-only")

    def test_inspect_package_rejects_tampered_artifact(self) -> None:
        client = FakeClient()
        provenance = make_provenance()

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "tampered"
                report = inspect_package("demo", client=cast(Any, client))

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
                report = inspect_package("demo", client=cast(Any, client))

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
                report = inspect_package("demo", client=cast(Any, client))

        self.assertFalse(report.files[0].verified)
        assert report.files[0].error is not None
        self.assertIn("Trusted Publisher", report.files[0].error)
