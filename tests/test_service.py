from trustcheck.pypi import PypiClientError
from trustcheck.service import inspect_package
from pypi_attestations import VerificationError
from types import SimpleNamespace
from unittest.mock import patch
import unittest


class FakeClient:
    def get_project(self, project):
        assert project == "demo"
        return {
            "info": {
                "version": "1.2.3",
                "summary": "Demo package",
                "project_urls": {
                    "Homepage": "https://github.com/example/demo",
                    "Documentation": "https://docs.example.com/demo",
                },
                "ownership": {
                    "organization": "example-org",
                    "roles": [{"role": "Owner", "user": "alice"}],
                },
            },
            "urls": [
                {
                    "filename": "demo-1.2.3-py3-none-any.whl",
                    "url": "https://files.pythonhosted.org/packages/demo.whl",
                    "digests": {"sha256": "abc123"},
                }
            ],
            "vulnerabilities": [],
        }

    def get_release(self, project, version):
        raise AssertionError("not expected in this test")

    def get_provenance(self, project, version, filename):
        return {
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

    def download_distribution(self, url):
        assert url == "https://files.pythonhosted.org/packages/demo.whl"
        return b"demo-wheel"


class NoProvClient(FakeClient):
    def get_provenance(self, project, version, filename):
        raise PypiClientError("resource not found")


class MetadataOnlyClient(FakeClient):
    def get_project(self, project):
        payload = super().get_project(project)
        payload["urls"] = []
        return payload


class MissingRepoClient(FakeClient):
    def get_project(self, project):
        payload = super().get_project(project)
        payload["info"]["project_urls"] = {}
        return payload


class NoRepoMetadataOnlyClient(MetadataOnlyClient):
    def get_project(self, project):
        payload = super().get_project(project)
        payload["info"]["project_urls"] = {}
        return payload


class InspectPackageTests(unittest.TestCase):
    def test_inspect_package_happy_path(self):
        publisher = SimpleNamespace(
            kind="GitHub",
            repository="example/demo",
            workflow="release.yml",
            environment=None,
            model_dump=lambda: {
                "kind": "GitHub",
                "repository": "example/demo",
                "workflow": "release.yml",
                "environment": None,
            },
        )
        attestation = SimpleNamespace()
        attestation.verify = lambda identity, dist: ("https://docs.pypi.org/attestations/publish/v1", None)
        provenance = SimpleNamespace(attestation_bundles=[SimpleNamespace(publisher=publisher, attestations=[attestation])])

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package(
                    "demo",
                    expected_repository="https://github.com/example/demo",
                    client=FakeClient(),
                )

        self.assertEqual(report.project, "demo")
        self.assertEqual(report.version, "1.2.3")
        self.assertEqual(report.recommendation, "verified")
        self.assertEqual(report.repository_urls, ["https://github.com/example/demo"])
        self.assertTrue(report.files[0].has_provenance)
        self.assertTrue(report.files[0].verified)
        self.assertEqual(report.files[0].verified_attestation_count, 1)
        self.assertEqual(
            report.files[0].publisher_identities[0].repository,
            "https://github.com/example/demo",
        )
        self.assertEqual(report.risk_flags, [])

    def test_inspect_package_flags_missing_provenance_and_repo_mismatch(self):
        report = inspect_package(
            "demo",
            expected_repository="https://github.com/example/other",
            client=NoProvClient(),
        )

        flag_codes = {flag.code for flag in report.risk_flags}
        self.assertIn("expected_repository_mismatch", flag_codes)
        self.assertIn("no_provenance", flag_codes)
        self.assertIn("provenance_verification_failed", flag_codes)
        self.assertIn("unverified_provenance", flag_codes)
        self.assertEqual(report.recommendation, "high-risk")

    def test_inspect_package_rejects_tampered_artifact(self):
        publisher = SimpleNamespace(
            kind="GitHub",
            repository="example/demo",
            workflow="release.yml",
            environment=None,
            model_dump=lambda: {"kind": "GitHub", "repository": "example/demo", "workflow": "release.yml"},
        )
        attestation = SimpleNamespace()
        attestation.verify = lambda identity, dist: ("https://docs.pypi.org/attestations/publish/v1", None)
        provenance = SimpleNamespace(attestation_bundles=[SimpleNamespace(publisher=publisher, attestations=[attestation])])

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "tampered"
                report = inspect_package("demo", client=FakeClient())

        self.assertFalse(report.files[0].verified)
        self.assertIn("does not match PyPI metadata", report.files[0].error)

    def test_inspect_package_rejects_mismatched_attestation(self):
        publisher = SimpleNamespace(
            kind="GitHub",
            repository="example/demo",
            workflow="release.yml",
            environment=None,
            model_dump=lambda: {"kind": "GitHub", "repository": "example/demo", "workflow": "release.yml"},
        )
        attestation = SimpleNamespace()

        def reject(identity, dist):
            raise VerificationError("subject does not match distribution digest")

        attestation.verify = reject
        provenance = SimpleNamespace(attestation_bundles=[SimpleNamespace(publisher=publisher, attestations=[attestation])])

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("demo", client=FakeClient())

        self.assertFalse(report.files[0].verified)
        self.assertIn("subject does not match distribution digest", report.files[0].error)

    def test_inspect_package_rejects_wrong_publisher_identity(self):
        publisher = SimpleNamespace(
            kind="GitHub",
            repository="example/demo",
            workflow="release.yml",
            environment=None,
            model_dump=lambda: {"kind": "GitHub", "repository": "example/demo", "workflow": "release.yml"},
        )
        attestation = SimpleNamespace()

        def reject(identity, dist):
            raise VerificationError("Certificate's Build Config URI does not match expected Trusted Publisher")

        attestation.verify = reject
        provenance = SimpleNamespace(attestation_bundles=[SimpleNamespace(publisher=publisher, attestations=[attestation])])

        with patch("trustcheck.service.Provenance") as provenance_model:
            provenance_model.model_validate.return_value = provenance
            with patch("trustcheck.service.hashlib.sha256") as sha256:
                sha256.return_value.hexdigest.return_value = "abc123"
                report = inspect_package("demo", client=FakeClient())

        self.assertFalse(report.files[0].verified)
        self.assertIn("Trusted Publisher", report.files[0].error)

    def test_inspect_package_uses_metadata_only_when_no_crypto_evidence_exists(self):
        report = inspect_package("demo", client=MetadataOnlyClient())

        self.assertEqual(report.recommendation, "metadata-only")
        self.assertEqual(report.risk_flags, [])

    def test_inspect_package_uses_review_required_for_medium_severity_metadata_concerns(self):
        report = inspect_package("demo", client=NoRepoMetadataOnlyClient())

        flag_codes = {flag.code for flag in report.risk_flags}
        self.assertIn("missing_repository_url", flag_codes)
        self.assertEqual(report.recommendation, "review-required")
