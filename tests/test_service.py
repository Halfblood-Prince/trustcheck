from trustcheck.pypi import PypiClientError
from trustcheck.service import inspect_package
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
                        "kind": "GitHub Actions",
                        "repository": "https://github.com/example/demo",
                        "workflow": "release.yml",
                    },
                    "attestations": [{"kind": "publish"}],
                }
            ]
        }


class NoProvClient(FakeClient):
    def get_provenance(self, project, version, filename):
        raise PypiClientError("resource not found")


class InspectPackageTests(unittest.TestCase):
    def test_inspect_package_happy_path(self):
        report = inspect_package(
            "demo",
            expected_repository="https://github.com/example/demo",
            client=FakeClient(),
        )

        self.assertEqual(report.project, "demo")
        self.assertEqual(report.version, "1.2.3")
        self.assertEqual(report.recommendation, "looks-good")
        self.assertEqual(report.repository_urls, ["https://github.com/example/demo"])
        self.assertTrue(report.files[0].has_provenance)
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
        self.assertIn("provenance_lookup_failed", flag_codes)
        self.assertEqual(report.recommendation, "do-not-trust-without-review")
