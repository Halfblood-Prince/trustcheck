from __future__ import annotations

import os
import unittest

from trustcheck.pypi import PypiClient, PypiClientError

RUN_LIVE = os.environ.get("TRUSTCHECK_RUN_LIVE") == "1"


@unittest.skipUnless(RUN_LIVE, "set TRUSTCHECK_RUN_LIVE=1 to run live PyPI integration tests")
class LivePypiIntegrationTests(unittest.TestCase):
    def test_sampleproject_release_has_expected_provenance(self) -> None:
        client = PypiClient()

        release = client.get_release("sampleproject", "4.0.0")
        filenames = {item["filename"] for item in release["urls"]}

        self.assertEqual(release["info"]["version"], "4.0.0")
        self.assertIn("sampleproject-4.0.0.tar.gz", filenames)
        self.assertIn("sampleproject-4.0.0-py3-none-any.whl", filenames)

        provenance = client.get_provenance(
            "sampleproject",
            "4.0.0",
            "sampleproject-4.0.0-py3-none-any.whl",
        )
        bundles = provenance["attestation_bundles"]

        self.assertGreaterEqual(len(bundles), 1)
        publisher = bundles[0]["publisher"]
        self.assertEqual(publisher["kind"], "GitHub")
        self.assertEqual(publisher["repository"], "pypa/sampleproject")
        self.assertEqual(publisher["workflow"], "release.yml")

    def test_requests_release_without_provenance_returns_404_style_error(self) -> None:
        client = PypiClient(max_retries=0)

        with self.assertRaises(PypiClientError) as caught:
            client.get_provenance(
                "requests",
                "2.31.0",
                "requests-2.31.0-py3-none-any.whl",
            )

        self.assertEqual(caught.exception.status_code, 404)
        self.assertFalse(caught.exception.transient)

    def test_requests_release_metadata_matches_expected_version(self) -> None:
        client = PypiClient()

        release = client.get_release("requests", "2.31.0")
        filenames = {item["filename"] for item in release["urls"]}

        self.assertEqual(release["info"]["version"], "2.31.0")
        self.assertIn("requests-2.31.0.tar.gz", filenames)
        self.assertIn("requests-2.31.0-py3-none-any.whl", filenames)
        self.assertGreaterEqual(len(release["urls"]), 2)
