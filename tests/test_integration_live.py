from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from trustcheck.advisories import OsvClient, parse_osv_vulnerabilities
from trustcheck.pypi import PypiClient, PypiClientError
from trustcheck.service import inspect_package
from trustcheck.snapshots import AdvisorySnapshotStore

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

    def test_sampleproject_sigstore_verification_succeeds(self) -> None:
        report = inspect_package(
            "sampleproject",
            version="4.0.0",
            client=PypiClient(),
            scan_profile="standard",
            artifact_scope="target",
        )

        self.assertTrue(report.files)
        self.assertTrue(any(file.verified for file in report.files))
        self.assertGreaterEqual(
            sum(file.verified_attestation_count for file in report.files),
            1,
        )

    def test_osv_and_pypi_advisory_lookups_return_known_history(self) -> None:
        pypi_records = PypiClient().get_release("jinja2", "2.10.0").get(
            "vulnerabilities",
            [],
        )
        osv_records = OsvClient().query("jinja2", "2.10.0")

        self.assertTrue(pypi_records)
        self.assertTrue(osv_records)

    def test_live_advisories_round_trip_through_snapshot(self) -> None:
        raw_records = OsvClient().query("jinja2", "2.10.0")
        records = parse_osv_vulnerabilities(raw_records, project="jinja2")
        self.assertTrue(records)

        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "advisories.json"
            writer = AdvisorySnapshotStore(
                output=snapshot,
                source_urls=("https://api.osv.dev",),
                allow_unsigned=True,
            )
            writer.put("jinja2", "2.10.0", records)
            writer.write()

            reader = AdvisorySnapshotStore(
                inputs=(snapshot,),
                allow_unsigned=True,
            )
            restored = reader.get("jinja2", "2.10.0")

        self.assertIsNotNone(restored)
        self.assertEqual(
            {record.id for record in restored or []},
            {record.id for record in records},
        )
