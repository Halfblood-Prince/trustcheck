from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_sarif import validate_sarif
from trustcheck.exports import ExportPackage, SourceLocation, render_export
from trustcheck.models import TrustReport, VulnerabilityRecord


class SarifValidationTests(unittest.TestCase):
    def _write_sarif(self, path: Path) -> None:
        report = TrustReport(
            project="Jinja2",
            version="2.10.0",
            summary="fixture",
            package_url="https://pypi.org/project/Jinja2/2.10.0/",
            vulnerabilities=[
                VulnerabilityRecord(
                    id="CVE-2019-10906",
                    summary="Sandbox escape",
                    severity="high",
                )
            ],
        )
        path.write_text(
            render_export(
                "sarif",
                [
                    ExportPackage(
                        report=report,
                        source=SourceLocation(
                            "tests/fixtures/requirements-vulnerable.txt",
                            1,
                        ),
                    )
                ],
                source_name="tests/fixtures/requirements-vulnerable.txt",
            ),
            encoding="utf-8",
        )

    def test_accepts_trustcheck_sarif_with_stable_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.sarif"
            self._write_sarif(path)
            fingerprints = validate_sarif(path)

        self.assertEqual(len(fingerprints), 1)

    def test_rejects_duplicate_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.sarif"
            self._write_sarif(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            result = payload["runs"][0]["results"][0]
            payload["runs"][0]["results"].append(result)
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate SARIF"):
                validate_sarif(path)


if __name__ == "__main__":
    unittest.main()
