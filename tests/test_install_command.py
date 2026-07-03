from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from trustcheck.cli import EXIT_OK, EXIT_POLICY_FAILURE, build_parser, main
from trustcheck.cli_models import ScanTarget
from trustcheck.models import CoverageSummary, FileProvenance, TrustReport
from trustcheck.resolver import ArtifactReference

WHEEL_BYTES = b"verified wheel bytes"
WHEEL_DIGEST = hashlib.sha256(WHEEL_BYTES).hexdigest()
WHEEL_FILENAME = "demo-1.0-py3-none-any.whl"
WHEEL_URL = f"https://files.pythonhosted.org/packages/{WHEEL_FILENAME}"


class FakeDownloadClient:
    timeout = 10.0
    max_retries = 0
    backoff_factor = 0.0
    offline = False
    request_hook = None

    def __init__(self) -> None:
        self.downloads: list[str] = []

    def download_distribution(self, url: str) -> bytes:
        self.downloads.append(url)
        return WHEEL_BYTES


def make_target() -> ScanTarget:
    return ScanTarget(
        requirement="demo==1.0",
        project="demo",
        version="1.0",
        locked_versions={"demo": "1.0"},
        complete_locked_versions=True,
        artifacts=(
            ArtifactReference(
                filename=WHEEL_FILENAME,
                url=WHEEL_URL,
                hashes=(("sha256", WHEEL_DIGEST),),
            ),
        ),
    )


def make_report(*, verified: bool = True) -> TrustReport:
    return TrustReport(
        project="demo",
        version="1.0",
        summary="demo package",
        package_url="https://pypi.org/project/demo/1.0/",
        files=[
            FileProvenance(
                filename=WHEEL_FILENAME,
                url=WHEEL_URL,
                sha256=WHEEL_DIGEST,
                observed_sha256=WHEEL_DIGEST if verified else None,
                has_provenance=verified,
                verified=verified,
                attestation_count=1 if verified else 0,
                verified_attestation_count=1 if verified else 0,
            )
        ],
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1 if verified else 0,
            verified_files=1 if verified else 0,
            status="all-verified" if verified else "none",
        ),
        recommendation="verified" if verified else "metadata-only",
    )


class InstallCommandTests(unittest.TestCase):
    def test_parser_accepts_secure_install_examples(self) -> None:
        parser = build_parser()

        file_args = parser.parse_args(
            ["install", "-r", "requirements.txt", "--policy", "strict"]
        )
        self.assertEqual(file_args.command, "install")
        self.assertEqual(file_args.requirement_file, "requirements.txt")
        self.assertEqual(file_args.policy, "strict")

        lock_args = parser.parse_args(
            ["install", "-r", "requirements.txt", "--lock", "trustcheck.lock"]
        )
        self.assertEqual(lock_args.lock, "trustcheck.lock")

        direct_args = parser.parse_args(
            ["install", "requests==2.32.5", "--require-provenance"]
        )
        self.assertEqual(direct_args.requirements, ["requests==2.32.5"])
        self.assertTrue(direct_args.require_provenance)

    def test_install_downloads_verified_artifact_then_invokes_local_pip(self) -> None:
        stdout = io.StringIO()
        fake_client = FakeDownloadClient()
        target = make_target()

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            lock = root / "trustcheck.lock"
            report_path = root / "trustcheck-install-report.json"
            attestation = root / "trustcheck-install-attestation.json"
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_inspect_package(project: str, **kwargs):
                self.assertEqual(project, "demo")
                self.assertTrue(kwargs["inspect_artifacts"])
                self.assertEqual(kwargs["scan_profile"], "full")
                self.assertEqual(kwargs["artifact_scope"], "target")
                return make_report()

            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch("trustcheck.cli._client_for_target", return_value=fake_client),
                patch(
                    "trustcheck.cli.inspect_package",
                    side_effect=fake_inspect_package,
                ),
                patch(
                    "trustcheck.cli_commands.install.subprocess.run",
                    return_value=completed,
                ) as pip_run,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "install",
                        "-r",
                        "requirements.txt",
                        "--lock",
                        str(lock),
                        "--report",
                        str(report_path),
                        "--attestation",
                        str(attestation),
                    ]
                )

            self.assertEqual(exit_code, EXIT_OK)
            self.assertEqual(fake_client.downloads, [WHEEL_URL])
            command = pip_run.call_args.args[0]
            self.assertIn("--no-index", command)
            self.assertIn("--find-links", command)
            self.assertIn("--require-hashes", command)
            self.assertIn("--no-deps", command)
            self.assertIn("--only-binary", command)
            self.assertIn("[ok] demo 1.0", stdout.getvalue())
            self.assertIn(
                "Installed packages from the verified local wheelhouse",
                stdout.getvalue(),
            )

            lock_payload = json.loads(lock.read_text(encoding="utf-8"))
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            attestation_payload = json.loads(attestation.read_text(encoding="utf-8"))
            self.assertEqual(lock_payload["schema"], "urn:trustcheck:install-lock:1.0.0")
            self.assertEqual(report_payload["status"], "installed")
            self.assertTrue(report_payload["installed"])
            self.assertEqual(
                report_payload["packages"][0]["install_artifact"]["observed_sha256"],
                WHEEL_DIGEST,
            )
            self.assertEqual(
                attestation_payload["subject"][0]["digest"]["sha256"],
                WHEEL_DIGEST,
            )

    def test_provenance_policy_failure_stops_before_download_or_install(self) -> None:
        stdout = io.StringIO()
        fake_client = FakeDownloadClient()
        target = make_target()

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            report_path = root / "report.json"
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch("trustcheck.cli._client_for_target", return_value=fake_client),
                patch("trustcheck.cli.inspect_package", return_value=make_report(verified=False)),
                patch("trustcheck.cli_commands.install.subprocess.run") as pip_run,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "install",
                        "-r",
                        "requirements.txt",
                        "--require-provenance",
                        "--lock",
                        str(root / "lock.json"),
                        "--report",
                        str(report_path),
                        "--attestation",
                        str(root / "attestation.json"),
                    ]
                )

            self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
            self.assertEqual(fake_client.downloads, [])
            pip_run.assert_not_called()
            rendered = stdout.getvalue()
            self.assertIn("[blocked] demo 1.0", rendered)
            self.assertIn("Policy requires verified provenance", rendered)
            self.assertIn("No packages were installed.", rendered)
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report_payload["status"], "blocked")
            self.assertFalse(report_payload["installed"])


if __name__ == "__main__":
    unittest.main()
