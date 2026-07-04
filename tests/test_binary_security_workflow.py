from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class BinarySecurityWorkflowTests(unittest.TestCase):
    def test_workflow_builds_and_scans_both_platform_binaries_on_push(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "binary-security.yml").read_text(
            encoding="utf-8"
        )

        self.assertRegex(workflow, r"(?m)^  push:$")
        self.assertIn("name: Windows Defender", workflow)
        self.assertIn("runs-on: windows-latest", workflow)
        self.assertIn("name: ClamAV", workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertEqual(workflow.count("python scripts/build_standalone.py"), 2)
        self.assertIn("dist\\standalone\\trustcheck.exe", workflow)
        self.assertIn("dist/standalone/trustcheck", workflow)

    def test_windows_job_uses_defender_cli_for_exact_executable(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "binary-security.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("MpCmdRun.exe", workflow)
        self.assertIn("Start-Service -Name wuauserv", workflow)
        self.assertIn("Get-MpComputerStatus", workflow)
        self.assertIn("$status.AntivirusEnabled", workflow)
        self.assertIn("-SignatureUpdate", workflow)
        self.assertIn("-ScanType 3", workflow)
        self.assertIn("-File $binary", workflow)
        self.assertIn("-DisableRemediation", workflow)
        self.assertIn("defender-scan.txt", workflow)
        self.assertIn("Upload clean Windows executable", workflow)

    def test_linux_job_updates_signatures_and_scans_exact_executable(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "binary-security.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("sudo apt-get install --yes clamav", workflow)
        self.assertIn("sudo freshclam --verbose", workflow)
        self.assertIn("clamscan \\", workflow)
        self.assertIn("dist/standalone/trustcheck", workflow)
        self.assertIn("--official-db-only=yes", workflow)
        self.assertIn("clamav-scan.txt", workflow)
        self.assertIn("Upload clean Linux executable", workflow)

    def test_standalone_builder_includes_verification_resources(self) -> None:
        builder = (ROOT / "scripts" / "build_standalone.py").read_text(encoding="utf-8")
        entrypoint = (ROOT / "scripts" / "trustcheck_binary.py").read_text(encoding="utf-8")

        self.assertIn('"--onefile"', builder)
        self.assertIn('"--noupx"', builder)
        self.assertIn('"--recursive-copy-metadata=trustcheck"', builder)
        for package in (
            "rekor_types",
            "sigstore",
            "sigstore_models",
            "tuf",
        ):
            self.assertIn(f'"{package}"', builder)
        self.assertNotIn("pypi_attestations", builder)
        self.assertIn("from trustcheck.cli import main", entrypoint)

    def test_runtime_depends_directly_on_sigstore_and_not_its_transitives(self) -> None:
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('"sigstore>=4.3,<5"', project)
        self.assertIn('"urllib3>=2.7,<3"', project)
        self.assertIn('"cryptography>=48.0.1,<50"', project)
        self.assertNotIn('"tuf>=7,<8"', project)
        self.assertNotIn('"idna>=3.15,<4"', project)
        self.assertNotIn('"PyJWT>=2.13,<3"', project)
        self.assertNotIn("tomli", project)
        self.assertNotIn("pypi-attestations", project)
        self.assertFalse((ROOT / "src" / "trustcheck" / "parse_toml.py").exists())
        self.assertFalse((ROOT / "src" / "trustcheck" / "parse_toml").exists())
        self.assertFalse((ROOT / "src" / "parse_toml").exists())

    def test_readme_has_independent_check_run_badges(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("nameFilter=Windows%20Defender", readme)
        self.assertIn("nameFilter=ClamAV", readme)
        self.assertEqual(readme.count("actions/workflows/binary-security.yml"), 3)


if __name__ == "__main__":
    unittest.main()
