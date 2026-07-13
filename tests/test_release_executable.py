from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


def _job_block(workflow: str, job_name: str) -> str:
    marker = f"  {job_name}:\n"
    start = workflow.index(marker)
    tail_start = start + len(marker)
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", workflow[tail_start:])
    if next_job is None:
        return workflow[start:]
    return workflow[start : tail_start + next_job.start()]


class ReleaseExecutableWorkflowTests(unittest.TestCase):
    def test_release_starts_with_the_required_serial_stages(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")

        qa = _job_block(workflow, "qa")
        self.assertIn("- verify-tag", qa)
        self.assertIn("- live-integration-freshness", qa)
        self.assertIn("needs: qa", _job_block(workflow, "matrix-build"))
        self.assertIn("needs: matrix-build", _job_block(workflow, "coverage-build"))

    def test_windows_executable_build_fans_out_after_coverage(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        build = _job_block(workflow, "build-windows-executable")

        self.assertIn("needs: coverage-build", build)
        self.assertNotIn("needs: snap-qa", build)
        self.assertNotIn("needs: publish-pypi", build)
        self.assertNotIn("needs: publish-github-action", build)
        self.assertNotIn("needs: publish-snap", build)
        self.assertIn("runs-on: windows-latest", build)

    def test_release_build_creates_and_verifies_versioned_executable(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        build = _job_block(workflow, "build-windows-executable")
        ci_lock = (ROOT / "requirements" / "ci.lock").read_text(encoding="utf-8")

        self.assertIn("--requirement requirements/ci.lock", build)
        self.assertIn("--require-hashes", build)
        self.assertIn("--no-build-isolation", build)
        self.assertIn("--no-deps", build)
        self.assertIn("pyinstaller==", ci_lock)
        self.assertIn("pillow==", ci_lock.lower())
        self.assertIn("Authenticode sign and RFC 3161 timestamp executable", build)
        self.assertIn("WINDOWS_SIGNING_CERTIFICATE_BASE64", build)
        self.assertIn("/tr $timestampUrl", build)
        self.assertIn("signtool.exe verify /pa /all /v", build)
        self.assertIn("Set standalone release version", build)
        self.assertIn(
            '"SETUPTOOLS_SCM_PRETEND_VERSION=$releaseVersion" >> $env:GITHUB_ENV',
            build,
        )
        self.assertIn(
            '"SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK=$releaseVersion" '
            ">> $env:GITHUB_ENV",
            build,
        )
        self.assertIn("python scripts/build_standalone.py", build)
        self.assertIn("Build unsigned Microsoft Store MSIX", build)
        self.assertIn("python scripts/build_msix_layout.py", build)
        self.assertIn("MakeAppx.exe pack", build)
        self.assertIn("dist\\standalone\\trustcheck.exe", build)
        self.assertIn("& $binary --version", build)
        self.assertIn("& $binary --help", build)
        self.assertIn("trustcheck-$releaseVersion-windows-x86_64.exe", build)
        self.assertIn("Get-FileHash", build)
        self.assertIn(
            "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
            build,
        )
        self.assertIn("windows-executable-unscanned-${{ github.sha }}", build)

    def test_windows_distributions_run_in_fresh_install_jobs(self) -> None:
        workflow = (ROOT / ".github/workflows/publish.yml").read_text(
            encoding="utf-8"
        )
        direct = _job_block(workflow, "windows-clean-install")
        msix = _job_block(workflow, "test-msix-installation")

        self.assertIn("needs: windows-defender-scan", direct)
        self.assertIn("needs: windows-defender-scan", msix)
        self.assertIn("Get-AuthenticodeSignature", direct)
        self.assertIn("trustcheck --help", direct)
        self.assertIn("trustcheck inspect requests", direct)
        self.assertIn("Add-AppxPackage", msix)
        self.assertIn("trustcheck.exe --help", msix)
        self.assertIn("trustcheck.exe inspect requests", msix)

    def test_defender_scans_the_executable_from_the_build_job(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        defender = _job_block(workflow, "windows-defender-scan")

        self.assertIn("needs: build-windows-executable", defender)
        self.assertIn("windows-executable-unscanned-${{ github.sha }}", defender)
        self.assertIn("Scan built executable with Microsoft Defender", defender)
        self.assertIn("-File $env:EXECUTABLE_PATH", defender)
        self.assertIn("windows-executable-${{ github.sha }}", defender)

    def test_scanned_executable_is_attached_after_windows_tests_and_release_creation(
        self,
    ) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        upload = _job_block(workflow, "upload-windows-executable")

        self.assertNotIn("- windows-defender-scan", upload)
        self.assertIn("- windows-clean-install", upload)
        self.assertIn("- test-msix-installation", upload)
        self.assertIn("- publish-github-release", upload)
        self.assertNotIn("- publish-github-action", upload)
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            upload,
        )
        self.assertIn('gh release upload "$RELEASE_TAG"', upload)
        self.assertIn("windows-executable/*", upload)
        self.assertIn("--clobber", upload)

if __name__ == "__main__":
    unittest.main()
