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

        self.assertIn("needs: verify-tag", _job_block(workflow, "qa"))
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

        self.assertIn('"pyinstaller>=6.20,<7"', build)
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
        self.assertIn("dist\\standalone\\trustcheck.exe", build)
        self.assertIn("& $binary --version", build)
        self.assertIn("& $binary --help", build)
        self.assertIn("trustcheck-$releaseVersion-windows-x86_64.exe", build)
        self.assertIn("Get-FileHash", build)
        self.assertIn(
            "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            build,
        )
        self.assertIn("windows-executable-unscanned-${{ github.sha }}", build)

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

    def test_scanned_executable_is_attached_after_release_creation(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        upload = _job_block(workflow, "upload-windows-executable")

        self.assertIn("- windows-defender-scan", upload)
        self.assertIn("- publish-github-action", upload)
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            upload,
        )
        self.assertIn('gh release upload "$RELEASE_TAG"', upload)
        self.assertIn("windows-executable/*", upload)
        self.assertIn("--clobber", upload)

if __name__ == "__main__":
    unittest.main()
