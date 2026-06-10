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
    def test_windows_executable_build_runs_beside_publish_jobs(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        build = _job_block(workflow, "build-windows-executable")

        self.assertIn("- coverage-build", build)
        self.assertIn("- snap-qa", build)
        self.assertNotIn("- publish-pypi", build)
        self.assertNotIn("- publish-github-action", build)
        self.assertNotIn("- publish-snap", build)
        self.assertIn("runs-on: windows-latest", build)

    def test_release_build_creates_and_verifies_versioned_executable(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        build = _job_block(workflow, "build-windows-executable")

        self.assertIn('"pyinstaller>=6.20,<7"', build)
        self.assertIn("python scripts/build_standalone.py", build)
        self.assertIn("dist\\standalone\\trustcheck.exe", build)
        self.assertIn("& $binary --version", build)
        self.assertIn("& $binary --help", build)
        self.assertIn("trustcheck-$releaseVersion-windows-x86_64.exe", build)
        self.assertIn("Get-FileHash", build)
        self.assertIn("actions/attest-build-provenance@v4", build)
        self.assertIn("windows-executable-${{ github.sha }}", build)

    def test_verified_executable_is_attached_after_release_creation(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "publish.yml"
        ).read_text(encoding="utf-8")
        attach = _job_block(workflow, "attach-windows-executable")

        self.assertIn("- build-windows-executable", attach)
        self.assertIn("- publish-github-action", attach)
        self.assertIn("actions/download-artifact@v8", attach)
        self.assertIn('gh release upload "$RELEASE_TAG"', attach)
        self.assertIn("windows-executable/*", attach)
        self.assertIn("--clobber", attach)

    def test_release_guide_documents_executable_publication(self) -> None:
        guide = (
            ROOT / "docs" / "guides" / "release-publishing.md"
        ).read_text(encoding="utf-8")

        self.assertIn("Windows\nexecutable build start in parallel", guide)
        self.assertIn("PyInstaller build", guide)
        self.assertIn("versioned Windows executable", guide)


if __name__ == "__main__":
    unittest.main()
