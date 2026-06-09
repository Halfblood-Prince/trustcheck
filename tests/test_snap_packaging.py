from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


def _job_block(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job {job_name!r} was not found")
    return match.group(1)


class SnapPackagingTests(unittest.TestCase):
    def test_snapcraft_project_packages_the_cli_with_strict_confinement(self) -> None:
        snapcraft = (ROOT / "snap" / "snapcraft.yaml").read_text(encoding="utf-8")

        self.assertIn("name: trustcheck", snapcraft)
        self.assertIn("base: core24", snapcraft)
        self.assertIn("grade: stable", snapcraft)
        self.assertIn("confinement: strict", snapcraft)
        self.assertIn("license: Proprietary", snapcraft)
        self.assertIn("command: bin/trustcheck", snapcraft)
        self.assertIn("plugin: python", snapcraft)
        self.assertIn("source: .", snapcraft)
        self.assertIn("- home", snapcraft)
        self.assertIn("- network", snapcraft)
        self.assertIn("- removable-media", snapcraft)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK", snapcraft)
        self.assertIn("CRAFT_PROJECT_VERSION", snapcraft)

    def test_snap_qa_precedes_all_parallel_publishers(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        publishers = (
            "publish-pypi",
            "publish-github-action",
            "publish-snap",
        )

        for job_name in publishers:
            with self.subTest(job=job_name):
                block = _job_block(workflow, job_name)
                self.assertIn("- coverage-build", block)
                self.assertIn("- snap-qa", block)
                for other_publisher in publishers:
                    if other_publisher != job_name:
                        self.assertNotIn(f"- {other_publisher}", block)

    def test_snap_qa_builds_lints_installs_and_attests_exact_artifact(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        qa = _job_block(workflow, "snap-qa")

        ordered_markers = (
            "Set release version in Snap metadata",
            "Require Snap Store credentials",
            "uses: snapcore/action-build@v1",
            "Validate Snap Store access",
            'snapcraft lint "$SNAP_PATH"',
            "Verify built snap metadata",
            'sudo snap install --dangerous "$SNAP_PATH"',
            "/snap/bin/trustcheck --version",
            "/snap/bin/trustcheck --help",
            "actions/attest-build-provenance@v4",
            "Upload verified snap",
        )
        positions = [qa.index(marker) for marker in ordered_markers]

        self.assertEqual(positions, sorted(positions))
        self.assertIn("snapcraft whoami", qa)
        self.assertIn("snapcraft status trustcheck", qa)
        self.assertIn("secrets.SNAPCRAFT_STORE_CREDENTIALS", qa)
        self.assertIn("snap-${{ github.sha }}", qa)
        self.assertIn("${{ steps.snapcraft.outputs.snap }}.sha256", qa)

    def test_snap_store_publishes_verified_artifact_to_stable(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        publisher = _job_block(workflow, "publish-snap")

        self.assertIn("secrets.SNAPCRAFT_STORE_CREDENTIALS", publisher)
        self.assertIn("name: snap-${{ github.sha }}", publisher)
        self.assertIn("uses: snapcore/action-publish@v1", publisher)
        self.assertIn("snap: ${{ steps.snap.outputs.path }}", publisher)
        self.assertIn("release: stable", publisher)

    def test_store_and_marketplace_one_time_setup_is_documented(self) -> None:
        guide = (ROOT / "docs" / "guides" / "release-publishing.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("snapcraft register trustcheck", guide)
        self.assertIn("SNAPCRAFT_STORE_CREDENTIALS", guide)
        self.assertIn("Publish this Action to the GitHub Marketplace", guide)
        self.assertIn("Marketplace Developer Agreement", guide)
        self.assertIn("Halfblood-Prince/trustcheck-action", guide)


if __name__ == "__main__":
    unittest.main()
