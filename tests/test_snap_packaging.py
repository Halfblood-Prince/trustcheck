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
        self.assertIn("title: TrustCheck Package Scanner", snapcraft)
        self.assertIn(
            "summary: Audit Python packages, provenance, dependencies, and vulnerabilities",
            snapcraft,
        )
        self.assertIn("icon: snap/gui/icon.png", snapcraft)
        self.assertIn("**What TrustCheck examines**", snapcraft)
        self.assertIn("**Quick start**", snapcraft)
        self.assertIn("trustcheck scan -f requirements.txt --policy strict", snapcraft)
        self.assertIn("base: core24", snapcraft)
        self.assertIn("grade: stable", snapcraft)
        self.assertIn("confinement: strict", snapcraft)
        self.assertIn("license: Proprietary", snapcraft)
        self.assertIn("command: bin/trustcheck", snapcraft)
        self.assertIn("XDG_CACHE_HOME: $SNAP_USER_COMMON/cache", snapcraft)
        self.assertIn("XDG_CONFIG_HOME: $SNAP_USER_COMMON/config", snapcraft)
        self.assertIn("XDG_DATA_HOME: $SNAP_USER_COMMON/data", snapcraft)
        self.assertIn("plugin: python", snapcraft)
        self.assertIn("source: .", snapcraft)
        self.assertIn("- home", snapcraft)
        self.assertIn("- network", snapcraft)
        self.assertIn("- removable-media", snapcraft)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK", snapcraft)
        self.assertIn("CRAFT_PROJECT_VERSION", snapcraft)
        self.assertIn("$CRAFT_PART_BUILD/pyproject.toml", snapcraft)

        fallback_override = snapcraft.index("fallback_version =")
        version_override = snapcraft.index(
            "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK"
        )
        default_build = snapcraft.index("craftctl default")

        self.assertLess(fallback_override, version_override)
        self.assertLess(version_override, default_build)

    def test_snapcraft_project_declares_supported_cpu_platforms(self) -> None:
        snapcraft = (ROOT / "snap" / "snapcraft.yaml").read_text(encoding="utf-8")

        for platform in ("amd64", "arm64", "armhf"):
            with self.subTest(platform=platform):
                self.assertRegex(snapcraft, rf"(?m)^  {platform}:$")
        self.assertNotRegex(snapcraft, r"(?m)^  i386:$")

    def test_snap_store_icon_meets_snapcraft_requirements(self) -> None:
        icon = ROOT / "snap" / "gui" / "icon.png"

        self.assertTrue(icon.is_file())
        contents = icon.read_bytes()
        self.assertLess(icon.stat().st_size, 256 * 1024)
        self.assertEqual(contents[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(int.from_bytes(contents[16:20], "big"), 256)
        self.assertEqual(int.from_bytes(contents[20:24], "big"), 256)

    def test_release_jobs_fan_out_after_coverage(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("needs: coverage-build", _job_block(workflow, "clam-av"))
        self.assertIn("needs: coverage-build", _job_block(workflow, "publish-pypi"))
        self.assertIn(
            "- coverage-build",
            _job_block(workflow, "publish-github-action"),
        )
        self.assertIn(
            "needs: coverage-build",
            _job_block(workflow, "build-windows-executable"),
        )

    def test_clam_av_precedes_snap_qa_and_snap_publish(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        clam_av = _job_block(workflow, "clam-av")
        qa = _job_block(workflow, "snap-qa")
        publisher = _job_block(workflow, "publish-snap")

        self.assertIn("name: dist-${{ github.sha }}", clam_av)
        self.assertIn("clamscan", clam_av)
        self.assertIn("needs: clam-av", qa)
        self.assertIn("needs: snap-qa", publisher)

    def test_snap_qa_builds_lints_installs_and_attests_exact_artifact(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        qa = _job_block(workflow, "snap-qa")

        ordered_markers = (
            "Set release version in Snap metadata",
            "Require Snap Store credentials",
            "uses: snapcore/action-build@3bdaa03e1ba6bf59a65f84a751d943d549a54e79",
            "Validate Snap Store access",
            'snapcraft lint "$SNAP_PATH"',
            "Verify built snap metadata",
            'sudo snap install --dangerous "$SNAP_PATH"',
            "snap run trustcheck --version",
            'export PATH="/snap/bin:$PATH"',
            "trustcheck --help",
            "trustcheck inspect sampleproject",
            "unexpected_verification_error",
            "actions/attest-build-provenance@a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            "Upload verified snap",
        )
        positions = [qa.index(marker) for marker in ordered_markers]

        self.assertEqual(positions, sorted(positions))
        self.assertIn("snapcraft whoami", qa)
        self.assertIn("snapcraft status trustcheck", qa)
        self.assertIn("secrets.SNAPCRAFT_STORE_CREDENTIALS", qa)
        self.assertIn('test "$(command -v trustcheck)" = "/snap/bin/trustcheck"', qa)
        self.assertIn("--version 4.0.0", qa)
        self.assertIn('report["coverage"]["verified_files"] > 0', qa)
        self.assertIn("snap-${{ github.sha }}", qa)
        self.assertIn("${{ steps.snapcraft.outputs.snap }}.sha256", qa)

    def test_snap_store_publishes_verified_artifact_to_stable(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        publisher = _job_block(workflow, "publish-snap")

        self.assertIn("secrets.SNAPCRAFT_STORE_CREDENTIALS", publisher)
        self.assertIn("name: snap-${{ github.sha }}", publisher)
        self.assertIn(
            "uses: snapcore/action-publish@214b86e5ca036ead1668c79afb81e550e6c54d40",
            publisher,
        )
        self.assertIn("snap: ${{ steps.snap.outputs.path }}", publisher)
        self.assertIn("release: stable", publisher)
        self.assertIn("sudo snap install snapcraft --classic", publisher)
        self.assertIn('snapcraft upload-metadata "$SNAP_PATH" --force', publisher)
        self.assertLess(
            publisher.index(
                "uses: snapcore/action-publish@214b86e5ca036ead1668c79afb81e550e6c54d40"
            ),
            publisher.index('snapcraft upload-metadata "$SNAP_PATH" --force'),
        )

    def test_snap_installation_and_path_troubleshooting_is_documented(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installation = (
            ROOT / "docs" / "getting-started" / "installation.md"
        ).read_text(encoding="utf-8")

        for documentation in (readme, installation):
            self.assertIn("sudo snap install trustcheck", documentation)
            self.assertIn("snap run trustcheck", documentation)
            self.assertIn('export PATH="/snap/bin:$PATH"', documentation)


if __name__ == "__main__":
    unittest.main()
