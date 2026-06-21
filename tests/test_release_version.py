from __future__ import annotations

import io
import tarfile
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.verify_release_version import _expected_version, verify_artifact_version


class ReleaseVersionTests(unittest.TestCase):
    def test_artifact_metadata_must_exactly_match_release_version(self) -> None:
        metadata = b"Metadata-Version: 2.4\nName: trustcheck\nVersion: 1.10.0\n\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "trustcheck-1.10.0-py3-none-any.whl"
            sdist = root / "trustcheck-1.10.0.tar.gz"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("trustcheck-1.10.0.dist-info/METADATA", metadata)
            with tarfile.open(sdist, "w:gz") as archive:
                info = tarfile.TarInfo("trustcheck-1.10.0/PKG-INFO")
                info.size = len(metadata)
                archive.addfile(info, io.BytesIO(metadata))

            verify_artifact_version(wheel, "1.10.0")
            verify_artifact_version(sdist, "1.10.0")
            with self.assertRaisesRegex(ValueError, "does not match tag"):
                verify_artifact_version(wheel, "1.10.1")

    def test_tag_normalization_rejects_ambiguous_release_versions(self) -> None:
        self.assertEqual(_expected_version(tag="v1.10.0", expected=None), "1.10.0")
        with self.assertRaisesRegex(ValueError, "normalized"):
            _expected_version(tag="v01.10.0", expected=None)

    def test_workflows_reject_unknown_or_mismatched_source_versions(self) -> None:
        project = Path("pyproject.toml").read_text(encoding="utf-8")
        source_workflow = Path(".github/workflows/source-build.yml").read_text(
            encoding="utf-8"
        )
        release_workflow = Path(".github/workflows/publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('fallback_version = "0.0.0+source"', project)
        self.assertNotIn('fallback_version = "0+unknown"', project)
        self.assertIn(
            "SETUPTOOLS_SCM_PRETEND_VERSION: 0.0.0+source",
            source_workflow,
        )
        self.assertIn(
            "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK: 0.0.0+source",
            source_workflow,
        )
        self.assertIn("--expected 0.0.0+source", source_workflow)
        self.assertIn(
            "SETUPTOOLS_SCM_PRETEND_VERSION: ${{ github.ref_name }}",
            release_workflow,
        )
        self.assertIn(
            "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_TRUSTCHECK: ${{ github.ref_name }}",
            release_workflow,
        )
        self.assertGreaterEqual(
            release_workflow.count("scripts/verify_release_version.py"),
            2,
        )
        self.assertIn('--tag "$GITHUB_REF_NAME"', release_workflow)


if __name__ == "__main__":
    unittest.main()
