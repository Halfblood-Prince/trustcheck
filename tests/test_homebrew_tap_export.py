from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

from scripts import export_homebrew_tap

RUNTIME_HASH = "a" * 64
HELPER_HASH = "b" * 64
BUILD_HASH = "c" * 64
TRUSTCHECK_HASH = "d" * 64


def _pypi_payload(name: str, version: str, sha256: str) -> dict[str, object]:
    return {
        "urls": [
            {
                "filename": f"{name}-{version}-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": f"https://files.pythonhosted.org/packages/{name}-{version}.whl",
                "digests": {"sha256": "0" * 64},
            },
            {
                "filename": f"{name}-{version}.tar.gz",
                "packagetype": "sdist",
                "url": f"https://files.pythonhosted.org/packages/{name}-{version}.tar.gz",
                "digests": {"sha256": sha256},
            },
        ]
    }


class HomebrewTapExportTests(unittest.TestCase):
    def test_parse_lockfile_reads_pinned_packages_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            lockfile = Path(tmpdir) / "runtime.lock"
            lockfile.write_text(
                "\n".join(
                    [
                        "demo-runtime==1.2.3 \\",
                        f"    --hash=sha256:{RUNTIME_HASH} \\",
                        f"    --hash=sha256:{HELPER_HASH}",
                        "    # via trustcheck",
                    ]
                ),
                encoding="utf-8",
            )

            packages = export_homebrew_tap.parse_lockfile(lockfile)

        self.assertEqual(set(packages), {"demo-runtime"})
        self.assertEqual(packages["demo-runtime"].version, "1.2.3")
        self.assertEqual(
            packages["demo-runtime"].hashes,
            frozenset({RUNTIME_HASH, HELPER_HASH}),
        )

    def test_export_homebrew_tap_writes_release_metadata_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            runtime_lock = root / "runtime.lock"
            build_lock = root / "build.lock"
            checksums = root / "SHA256SUMS.txt"
            output_dir = root / "tap" / "trustcheck"
            runtime_lock.write_text(
                "\n".join(
                    [
                        "demo-runtime==1.2.3 \\",
                        f"    --hash=sha256:{RUNTIME_HASH}",
                    ]
                ),
                encoding="utf-8",
            )
            build_lock.write_text(
                "\n".join(
                    [
                        "build-helper==4.5.6 \\",
                        f"    --hash=sha256:{BUILD_HASH}",
                    ]
                ),
                encoding="utf-8",
            )
            checksums.write_text(
                f"{TRUSTCHECK_HASH}  dist/trustcheck-2.2.0.tar.gz\n",
                encoding="utf-8",
            )

            def fetch_json(project: str, version: str) -> Mapping[str, object]:
                payloads = {
                    ("trustcheck", "2.2.0"): _pypi_payload(
                        "trustcheck", "2.2.0", TRUSTCHECK_HASH
                    ),
                    ("demo-runtime", "1.2.3"): _pypi_payload(
                        "demo-runtime", "1.2.3", RUNTIME_HASH
                    ),
                    ("build-helper", "4.5.6"): _pypi_payload(
                        "build-helper", "4.5.6", BUILD_HASH
                    ),
                }
                return payloads[(project, version)]

            export_homebrew_tap.export_homebrew_tap(
                runtime_lock=runtime_lock,
                build_lock=build_lock,
                checksums=checksums,
                output_dir=output_dir,
                tag="v2.2.0",
                source_repository="Halfblood-Prince/trustcheck",
                source_commit="abc123",
                extra_packages=["build-helper"],
                fetch_json=fetch_json,
            )

            resources = (output_dir / "resources.rb").read_text(encoding="utf-8")
            release = json.loads((output_dir / "release.json").read_text(encoding="utf-8"))
            copied_lock = (output_dir / "runtime.lock").read_text(encoding="utf-8")

        self.assertIn('resource "build-helper" do', resources)
        self.assertIn('resource "demo-runtime" do', resources)
        self.assertIn(f'  sha256 "{BUILD_HASH}"', resources)
        self.assertEqual(release["package"]["version"], "2.2.0")
        self.assertEqual(release["package"]["sdist"]["sha256"], TRUSTCHECK_HASH)
        self.assertEqual(
            [resource["name"] for resource in release["resources"]],
            ["build-helper", "demo-runtime"],
        )
        self.assertIn("demo-runtime==1.2.3", copied_lock)


if __name__ == "__main__":
    unittest.main()
