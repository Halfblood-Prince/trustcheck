from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustcheck.lockfiles import (
    _is_registry_package,
    _lock_package_applies,
    is_supported_lockfile,
    load_lockfile,
)


class LockfileTests(unittest.TestCase):
    def test_supported_lockfile_names_are_case_insensitive(self) -> None:
        self.assertTrue(is_supported_lockfile(Path("UV.LOCK")))
        self.assertTrue(is_supported_lockfile(Path("poetry.lock")))
        self.assertTrue(is_supported_lockfile(Path("nested/PDM.lock")))
        self.assertFalse(is_supported_lockfile(Path("requirements.txt")))

    def test_load_lockfile_rejects_non_mapping_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "uv.lock"
            path.write_text("version = 1", encoding="utf-8")
            with patch(
                "trustcheck.lockfiles.tomllib.load",
                return_value=[],
            ):
                with self.assertRaisesRegex(ValueError, "top-level table"):
                    load_lockfile(path)

    def test_load_lockfile_skips_invalid_entries_and_duplicate_versions(self) -> None:
        payload = {
            "package": [
                "not-a-table",
                {"name": "", "version": "1.0.0"},
                {"name": "missing-version"},
                {
                    "name": "local-project",
                    "version": "0.1.0",
                    "source": {"editable": "."},
                },
                {
                    "name": "Demo_Package",
                    "version": "1.2.3",
                    "source": {"registry": "https://pypi.org/simple"},
                },
                {
                    "name": "demo-package",
                    "version": "1.2.3",
                    "source": {"registry": "https://pypi.org/simple"},
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "uv.lock"
            path.write_text("version = 1", encoding="utf-8")
            with patch(
                "trustcheck.lockfiles.tomllib.load",
                return_value=payload,
            ):
                resolution = load_lockfile(path)

        self.assertEqual(resolution.requirements, ["Demo_Package==1.2.3"])
        self.assertEqual(resolution.versions, {"demo-package": "1.2.3"})

    def test_load_lockfile_rejects_invalid_package_and_empty_resolution(self) -> None:
        cases = [
            (
                {"package": [{"name": "bad name", "version": "1.0.0"}]},
                "invalid locked package",
            ),
            ({"package": ["not-a-table"]}, "no supported locked packages"),
        ]
        for payload, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "uv.lock"
                path.write_text("version = 1", encoding="utf-8")
                with patch(
                    "trustcheck.lockfiles.tomllib.load",
                    return_value=payload,
                ):
                    with self.assertRaisesRegex(ValueError, message):
                        load_lockfile(path)

    def test_marker_shapes_are_evaluated_and_invalid_markers_are_rejected(self) -> None:
        environment = {"python_version": "3.12", "extra": ""}
        path = Path("uv.lock")
        cases = [
            ({}, True),
            ({"marker": "python_version >= '3.11'"}, True),
            ({"markers": [3, "python_version < '3.0'"]}, False),
            ({"markers": {"main": "python_version >= '3.11'", "ignored": 3}}, True),
            ({"resolution-markers": ["python_version >= '3.11'"]}, True),
            ({"marker": 3}, True),
        ]
        for package, expected in cases:
            with self.subTest(package=package):
                self.assertEqual(
                    _lock_package_applies(
                        package,
                        environment,
                        path=path,
                        index=1,
                    ),
                    expected,
                )

        with self.assertRaisesRegex(ValueError, "invalid environment marker"):
            _lock_package_applies(
                {"marker": "python_version >>> '3.11'"},
                environment,
                path=path,
                index=2,
            )

    def test_registry_package_detection_covers_supported_lockfile_formats(self) -> None:
        cases = [
            ({}, "uv.lock", True),
            ({"source": {"registry": "https://pypi.org/simple"}}, "uv.lock", True),
            ({"source": "registry"}, "uv.lock", False),
            ({}, "poetry.lock", True),
            ({"source": {"type": "legacy"}}, "poetry.lock", True),
            ({"source": {"type": "git"}}, "poetry.lock", False),
            ({}, "pdm.lock", True),
            ({"path": "../local"}, "pdm.lock", False),
            ({"url": "https://example.com/demo.whl"}, "pdm.lock", False),
        ]
        for package, lockfile_kind, expected in cases:
            with self.subTest(package=package, lockfile_kind=lockfile_kind):
                self.assertEqual(
                    _is_registry_package(package, lockfile_kind),
                    expected,
                )
