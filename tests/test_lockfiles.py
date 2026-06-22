from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packaging.requirements import Requirement

from trustcheck.lockfiles import (
    LockedPackage,
    LockfileResolution,
    _clean_requirement_entry,
    _evaluate_marker,
    _exact_requirement_version,
    _filename_from_location,
    _hash_table,
    _included_requirements_path,
    _is_registry_package,
    _legacy_artifact,
    _legacy_artifacts,
    _legacy_dependencies,
    _legacy_index_url,
    _lock_package_applies,
    _logical_requirement_lines,
    _marker_environment,
    _parse_hash,
    _pylock_artifact,
    _pylock_dependencies,
    _pylock_source,
    _resolve_lock_path,
    _string_list,
    _validate_requires_python,
    _validated_exact_requirement,
    is_supported_lockfile,
    load_lockfile,
    load_pip_tools_lock,
)
from trustcheck.resolver import ArtifactReference


class LockfileTests(unittest.TestCase):
    def test_supported_lockfile_names_are_case_insensitive(self) -> None:
        self.assertTrue(is_supported_lockfile(Path("UV.LOCK")))
        self.assertTrue(is_supported_lockfile(Path("poetry.lock")))
        self.assertTrue(is_supported_lockfile(Path("nested/PDM.lock")))
        self.assertTrue(is_supported_lockfile(Path("Pipfile.lock")))
        self.assertTrue(is_supported_lockfile(Path("pylock.toml")))
        self.assertTrue(is_supported_lockfile(Path("pylock.prod.toml")))
        self.assertFalse(is_supported_lockfile(Path("pylock.bad.name.toml")))
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

    def test_load_pylock_supports_markers_groups_indexes_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "pylock.prod.toml"
            path.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "locker"',
                        'requires-python = ">=3.11"',
                        'environments = ["sys_platform == \'linux\'"]',
                        'extras = ["security"]',
                        'dependency-groups = ["dev"]',
                        'default-groups = ["dev"]',
                        "",
                        "[[packages]]",
                        'name = "demo"',
                        'version = "1.0"',
                        'marker = "\'dev\' in dependency_groups"',
                        'index = "https://private.example/simple"',
                        'dependencies = [{name = "dep", version = "2.0"}]',
                        "[[packages.wheels]]",
                        'name = "demo-1.0-py3-none-any.whl"',
                        'url = "https://private.example/files/demo.whl"',
                        "size = 4",
                        f'hashes = {{sha256 = "{"a" * 64}", sha512 = "{"b" * 128}"}}',
                        "",
                        "[[packages]]",
                        'name = "inactive"',
                        'version = "9.0"',
                        'marker = "\'security\' in extras"',
                        "[packages.sdist]",
                        'name = "inactive-9.0.tar.gz"',
                        'url = "https://private.example/files/inactive.tar.gz"',
                        f'hashes = {{sha256 = "{"c" * 64}"}}',
                    ]
                ),
                encoding="utf-8",
            )

            resolution = load_lockfile(
                path,
                groups=["dev"],
                environment={
                    "python_version": "3.12",
                    "python_full_version": "3.12.1",
                    "sys_platform": "linux",
                },
            )

        self.assertEqual(resolution.format, "pylock.toml")
        self.assertEqual(resolution.requirements, ["demo==1.0"])
        package = resolution.packages[0]
        self.assertEqual(package.index_url, "https://private.example/simple")
        self.assertEqual(package.requires_dist, ("dep==2.0",))
        self.assertEqual(package.artifacts[0].size, 4)
        self.assertEqual(
            package.artifacts[0].hashes,
            (("sha256", "a" * 64), ("sha512", "b" * 128)),
        )

    def test_pylock_set_markers_work_with_older_packaging_versions(self) -> None:
        environment = _marker_environment({"python_version": "3.12"})
        environment["extras"] = {"security"}
        environment["dependency_groups"] = {"dev"}

        self.assertTrue(
            _evaluate_marker(
                "python_version >= '3.11' and 'security' in extras "
                "and 'docs' not in dependency_groups",
                environment,
                context="test",
            )
        )
        self.assertFalse(
            _evaluate_marker(
                "'security' not in extras or 'test' in dependency_groups",
                environment,
                context="test",
            )
        )

    def test_load_pylock_supports_archive_directory_vcs_and_duplicate_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "local").mkdir()
            path = root / "pylock.toml"
            path.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "locker"',
                        "",
                        "[[packages]]",
                        'name = "archive-demo"',
                        'version = "1.0"',
                        "[packages.archive]",
                        'path = "archive-demo-1.0.tar.gz"',
                        f'hashes = {{sha256 = "{"a" * 64}"}}',
                        "",
                        "[[packages]]",
                        'name = "archive-demo"',
                        'version = "1.0"',
                        "[packages.archive]",
                        'url = "https://example.com/archive-demo-1.0.whl"',
                        f'hashes = {{sha256 = "{"b" * 64}"}}',
                        "",
                        "[[packages]]",
                        'name = "local-demo"',
                        'version = "2.0"',
                        '[packages.directory]',
                        'path = "local"',
                        "",
                        "[[packages]]",
                        'name = "vcs-demo"',
                        'version = "3.0"',
                        "[packages.vcs]",
                        'type = "git"',
                        'url = "https://example.com/repo.git"',
                        'commit-id = "abcdef"',
                        'subdirectory = "python pkg"',
                    ]
                ),
                encoding="utf-8",
            )

            resolution = load_lockfile(path)

        self.assertEqual(len(resolution.packages), 3)
        archive = resolution.packages[0]
        self.assertEqual(len(archive.artifacts), 2)
        self.assertTrue(archive.artifacts[0].url.startswith("file:"))
        self.assertEqual(
            resolution.packages[1].artifacts[0].url,
            (root / "local").resolve().as_uri(),
        )
        self.assertIn(
            "@abcdef#subdirectory=python%20pkg",
            resolution.packages[2].artifacts[0].url or "",
        )

    def test_load_pylock_validates_required_fields_and_environment(self) -> None:
        cases = [
            ('created-by = "x"\npackages = []', "lock-version"),
            ('lock-version = "2.0"\ncreated-by = "x"\npackages = []', "unsupported"),
            ('lock-version = "bad"\ncreated-by = "x"\npackages = []', "invalid"),
            ('lock-version = "1.0"\npackages = []', "created-by"),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                'requires-python = "<3"\npackages = []',
                "does not satisfy",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                'environments = ["sys_platform == \'win32\'"]\npackages = []',
                "not supported",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                'extras = ["known"]\npackages = []',
                "unknown pylock extra",
            ),
        ]
        for payload, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "pylock.toml"
                path.write_text(payload, encoding="utf-8")
                kwargs = {"extras": ["missing"]} if "extra" in message else {}
                with self.assertRaisesRegex(ValueError, message):
                    load_lockfile(
                        path,
                        environment={
                            "python_version": "3.12",
                            "python_full_version": "3.12.0",
                            "sys_platform": "linux",
                        },
                        **kwargs,
                    )

    def test_load_pylock_rejects_invalid_package_sources_and_hashes(self) -> None:
        packages = [
            ('name = "demo"\nversion = "1"', "exactly one source"),
            (
                'name = "demo"\nversion = "1"\n'
                '[packages.archive]\nurl = "https://example.com/demo.whl"',
                "hashes are required",
            ),
            (
                'name = "demo"\nversion = "1"\n'
                '[packages.directory]\npath = 3',
                "directory source",
            ),
            (
                'name = "demo"\nversion = "1"\n'
                '[packages.vcs]\ntype = "git"\nurl = "x"',
                "incomplete",
            ),
            (
                'name = "demo"\nversion = "1"\n'
                '[packages.vcs]\ntype = "git"\ncommit-id = "a"\n'
                'url = "x"\npath = "x"',
                "exactly one",
            ),
        ]
        for package, message in packages:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "pylock.toml"
                path.write_text(
                    'lock-version = "1.0"\ncreated-by = "x"\n'
                    f"[[packages]]\n{package}\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, message):
                    load_lockfile(path)

    def test_load_pipfile_lock_preserves_hashes_groups_and_indexes(self) -> None:
        payload = {
            "_meta": {
                "sources": [
                    {
                        "name": "private",
                        "url": "https://user:secret@private.example/simple",
                    }
                ]
            },
            "default": {
                "demo": {
                    "version": "==1.2.3",
                    "hashes": [f"sha256:{'a' * 64}", f"sha256:{'b' * 64}"],
                    "index": "private",
                    "markers": "python_version >= '3.11'",
                },
                "local": {"path": "."},
            },
            "develop": {"pytest": {"version": "==9.0.0", "hashes": []}},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pipfile.lock"
            path.write_text(json.dumps(payload), encoding="utf-8")
            resolution = load_lockfile(
                path,
                groups=["default"],
                environment={"python_version": "3.12"},
            )

        self.assertEqual(resolution.format, "Pipfile.lock")
        self.assertEqual(resolution.requirements, ["demo==1.2.3"])
        self.assertEqual(len(resolution.packages[0].artifacts), 2)
        self.assertIn("secret", resolution.packages[0].index_url or "")

    def test_load_pipfile_lock_rejects_invalid_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pipfile.lock"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid Pipfile"):
                load_lockfile(path)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "top-level object"):
                load_lockfile(path)
            path.write_text(json.dumps({"default": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be an object"):
                load_lockfile(path)
            path.write_text(
                json.dumps({"default": {"demo": {"version": ">=1"}}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "not pinned"):
                load_lockfile(path)
            path.write_text(
                json.dumps({"default": {"local": {"path": "."}}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "no supported"):
                load_lockfile(path)
            with self.assertRaisesRegex(ValueError, "unknown Pipfile"):
                load_lockfile(path, groups=["qa"])

    def test_load_pip_tools_lock_supports_nested_hash_pinned_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            nested = root / "nested.txt"
            nested.write_text(
                f"dep==2.0 --hash=sha256:{'b' * 64}\n",
                encoding="utf-8",
            )
            path = root / "requirements.txt"
            path.write_text(
                "\n".join(
                    [
                        "--require-hashes",
                        "-r nested.txt",
                        "demo==1.0 \\",
                        f"  --hash=sha256:{'a' * 64}",
                    ]
                ),
                encoding="utf-8",
            )
            resolution = load_pip_tools_lock(path)

        assert resolution is not None
        self.assertEqual(resolution.format, "pip-tools")
        self.assertEqual(resolution.versions, {"dep": "2.0", "demo": "1.0"})
        self.assertEqual(
            resolution.packages[1].artifacts[0].hashes,
            (("sha256", "a" * 64),),
        )

    def test_load_pip_tools_lock_handles_unhashed_and_cyclic_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            plain = root / "plain.txt"
            plain.write_text("demo==1.0\n", encoding="utf-8")
            self.assertIsNone(load_pip_tools_lock(plain))

            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("-r second.txt\n", encoding="utf-8")
            second.write_text("-r first.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cyclic"):
                load_pip_tools_lock(first)

            bad = root / "bad.txt"
            bad.write_text("demo==1 --hash=sha256:not-hex\n", encoding="utf-8")
            self.assertIsNone(load_pip_tools_lock(bad))

    def test_legacy_lockfiles_preserve_artifacts_and_dependencies(self) -> None:
        payload = {
            "package": [
                {
                    "name": "demo",
                    "version": "1.0",
                    "source": {"registry": "https://private.example/simple"},
                    "dependencies": ["dep>=1"],
                    "sdist": {
                        "url": "https://private.example/demo.tar.gz",
                        "hash": f"sha256:{'a' * 64}",
                        "size": 3,
                    },
                    "wheels": [
                        {
                            "url": "https://private.example/demo.whl",
                            "hash": f"sha256:{'b' * 64}",
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "uv.lock"
            path.write_text("version = 1", encoding="utf-8")
            with patch("trustcheck.lockfiles.tomllib.load", return_value=payload):
                resolution = load_lockfile(path)

        package = resolution.packages[0]
        self.assertEqual(package.index_url, "https://private.example/simple")
        self.assertEqual(package.requires_dist, ("dep>=1",))
        self.assertEqual(len(package.artifacts), 2)

    def test_lockfile_helper_models_and_requirement_parsing(self) -> None:
        artifact = ArtifactReference(hashes=(("sha256", "aa"),))
        resolution = LockfileResolution(
            requirements=["Demo==1"],
            versions={"demo": "1"},
            packages=(
                LockedPackage(
                    name="Demo",
                    version="1",
                    requirement="Demo==1",
                    artifacts=(artifact,),
                ),
            ),
        )
        self.assertEqual(resolution.artifacts, {"demo": (artifact,)})
        self.assertEqual(
            _clean_requirement_entry(
                "demo==1 --hash sha256:AA  # generated"
            ),
            ("demo==1", (("sha256", "aa"),)),
        )
        self.assertIsNone(_clean_requirement_entry("--require-hashes"))
        self.assertIsNone(_clean_requirement_entry("# comment"))
        self.assertEqual(_exact_requirement_version(Requirement("demo===1")), "1")
        self.assertIsNone(_exact_requirement_version(Requirement("demo==1.*")))
        self.assertIsNone(_exact_requirement_version(Requirement("demo>=1")))
        self.assertIsNone(
            _exact_requirement_version(Requirement("demo===not-a-version"))
        )

    def test_pip_tools_rejects_hashed_but_unpinned_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "requirements.txt"
            path.write_text(
                f"demo>=1 --hash=sha256:{'a' * 64}\ninvalid ??? "
                f"--hash=sha256:{'b' * 64}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "no exact hash-pinned"):
                load_pip_tools_lock(path)

    def test_pylock_additional_validation_paths(self) -> None:
        cases = [
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                'dependency-groups = ["dev"]\npackages = []',
                {"groups": ["qa"]},
                "unknown pylock dependency group",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"',
                {},
                "packages array",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\npackages = [1]',
                {},
                "expected a table",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                '[[packages]]\nname = "demo"\nversion = "1"\nmarker = 3\n'
                '[packages.directory]\npath = "."',
                {},
                "invalid marker",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                '[[packages]]\nversion = "1"\n[packages.directory]\npath = "."',
                {},
                "missing name",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                '[[packages]]\nname = "demo"\nversion = "1"\nindex = 3\n'
                '[packages.directory]\npath = "."',
                {},
                "invalid index",
            ),
            (
                'lock-version = "1.0"\ncreated-by = "x"\n'
                '[[packages]]\nname = "demo"\n[packages.directory]\npath = "."',
                {},
                "no supported",
            ),
        ]
        for payload, kwargs, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "pylock.toml"
                path.write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    load_lockfile(path, **kwargs)

    def test_pipfile_additional_entry_shapes(self) -> None:
        payload = {
            "_meta": {"sources": [3, {"name": 3, "url": None}]},
            "default": {
                "ignored": "bad",
                "inactive": {
                    "version": "==1",
                    "markers": "python_version < '2'",
                },
                "missing": {},
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "Pipfile.lock"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "has no exact version"):
                load_lockfile(path, environment={"python_version": "3.12"})

            path.write_text(
                json.dumps(
                    {
                        "default": {
                            "demo": {
                                "version": "==1",
                                "hashes": [3, f"sha256:{'a' * 64}"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            resolution = load_lockfile(path)
        self.assertEqual(len(resolution.packages[0].artifacts), 1)

    def test_pylock_source_and_artifact_helper_errors(self) -> None:
        path = Path("pylock.toml")
        with self.assertRaisesRegex(ValueError, "non-empty array"):
            _pylock_source({"wheels": []}, path=path, index=1)
        with self.assertRaisesRegex(ValueError, "wheels must be an array"):
            _pylock_source(
                {
                    "sdist": {
                        "url": "https://example.com/demo.tar.gz",
                        "hashes": {"sha256": "aa"},
                    },
                    "wheels": "bad",
                },
                path=path,
                index=1,
            )
        with self.assertRaisesRegex(ValueError, "invalid pylock VCS"):
            _pylock_source({"vcs": "bad"}, path=path, index=1)
        with tempfile.TemporaryDirectory() as tmpdir:
            lock = Path(tmpdir) / "pylock.toml"
            source_type, _, url = _pylock_source(
                {
                    "vcs": {
                        "type": "git",
                        "path": "repo",
                        "commit-id": "abc",
                    }
                },
                path=lock,
                index=1,
            )
            self.assertEqual(source_type, "vcs")
            self.assertIn("git+file:", url or "")

        with self.assertRaisesRegex(ValueError, "invalid pylock artifact"):
            _pylock_artifact("bad", path=path, context="test", kind="wheel")
        with self.assertRaisesRegex(ValueError, "needs url or path"):
            _pylock_artifact({}, path=path, context="test", kind="wheel")
        with self.assertRaisesRegex(ValueError, "invalid artifact size"):
            _pylock_artifact(
                {
                    "url": "https://example.com/demo.whl",
                    "hashes": {"sha256": "aa"},
                    "size": -1,
                },
                path=path,
                context="test",
                kind="wheel",
            )
        artifact = _pylock_artifact(
            {
                "url": "https://example.com/demo.whl",
                "hashes": {"sha256": "aa"},
            },
            path=path,
            context="test",
            kind="wheel",
        )
        self.assertEqual(artifact.filename, "demo.whl")

    def test_legacy_helpers_cover_poetry_pdm_and_metadata_shapes(self) -> None:
        path = Path("pdm.lock")
        pdm = _legacy_artifacts(
            {"name": "demo"},
            payload={
                "metadata": {
                    "files": {
                        "demo": [
                            {"file": "demo.whl", "hash": "sha256:aa"},
                            3,
                        ]
                    }
                }
            },
            kind="pdm.lock",
            path=path,
        )
        self.assertEqual(pdm[0].filename, "demo.whl")
        poetry = _legacy_artifacts(
            {"files": [{"file": "demo.tar.gz", "hashes": {"sha256": "bb"}}]},
            payload={},
            kind="poetry.lock",
            path=path,
        )
        self.assertEqual(poetry[0].hashes, (("sha256", "bb"),))
        local = _legacy_artifact(
            {"path": "demo.whl", "size": -1},
            kind="archive",
            path=path,
        )
        self.assertTrue(local.path)
        self.assertIsNone(local.size)
        self.assertEqual(
            _legacy_index_url(
                {"source": {"url": "https://poetry.example/simple"}},
                {},
                "poetry.lock",
            ),
            "https://poetry.example/simple",
        )
        self.assertEqual(
            _legacy_index_url(
                {},
                {
                    "metadata": {
                        "sources": [{"url": "https://pdm.example/simple"}]
                    }
                },
                "pdm.lock",
            ),
            "https://pdm.example/simple",
        )
        self.assertIsNone(_legacy_index_url({}, {}, "pdm.lock"))
        self.assertEqual(
            _legacy_dependencies({"dependencies": {"dep": ">=1", "plain": 3}}),
            ("dep>=1", "plain"),
        )
        self.assertEqual(_legacy_dependencies({}), ())
        self.assertEqual(
            _pylock_dependencies(
                [{"name": "dep"}, {"name": "pinned", "version": "2"}, 3]
            ),
            ("dep", "pinned==2"),
        )
        self.assertEqual(_pylock_dependencies("bad"), ())

    def test_validation_hash_marker_and_path_helpers(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid locked package"):
            _validated_exact_requirement(
                "demo",
                "not valid",
                path=Path("lock"),
                index=1,
            )
        environment = _marker_environment({"python_version": "3.12"})
        self.assertEqual(environment["python_version"], "3.12")
        with self.assertRaisesRegex(ValueError, "invalid environment marker"):
            _lock_package_applies(
                {"marker": "bad >>> marker"},
                environment,
                path=Path("lock"),
                index=1,
            )
        _validate_requires_python(None, environment, context="test")
        with self.assertRaisesRegex(ValueError, "invalid requires-python"):
            _validate_requires_python(3, environment, context="test")
        with self.assertRaisesRegex(ValueError, "invalid requires-python"):
            _validate_requires_python("=>3", environment, context="test")
        self.assertEqual(
            _string_list(None, field_name="test", path=Path("lock")),
            [],
        )
        with self.assertRaisesRegex(ValueError, "array of strings"):
            _string_list([3], field_name="test", path=Path("lock"))
        self.assertEqual(_hash_table(None, context="test", required=False), ())
        with self.assertRaisesRegex(ValueError, "invalid artifact hash"):
            _hash_table({3: "aa"}, context="test", required=False)
        with self.assertRaisesRegex(ValueError, "hashes are required"):
            _hash_table({}, context="test", required=True)
        with self.assertRaisesRegex(ValueError, "invalid artifact hash"):
            _parse_hash("sha256", context="test")
        with self.assertRaisesRegex(ValueError, "hash algorithm"):
            _parse_hash("bad algorithm:aa", context="test")
        with self.assertRaisesRegex(ValueError, "hash digest"):
            _parse_hash("sha256:not-hex", context="test")
        self.assertEqual(_parse_hash("SHA256=AA", context="test"), ("sha256", "aa"))

        base = Path.cwd()
        self.assertEqual(
            _included_requirements_path("--requirement 'nested.txt'", base),
            base / "nested.txt",
        )
        absolute = (base / "absolute.txt").resolve()
        self.assertEqual(
            _included_requirements_path(f"-r {absolute}", base),
            absolute,
        )
        self.assertIsNone(_included_requirements_path("demo==1", base))
        self.assertEqual(_resolve_lock_path(Path("lock"), str(absolute)), absolute)
        self.assertIsNone(_filename_from_location(None))
        self.assertEqual(_filename_from_location("https://example.com/a%20b.whl"), "a b.whl")

    def test_logical_requirement_lines_retains_unfinished_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "requirements.txt"
            path.write_text("demo==1 \\", encoding="utf-8")
            self.assertEqual(_logical_requirement_lines(path), ["demo==1"])
