from __future__ import annotations

import io
import re
import shlex
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import trustcheck
from trustcheck.cli import build_parser, main
from trustcheck.contract import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION

ROOT = Path(__file__).parents[1]
RELEASE_VERSION = "2.1.1"
RELEASE_DATE = "2026-06-28"


def _documented_trustcheck_commands() -> list[tuple[Path, list[str]]]:
    paths = [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]
    commands: list[tuple[Path, list[str]]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"\\\r?\n\s*", " ", text)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("trustcheck "):
                continue
            argv = shlex.split(stripped, posix=True)
            for operator in (">", ">>", "|", "&&", "||"):
                if operator in argv:
                    argv = argv[: argv.index(operator)]
            commands.append((path, argv[1:]))
    return commands


class ReleaseReadinessTests(unittest.TestCase):
    def test_documented_cli_commands_parse(self) -> None:
        commands = _documented_trustcheck_commands()
        self.assertGreaterEqual(len(commands), 40)

        for path, argv in commands:
            with self.subTest(path=path.relative_to(ROOT), argv=argv):
                parser = build_parser()
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    try:
                        parser.parse_args(argv)
                    except SystemExit as exc:
                        self.assertEqual(exc.code, 0)

    def test_cli_version_reports_package_and_schema_versions(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn(f"trustcheck {trustcheck.__version__}", stdout.getvalue())
        self.assertIn(f"report schema {JSON_SCHEMA_VERSION}", stdout.getvalue())

    def test_release_and_schema_versions_are_consistent(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        docs_index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        json_contract = (ROOT / "docs" / "reference" / "json-contract.md").read_text(
            encoding="utf-8"
        )
        docs_changelog = (ROOT / "docs" / "changelog.md").read_text(encoding="utf-8")

        self.assertIn(f"## [{RELEASE_VERSION}] - {RELEASE_DATE}", changelog)
        self.assertIn(
            f"Package release `{RELEASE_VERSION}` emits machine-readable report schema "
            f"`{JSON_SCHEMA_VERSION}`.",
            changelog,
        )
        self.assertIn(f"advanced the schema to `{JSON_SCHEMA_VERSION}`", changelog)
        self.assertIn(f"JSON schema `{JSON_SCHEMA_VERSION}`", readme)
        self.assertIn(f"JSON schema `{JSON_SCHEMA_VERSION}`", docs_index)
        self.assertIn(
            f'JSON_SCHEMA_VERSION = "{JSON_SCHEMA_VERSION}"',
            json_contract,
        )
        self.assertIn(JSON_SCHEMA_ID, json_contract)
        self.assertIn(f"Current release milestone: `{RELEASE_VERSION}`", docs_changelog)
        self.assertIn(
            f"Current development report schema: `{JSON_SCHEMA_VERSION}`",
            docs_changelog,
        )

    def test_github_action_docs_use_current_major_ref(self) -> None:
        current_major = f"v{RELEASE_VERSION.split('.', 1)[0]}"
        documentation = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [
                ROOT / "README.md",
                *(ROOT / "docs").rglob("*.md"),
            ]
        )

        self.assertIn(f"Halfblood-Prince/trustcheck@{current_major}", documentation)
        self.assertIn(
            f"compatible major ref `{current_major}`",
            documentation,
        )
        self.assertIn(
            f"Use `@{current_major}` for compatible updates",
            documentation,
        )
        if current_major != "v1":
            self.assertNotIn("Halfblood-Prince/trustcheck@v1", documentation)

    def test_public_support_links_use_stable_github_pages(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
            project_urls = tomllib.load(pyproject_file)["project"]["urls"]

        self.assertEqual(
            project_urls["Issues"],
            "https://github.com/Halfblood-Prince/trustcheck/issues",
        )
        self.assertEqual(
            project_urls["Security"],
            "https://github.com/Halfblood-Prince/trustcheck/security/advisories/new",
        )

        public_files = [
            ROOT / "README.md",
            ROOT / "SECURITY.md",
            ROOT / "CONTRIBUTING.md",
            ROOT / "pyproject.toml",
        ]
        for path in public_files:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotIn("discord.com/channels/", path.read_text(encoding="utf-8"))

    def test_project_license_metadata_matches_license_file(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
            project = tomllib.load(pyproject_file)["project"]

        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertEqual(project["license"], "LicenseRef-Trustcheck-Personal-Use")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertTrue(license_text.startswith("Trustcheck Personal Use License\n"))

    def test_lockfile_documentation_does_not_repeat_the_old_limitation(self) -> None:
        documentation = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]
        )

        self.assertNotIn("does not yet ingest lockfiles", documentation)
        for filename in (
            "pylock.toml",
            "Pipfile.lock",
            "uv.lock",
            "poetry.lock",
            "pdm.lock",
        ):
            self.assertIn(filename, documentation)
