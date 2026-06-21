from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from trustcheck.pre_commit import main


class PreCommitHookTests(unittest.TestCase):
    def test_scans_only_dependency_files_with_fast_hash_aware_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = root / "requirements.txt"
            ignored = root / "app.py"
            requirements.write_text("demo==1\n", encoding="utf-8")
            ignored.write_text("pass\n", encoding="utf-8")
            with patch("trustcheck.pre_commit.trustcheck_main", return_value=4) as run:
                result = main(
                    [
                        "--offline",
                        "--strict",
                        "--cache-dir",
                        "cache",
                        str(ignored),
                        str(requirements),
                        str(requirements),
                    ]
                )

        self.assertEqual(result, 4)
        command = run.call_args.args[0]
        self.assertIn("--fast", command)
        self.assertIn("--no-deps", command)
        self.assertIn("--with-osv", command)
        self.assertIn("--offline", command)
        self.assertIn("--strict", command)
        self.assertEqual(command[-2:], ["--cache-dir", "cache"])
        self.assertEqual(run.call_count, 1)

    def test_empty_file_list_succeeds(self) -> None:
        self.assertEqual(main([]), 0)

    def test_optional_flags_are_omitted_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            requirements = Path(directory) / "requirements.in"
            requirements.write_text("demo==1\n", encoding="utf-8")
            with patch("trustcheck.pre_commit.trustcheck_main", return_value=0) as run:
                self.assertEqual(main([str(requirements)]), 0)
        command = run.call_args.args[0]
        self.assertNotIn("--offline", command)
        self.assertNotIn("--strict", command)
        self.assertNotIn("--cache-dir", command)
