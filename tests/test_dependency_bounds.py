from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.dependency_bounds import lower_bound_constraints


class DependencyBoundsTests(unittest.TestCase):
    def test_extracts_declared_direct_lower_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pyproject = Path(directory) / "pyproject.toml"
            pyproject.write_text(
                "[project]\n"
                "name = \"example\"\n"
                "dependencies = [\n"
                "  \"bravo>=2.1,<3\",\n"
                "  \"Alpha~=1.4\",\n"
                "]\n",
                encoding="utf-8",
            )

            constraints = lower_bound_constraints(pyproject)

        self.assertEqual(constraints, ["Alpha==1.4", "bravo==2.1"])

    def test_rejects_dependency_without_lower_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pyproject = Path(directory) / "pyproject.toml"
            pyproject.write_text(
                "[project]\nname = \"example\"\ndependencies = [\"example<3\"]\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "no installable lower bound"):
                lower_bound_constraints(pyproject)

    def test_includes_requested_optional_dependency_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pyproject = Path(directory) / "pyproject.toml"
            pyproject.write_text(
                "[project]\n"
                "name = \"example\"\n"
                "dependencies = [\"core>=1,<2\"]\n"
                "[project.optional-dependencies]\n"
                "test = [\"Hypothesis>=6.100,<7\"]\n",
                encoding="utf-8",
            )

            constraints = lower_bound_constraints(pyproject, extras=["test"])

        self.assertEqual(constraints, ["core==1", "Hypothesis==6.100"])

    def test_rejects_inconsistent_lower_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pyproject = Path(directory) / "pyproject.toml"
            pyproject.write_text(
                "[project]\nname = \"example\"\ndependencies = [\"example==2,>=3\"]\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "no installable lower bound"):
                lower_bound_constraints(pyproject)


if __name__ == "__main__":
    unittest.main()
