from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class CoverageBadgeWorkflowTests(unittest.TestCase):
    def test_ci_verifies_published_benchmark_signature(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("name: Verify published benchmark signature", workflow)
        self.assertIn("benchmarks/results/latest.json.sig", workflow)
        self.assertIn("benchmarks/results/benchmark-public-key.pem", workflow)
        self.assertIn("python -m pip install -e . mypy ruff", workflow)
        self.assertNotIn('python-version: ["3.10"', workflow)
        publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('python-version: ["3.10"', publish)
        self.assertIn("name: Test built sdist source tree", workflow)
        self.assertIn("python -m pytest -q tests/test_release_version.py", workflow)

    def test_benchmark_workflow_verifies_before_and_after_generation(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "benchmarks.yml").read_text(
            encoding="utf-8"
        )

        published = workflow.index("name: Verify published benchmark signature")
        benchmark = workflow.index("python benchmarks/benchmark_against_pip_audit.py")
        signing = workflow.index("name: Sign benchmark result")
        generated = workflow.index("name: Verify generated benchmark signature")
        self.assertLess(published, benchmark)
        self.assertLess(benchmark, signing)
        self.assertLess(signing, generated)

    def test_ci_generates_and_publishes_coverage_badge(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("name: Generate coverage badge", workflow)
        self.assertIn("coverage-badge/coverage.svg", workflow)
        self.assertIn("publish-coverage-badge:", workflow)
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            workflow,
        )
        self.assertIn("contents: write", workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("group: coverage-badge", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("git -C \"$publish_root\" push --force origin coverage-badge", workflow)
        self.assertNotIn("git diff --exit-code -- docs/assets/images/coverage.svg", workflow)

    def test_readme_uses_action_published_badge(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn(
            "raw.githubusercontent.com/Halfblood-Prince/trustcheck/"
            "coverage-badge/coverage.svg",
            readme,
        )
        self.assertFalse((ROOT / "docs" / "assets" / "images" / "coverage.svg").exists())


if __name__ == "__main__":
    unittest.main()
