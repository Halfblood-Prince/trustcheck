from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class CoverageBadgeWorkflowTests(unittest.TestCase):
    def test_workflows_reject_unknown_or_mismatched_source_versions(self) -> None:
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        source_workflow = (ROOT / ".github/workflows/source-build.yml").read_text(
            encoding="utf-8"
        )
        release_workflow = (ROOT / ".github/workflows/publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('fallback_version = "0.0.0+source"', project)
        self.assertNotIn('fallback_version = "0+unknown"', project)
        self.assertIn("SETUPTOOLS_SCM_PRETEND_VERSION: 0.0.0+source", source_workflow)
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
            release_workflow.count("scripts/verify_release_version.py"), 2
        )
        self.assertIn('--tag "$GITHUB_REF_NAME"', release_workflow)
        build_step_start = release_workflow.index("- name: Build package")
        build_step_end = release_workflow.index(
            "- name: Prepare package upload directory", build_step_start
        )
        self.assertIn(
            "shell: bash", release_workflow[build_step_start:build_step_end]
        )

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

    def test_benchmark_workflow_presents_unsigned_results(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "benchmarks.yml").read_text(
            encoding="utf-8"
        )

        benchmark = workflow.index("python benchmarks/benchmark_against_pip_audit.py")
        presentation = workflow.index("name: Present benchmark results")
        artifact = workflow.index("uses: actions/upload-artifact@")
        self.assertLess(benchmark, presentation)
        self.assertLess(presentation, artifact)
        self.assertIn("$GITHUB_STEP_SUMMARY", workflow)
        self.assertNotIn("benchmark_signature.py", workflow)
        self.assertNotIn("BENCHMARK_SIGNING_KEY_PEM", workflow)

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

    def test_readme_links_adversarial_fuzzing_badge(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("actions/workflows/fuzz.yml/badge.svg?branch=main", readme)
        self.assertEqual(readme.count("actions/workflows/fuzz.yml"), 2)


if __name__ == "__main__":
    unittest.main()
