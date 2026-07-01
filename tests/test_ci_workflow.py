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
        self.assertIn("--requirement requirements/ci.lock", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("--no-build-isolation", workflow)
        self.assertIn("--no-deps", workflow)
        self.assertNotIn("python -m pip install -e . mypy ruff", workflow)
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

    def test_ci_exercises_dependency_bounds_and_checks_installations(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("dependency-bounds:", workflow)
        self.assertIn("dependency-set: lowest-supported", workflow)
        self.assertIn("dependency-set: latest-compatible", workflow)
        self.assertIn("python scripts/dependency_bounds.py", workflow)
        self.assertIn("--extra test", workflow)
        generator = workflow.index("python scripts/dependency_bounds.py")
        bootstrap = workflow.index('python -m pip install "packaging>=24,<27"')
        self.assertLess(bootstrap, generator)
        self.assertEqual(workflow.count('-e ".[test]"'), 2)
        self.assertIn("--upgrade-strategy eager", workflow)
        self.assertGreaterEqual(workflow.count("python -m pip check"), 6)

    def test_ci_tooling_installs_are_hash_checked(self) -> None:
        workflow_dir = ROOT / ".github" / "workflows"
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(workflow_dir.glob("*.yml"))
        )
        semgrep = (workflow_dir / "semgrep.yml").read_text(encoding="utf-8")
        fuzz = (workflow_dir / "fuzz.yml").read_text(encoding="utf-8")
        semgrep_lock = (ROOT / "requirements" / "semgrep.lock").read_text(
            encoding="utf-8"
        )
        fuzz_lock = (ROOT / "requirements" / "fuzz.lock").read_text(
            encoding="utf-8"
        )

        self.assertIn("--requirement requirements/ci.lock", combined)
        self.assertIn("--requirement requirements/semgrep.lock", semgrep)
        self.assertIn("--requirement requirements/fuzz.lock", fuzz)
        self.assertIn("--hash=sha256:", semgrep_lock)
        self.assertIn("--hash=sha256:", fuzz_lock)
        self.assertIn("semgrep==", semgrep_lock)
        self.assertIn("atheris==3.0.0", fuzz_lock)
        self.assertNotIn("python -m pip install semgrep", combined)
        self.assertNotIn("python -m pip install . atheris==3.0.0", combined)
        self.assertNotIn("python -m pip install bandit", combined)
        self.assertNotIn("python -m pip install mkdocs-material", combined)

    def test_ci_generates_product_specific_sbom_from_runtime_lock(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        runtime_lock = (ROOT / "requirements" / "runtime.lock").read_text(
            encoding="utf-8"
        )
        ci_lock = (ROOT / "requirements" / "ci.lock").read_text(encoding="utf-8")

        self.assertIn("name: Generate SBOM preview", workflow)
        self.assertIn("--requirement requirements/runtime.lock", workflow)
        self.assertIn("sbom-dist/*.whl", workflow)
        self.assertIn('cyclonedx-py environment "$sbom_env/bin/python"', workflow)
        self.assertIn("--hash=sha256:", runtime_lock)
        self.assertIn("--hash=sha256:", ci_lock)
        self.assertIn("cyclonedx-bom==", ci_lock)

    def test_release_generates_per_artifact_runtime_sboms(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("name: Generate release SBOMs", workflow)
        self.assertIn("--requirement requirements/runtime.lock", workflow)
        self.assertIn('--no-deps \\', workflow)
        self.assertIn('"${artifact}.cdx.json"', workflow)
        self.assertIn("dist/*.cdx.json", workflow)
        self.assertNotIn("dist/trustcheck-sbom.json", workflow)

    def test_ci_gates_pull_requests_with_dependency_review(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("dependency-review:", workflow)
        self.assertIn("if: github.event_name == 'pull_request'", workflow)
        self.assertIn("pull-requests: read", workflow)
        self.assertIn(
            "actions/dependency-review-action@"
            "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
            workflow,
        )
        self.assertIn("fail-on-severity: moderate", workflow)
        self.assertIn("deny-licenses: AGPL-1.0, AGPL-3.0, GPL-2.0, GPL-3.0", workflow)

    def test_live_integration_is_nightly_and_blocks_stale_releases(self) -> None:
        live = (ROOT / ".github/workflows/live-integration.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github/workflows/publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("workflow_dispatch:", live)
        self.assertIn("schedule:", live)
        self.assertNotIn("pull_request:", live)
        self.assertIn('TRUSTCHECK_RUN_LIVE: "1"', live)
        self.assertIn("tests/test_integration_live.py", live)
        self.assertIn("python -m pip check", live)
        self.assertIn("live-integration-freshness:", release)
        self.assertIn("live-integration.yml/runs", release)
        self.assertIn('"$age_seconds" -gt 172800', release)

    def test_sarif_integration_uploads_stable_fixture_alerts(self) -> None:
        workflow = (ROOT / ".github/workflows/sarif-integration.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("security-events: write", workflow)
        self.assertIn("requirements-vulnerable.txt", workflow)
        self.assertEqual(workflow.count("--output-file trustcheck-"), 2)
        self.assertIn("scripts/validate_sarif.py", workflow)
        self.assertIn("--compare trustcheck-second.sarif", workflow)
        self.assertIn(
            "github/codeql-action/upload-sarif@8aad20d150bbac5944a9f9d289da16a4b0d87c1e",
            workflow,
        )
        self.assertIn("category: trustcheck-sarif-integration", workflow)

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
