from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import trustcheck.cli as cli_module
import trustcheck.remediation as remediation_module
from trustcheck.cli import (
    EXIT_OK,
    EXIT_POLICY_FAILURE,
    EXIT_REMEDIATION_FAILURE,
    ScanTarget,
    build_parser,
    main,
)
from trustcheck.lockfiles import load_lockfile
from trustcheck.models import (
    PolicyEvaluation,
    PolicyViolation,
    TrustReport,
    VulnerabilityRecord,
    VulnerabilitySuppression,
)
from trustcheck.remediation import (
    BlockedFix,
    CommandValidationResult,
    FilePatch,
    PreparedRemediation,
    PullRequestResult,
    RemediationError,
    RemediationPlan,
    RemediationUpgrade,
    RemediationValidation,
    SemanticEdit,
    apply_prepared_remediation,
    create_pull_request,
    plan_remediation,
    prepare_remediation,
    write_remediation_patch,
)
from trustcheck.resolver import (
    ArtifactReference,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
)


def make_report(
    version: str,
    *,
    vulnerabilities: list[VulnerabilityRecord] | None = None,
    violations: list[PolicyViolation] | None = None,
) -> TrustReport:
    return TrustReport(
        project="demo",
        version=version,
        summary=None,
        package_url=f"https://pypi.org/project/demo/{version}/",
        vulnerabilities=vulnerabilities or [],
        policy=PolicyEvaluation(
            passed=not violations,
            violations=violations or [],
        ),
    )


def vulnerable_report() -> TrustReport:
    return make_report(
        "1.0",
        vulnerabilities=[
            VulnerabilityRecord(
                id="CVE-2026-1000",
                summary="fixed in 2.0",
                fixed_in=["2.0", "3.0"],
            )
        ],
    )


def validated_plan(source: Path) -> RemediationPlan:
    resolution = Resolution(
        distributions=[
            ResolvedDistribution(
                name="demo",
                version="2.0",
                requested=True,
                artifacts=(
                    ArtifactReference(
                        filename="demo-2.0-py3-none-any.whl",
                        url="https://files.example/demo.whl",
                        hashes=(("sha256", "a" * 64),),
                        kind="wheel",
                    ),
                ),
            )
        ]
    )
    return RemediationPlan(
        source=str(source),
        status="validated",
        minimal=True,
        upgrades=[
            RemediationUpgrade(
                project="demo",
                from_version="1.0",
                to_version="2.0",
                advisory_ids=("CVE-2026-1000",),
                direct=True,
            )
        ],
        validation=RemediationValidation(
            resolution_passed=True,
            rescan_passed=True,
            targeted_advisories_removed=True,
            no_new_vulnerabilities=True,
            no_new_policy_violations=True,
            index_provenance_preserved=True,
            policy_passed=True,
        ),
        candidate_resolution=resolution,
    )


class RemediationPlannerTests(unittest.TestCase):
    def test_confidence_changelog_and_transitive_explanations(self) -> None:
        self.assertEqual(
            remediation_module._compatibility_confidence("1.2.0", "1.2.1", direct=True),
            "high",
        )
        self.assertEqual(
            remediation_module._compatibility_confidence("1.2.0", "1.3.0", direct=True),
            "medium",
        )
        self.assertEqual(
            remediation_module._compatibility_confidence("bad", "2", direct=True),
            "low",
        )
        self.assertEqual(
            remediation_module._compatibility_confidence("1.2.0", "1.3.0", direct=False),
            "low",
        )
        self.assertIn(
            "could not be classified",
            remediation_module._breaking_change_warning("bad", "2") or "",
        )
        self.assertIsNone(remediation_module._breaking_change_warning("1.2", "1.3"))
        self.assertIsNone(remediation_module._changelog_url(None))
        report = make_report("1")
        report.repository_urls = ["https://github.com/example/demo"]
        self.assertEqual(
            remediation_module._changelog_url(report),
            "https://github.com/example/demo/releases",
        )
        report.repository_urls = ["https://example.test/changelog"]
        self.assertEqual(
            remediation_module._changelog_url(report),
            "https://example.test/changelog",
        )
        resolution = Resolution(
            distributions=[
                ResolvedDistribution(
                    name="parent",
                    version="1",
                    requires_dist=("child>=1", "not valid @@@"),
                ),
                ResolvedDistribution(name="child", version="1"),
            ]
        )
        self.assertIn(
            "parent==1",
            remediation_module._transitive_explanation("child", resolution),
        )
        self.assertIn(
            "resolved dependency graph",
            remediation_module._transitive_explanation("other", resolution),
        )

    def setUp(self) -> None:
        self.baseline = Resolution(
            distributions=[
                ResolvedDistribution(
                    name="demo",
                    version="1.0",
                    requested=True,
                    index_url="https://pypi.org/simple",
                ),
                ResolvedDistribution(
                    name="stable-dep",
                    version="4.0",
                    index_url="https://pypi.org/simple",
                ),
            ]
        )

    def test_planner_selects_lowest_secure_constraint_compatible_release(self) -> None:
        seen: list[list[str]] = []

        def resolve(requirements):
            seen.append(list(requirements))
            selected = "2.0" if "demo==2.0" in requirements else "3.0"
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version=selected,
                        requested=True,
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version="4.0",
                        index_url="https://pypi.org/simple",
                    ),
                ]
            )

        def scan(resolution):
            return {
                "demo": make_report(resolution.versions["demo"]),
                "stable-dep": TrustReport(
                    project="stable-dep",
                    version="4.0",
                    summary=None,
                    package_url="https://pypi.org/project/stable-dep/4.0/",
                ),
            }

        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={
                "demo": vulnerable_report(),
                "stable-dep": TrustReport(
                    project="stable-dep",
                    version="4.0",
                    summary=None,
                    package_url="https://pypi.org/project/stable-dep/4.0/",
                ),
            },
            root_requirements=["demo==1.0"],
            resolve=resolve,
            scan=scan,
        )

        self.assertEqual(plan.status, "validated")
        self.assertTrue(plan.minimal)
        self.assertEqual(plan.upgrades[0].to_version, "2.0")
        self.assertEqual(plan.upgrades[0].compatibility_confidence, "low")
        self.assertIn("Major-version", plan.upgrades[0].breaking_change_warning or "")
        self.assertTrue(plan.minimal_secure_upgrade_proof["proven"])
        self.assertEqual(
            plan.to_dict()["minimal_secure_upgrade_proof"]["strategy"],  # type: ignore[index]
            "exhaustive-cardinality-then-version search",
        )
        self.assertIsNotNone(plan.before_graph)
        self.assertIsNotNone(plan.after_graph)
        assert plan.before_graph is not None
        assert plan.after_graph is not None
        self.assertEqual(plan.before_graph.to_dict()["package_count"], 2)
        self.assertEqual(plan.after_graph.to_dict()["package_count"], 2)
        self.assertNotEqual(plan.before_graph.sha256, plan.after_graph.sha256)
        self.assertEqual(
            plan.advisory_ids_removed[0].to_dict(),
            {
                "project": "demo",
                "from_version": "1.0",
                "to_version": "2.0",
                "advisory_ids": ["CVE-2026-1000"],
            },
        )
        self.assertIn("stable-dep==4.0", seen[0])
        self.assertTrue(plan.validation.accepted)

    def test_planner_remediates_policy_failing_package(self) -> None:
        def resolve(requirements):
            selected = next(
                item.split("==", 1)[1]
                for item in requirements
                if item.startswith("demo==")
            )
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version=selected,
                        requested=True,
                        index_url="https://pypi.org/simple",
                    )
                ]
            )

        baseline_report = make_report(
            "1.0",
            violations=[
                PolicyViolation(
                    code="publisher_policy",
                    severity="high",
                    message="publisher is not trusted",
                )
            ],
        )
        plan = plan_remediation(
            source="requirements.txt",
            baseline=Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="1.0",
                        requested=True,
                        index_url="https://pypi.org/simple",
                    )
                ]
            ),
            reports={"demo": baseline_report},
            root_requirements=["demo>=1,<2"],
            resolve=resolve,
            scan=lambda resolution: {
                "demo": make_report(resolution.versions["demo"])
            },
            available_versions={"demo": ["1.0", "1.5", "2.0"]},
        )

        self.assertEqual(plan.status, "validated")
        self.assertEqual(plan.upgrades[0].to_version, "1.5")
        self.assertEqual(plan.upgrades[0].advisory_ids, ())
        self.assertIn("passes selected policy", plan.upgrades[0].reason)
        self.assertTrue(plan.validation.accepted)

    def test_planner_enumerates_registry_releases_above_fix_threshold(self) -> None:
        def resolve(requirements):
            selected = next(
                item.split("==", 1)[1]
                for item in requirements
                if item.startswith("demo==")
            )
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version=selected,
                        requested=True,
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version="4.0",
                        index_url="https://pypi.org/simple",
                    ),
                ]
            )

        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo==1.0"],
            resolve=resolve,
            scan=lambda resolution: {
                "demo": make_report(resolution.versions["demo"])
            },
            available_versions={"demo": ["1.5", "2.1", "2.5", "3.0"]},
        )

        self.assertEqual(plan.status, "validated")
        self.assertEqual(plan.upgrades[0].to_version, "2.1")

    def test_planner_blocks_excluded_secure_release_without_opt_in(self) -> None:
        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo>=1,<2"],
            resolve=lambda requirements: self.baseline,
            scan=lambda resolution: {"demo": vulnerable_report()},
        )

        self.assertEqual(plan.status, "blocked")
        self.assertIn("excludes every known secure release", plan.blocked[0].reason)

    def test_planner_ignores_withdrawn_and_active_suppressions(self) -> None:
        report = make_report(
            "1.0",
            vulnerabilities=[
                VulnerabilityRecord(
                    id="WITHDRAWN",
                    summary="withdrawn",
                    fixed_in=["2.0"],
                    withdrawn=True,
                ),
                VulnerabilityRecord(
                    id="SUPPRESSED",
                    summary="suppressed",
                    fixed_in=["2.0"],
                    suppression=VulnerabilitySuppression(
                        vulnerability_id="SUPPRESSED",
                        owner="security",
                        justification="temporary",
                        expires="2026-12-31",
                        status="active",
                    ),
                ),
            ],
        )

        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": report},
            root_requirements=["demo==1.0"],
            resolve=lambda requirements: self.baseline,
            scan=lambda resolution: {"demo": report},
        )

        self.assertEqual(plan.status, "not-needed")
        self.assertTrue(plan.minimal)

    def test_planner_blocks_vcs_and_search_exhaustion(self) -> None:
        vcs_baseline = Resolution(
            distributions=[
                ResolvedDistribution(
                    name="demo",
                    version="1.0",
                    requested=True,
                    vcs="git",
                    vcs_commit="abc",
                )
            ]
        )
        blocked = plan_remediation(
            source="requirements.txt",
            baseline=vcs_baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo @ git+https://example/demo.git@abc"],
            resolve=lambda requirements: vcs_baseline,
            scan=lambda resolution: {"demo": vulnerable_report()},
            source_types={"demo": "vcs"},
        )
        self.assertEqual(blocked.status, "blocked")
        self.assertIn("VCS", blocked.blocked[0].reason)

        exhausted = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo==1.0"],
            resolve=lambda requirements: (_ for _ in ()).throw(
                ResolutionError("conflict")
            ),
            scan=lambda resolution: {},
            max_attempts=1,
        )
        self.assertEqual(exhausted.status, "blocked")
        self.assertFalse(exhausted.minimal)
        self.assertEqual(exhausted.attempts, 1)

    def test_planner_rejects_new_vulnerabilities_and_policy_violations(self) -> None:
        def resolve(requirements):
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="2.0",
                        requested=True,
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version="4.0",
                        index_url="https://pypi.org/simple",
                    ),
                ]
            )

        def scan(resolution):
            return {
                "demo": make_report(
                    "2.0",
                    vulnerabilities=[
                        VulnerabilityRecord(
                            id="CVE-2026-NEW",
                            summary="new",
                        )
                    ],
                    violations=[
                        PolicyViolation(
                            code="new_violation",
                            severity="high",
                            message="new",
                        )
                    ],
                )
            }

        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo==1.0"],
            resolve=resolve,
            scan=scan,
            max_attempts=4,
        )

        self.assertEqual(plan.status, "blocked")
        self.assertIn("no constraint-compatible", plan.message)

    def test_planner_covers_invalid_fixes_relaxation_and_minimality_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 1"):
            plan_remediation(
                source="requirements.txt",
                baseline=self.baseline,
                reports={},
                root_requirements=[],
                resolve=lambda requirements: self.baseline,
                scan=lambda resolution: {},
                max_attempts=0,
            )

        invalid = make_report(
            "not-a-version",
            vulnerabilities=[
                VulnerabilityRecord(
                    id="BAD",
                    summary="bad",
                    fixed_in=["also-bad", "2.0rc1"],
                )
            ],
        )
        invalid_baseline = Resolution(
            distributions=[
                ResolvedDistribution(name="demo", version="not-a-version")
            ]
        )
        blocked = plan_remediation(
            source="requirements.txt",
            baseline=invalid_baseline,
            reports={"demo": invalid, "missing": vulnerable_report()},
            root_requirements=["not valid ???"],
            resolve=lambda requirements: invalid_baseline,
            scan=lambda resolution: {},
        )
        self.assertEqual(blocked.status, "blocked")
        self.assertIn("valid non-downgrade", blocked.blocked[0].reason)

        attempts: list[list[str]] = []

        def relaxed_resolver(requirements):
            attempts.append(list(requirements))
            if "stable-dep==4.0" in requirements:
                raise ResolutionError("must relax")
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="2.0",
                        requested=True,
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version="5.0",
                        index_url="https://pypi.org/simple",
                    ),
                ]
            )

        relaxed = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo<2"],
            resolve=relaxed_resolver,
            scan=lambda resolution: {
                "demo": make_report("2.0"),
                "stable-dep": TrustReport(
                    project="stable-dep",
                    version="5.0",
                    summary=None,
                    package_url="https://pypi.org/project/stable-dep/5.0/",
                ),
            },
            allow_constraint_changes=True,
        )
        self.assertEqual(relaxed.status, "validated")
        self.assertGreaterEqual(len(attempts), 2)

        limited = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo==1.0"],
            resolve=lambda requirements: Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="2.0",
                        requested=True,
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version="4.0",
                        index_url="https://pypi.org/simple",
                    ),
                ]
            ),
            scan=lambda resolution: {"demo": make_report("2.0")},
            available_versions={"demo": ["2.0", "3.0"]},
            max_attempts=1,
        )
        self.assertEqual(limited.status, "blocked")
        self.assertIn("prove minimality", limited.message)

    def test_planner_skips_yanked_and_new_prerelease_candidates(self) -> None:
        def resolver(requirements):
            selected = next(
                value.split("==", 1)[1]
                for value in requirements
                if value.startswith("demo==")
            )
            return Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version=selected,
                        requested=True,
                        is_yanked=selected == "2.0",
                        index_url="https://pypi.org/simple",
                    ),
                    ResolvedDistribution(
                        name="stable-dep",
                        version=(
                            "5.0rc1" if selected == "2.5" else "4.0"
                        ),
                        index_url="https://pypi.org/simple",
                    ),
                ]
            )

        plan = plan_remediation(
            source="requirements.txt",
            baseline=self.baseline,
            reports={"demo": vulnerable_report()},
            root_requirements=["demo==1.0"],
            resolve=resolver,
            scan=lambda resolution: {"demo": make_report(resolution.versions["demo"])},
            available_versions={"demo": ["2.0", "2.5", "3.0"]},
        )

        self.assertEqual(plan.status, "validated")
        self.assertEqual(plan.upgrades[0].to_version, "3.0")

    def test_candidate_validation_reports_missing_remaining_and_index_drift(self) -> None:
        candidate = Resolution(
            distributions=[
                ResolvedDistribution(
                    name="demo",
                    version="2.0",
                    index_url="https://mirror.example/simple",
                )
            ]
        )
        remaining = make_report(
            "2.0",
            vulnerabilities=[
                VulnerabilityRecord(
                    id="CVE-2026-1000",
                    summary="still affected",
                )
            ],
        )
        validation = remediation_module.validate_candidate(
            baseline=self.baseline,
            baseline_reports={"demo": vulnerable_report()},
            candidate=candidate,
            candidate_reports={"demo": remaining},
            targeted={
                "demo": ("CVE-2026-1000",),
                "missing": ("CVE-2026-2000",),
            },
        )

        self.assertFalse(validation.accepted)
        self.assertFalse(validation.targeted_advisories_removed)
        self.assertFalse(validation.index_provenance_preserved)
        self.assertTrue(any("did not return" in error for error in validation.errors))
        self.assertTrue(any("remains affected" in error for error in validation.errors))
        self.assertTrue(any("index origins" in error for error in validation.errors))


class RemediationModelTests(unittest.TestCase):
    def test_models_serialize_write_and_render_all_sections(self) -> None:
        edit = SemanticEdit("requirements.txt", "demo", "1", "2", "pin")
        patch_item = FilePatch("requirements.txt", "a", "b", "diff", (edit,))
        blocked = BlockedFix("local", "1", ("CVE-1",), "immutable")
        pull_request = PullRequestResult(
            created=True,
            url="https://github.com/example/repo/pull/1",
            branch="trustcheck/fix",
        )
        plan = RemediationPlan(
            source="requirements.txt",
            status="pull-request-created",
            minimal=True,
            attempts=2,
            upgrades=[
                RemediationUpgrade(
                    project="demo",
                    from_version="1",
                    to_version="2",
                    advisory_ids=("CVE-2",),
                    direct=True,
                    reason="secure",
                    breaking_change_warning="review the major upgrade",
                    changelog_url="https://example.test/changelog",
                    transitive_explanation="required by parent==1",
                )
            ],
            blocked=[blocked],
            planned_edits=[edit],
            patches=[patch_item],
            pull_request=pull_request,
            message="done",
            minimal_secure_upgrade_proof={"proven": True},
        )

        payload = plan.to_dict()
        rendered = remediation_module.render_remediation_text(plan)
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "nested" / "plan.json"
            plan.write_json(output)
            persisted = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload, persisted)
        self.assertEqual(blocked.to_dict()["reason"], "immutable")
        command = CommandValidationResult(
            command="pytest -q",
            argv=("pytest", "-q"),
            returncode=0,
            stdout="1 passed",
        )
        self.assertTrue(command.passed)
        self.assertEqual(command.to_dict()["command"], "pytest -q")
        self.assertEqual(patch_item.to_dict()["edits"][0]["kind"], "pin")
        self.assertEqual(pull_request.to_dict()["created"], True)
        self.assertIn("upgrades:", rendered)
        self.assertIn("blocked:", rendered)
        self.assertIn("patches:", rendered)
        self.assertIn("pull request:", rendered)
        self.assertIn("minimal secure upgrade proof: proven", rendered)
        self.assertIn("warning: review the major upgrade", rendered)
        self.assertIn("cause: required by parent==1", rendered)
        self.assertIn("changelog: https://example.test/changelog", rendered)


class RemediationWriterTests(unittest.TestCase):
    def test_requirements_dry_run_and_atomic_application(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0  # keep this comment\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                self.assertEqual(
                    target.read_text(encoding="utf-8"),
                    "demo==1.0  # keep this comment\n",
                )
                patch = prepared.plan.patches[0]
                hash_validation = prepared.plan.lockfile_hash_validation[0]
                self.assertIn("demo==2.0", patch.diff)
                self.assertFalse(hash_validation.applicable)
                self.assertTrue(hash_validation.valid)
                apply_prepared_remediation(prepared)

            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "demo==2.0  # keep this comment\n",
            )
            self.assertEqual(plan.status, "applied")

    def test_requirements_lock_uses_requirements_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.lock"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                patch = prepared.plan.patches[0]

            self.assertEqual(patch.path, "requirements.lock")
            self.assertIn("demo==2.0", patch.diff)

    def test_writes_review_patch_without_clobbering_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            plan = validated_plan(root / "requirements.txt")
            plan.patches = [
                FilePatch(
                    path="requirements.txt",
                    before_sha256="before",
                    after_sha256="after",
                    diff="--- a/requirements.txt\n+++ b/requirements.txt\n",
                )
            ]
            requested = root / "trustcheck-fix.patch"

            first = write_remediation_patch(plan, requested)
            requested.write_text("human notes\n", encoding="utf-8")
            second = write_remediation_patch(plan, requested)

            self.assertEqual(first, requested)
            self.assertEqual(second, root / "trustcheck-fix-1.patch")
            self.assertEqual(plan.patch_path, str(second))

    def test_application_refuses_stale_source_and_restores_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                target.write_text("demo==1.1\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    RemediationError,
                    "refusing to overwrite changed file",
                ):
                    apply_prepared_remediation(prepared)

            self.assertEqual(target.read_text(encoding="utf-8"), "demo==1.1\n")

    def test_pyproject_edit_preserves_comments_and_unrelated_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pyproject.toml"
            target.write_text(
                "\n".join(
                    [
                        "[project]",
                        'dependencies = ["demo==1.0"] # important',
                        "",
                        "[tool.example]",
                        'value = "untouched"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                staged = prepared.root / "pyproject.toml"
                rendered = staged.read_text(encoding="utf-8")

            self.assertIn('"demo==2.0"', rendered)
            self.assertIn("# important", rendered)
            self.assertIn('value = "untouched"', rendered)

    def test_nested_requirements_and_constraints_are_staged_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            nested = root / "base.txt"
            constraints = root / "constraints.txt"
            target.write_text("-r base.txt\n", encoding="utf-8")
            nested.write_text("demo==1.0\n", encoding="utf-8")
            constraints.write_text("# security constraints\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(
                target,
                plan,
                constraint_files=[constraints],
            ) as prepared:
                staged_nested = prepared.root / "base.txt"
                staged_constraints = prepared.root / "constraints.txt"

                self.assertIn("demo==2.0", staged_nested.read_text(encoding="utf-8"))
                self.assertIn(
                    "demo==2.0",
                    staged_constraints.read_text(encoding="utf-8"),
                )

    def test_pep751_regeneration_preserves_hashed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pylock.toml"
            target.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "test"',
                        "",
                        "[[packages]]",
                        'name = "demo"',
                        'version = "1.0"',
                        "[[packages.wheels]]",
                        'name = "demo-1.0-py3-none-any.whl"',
                        'url = "https://files.example/demo-1.whl"',
                        f'hashes = {{sha256 = "{"b" * 64}"}}',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            plan = validated_plan(target)

            with prepare_remediation(
                target,
                plan,
                source_manifest=target,
            ) as prepared:
                staged = prepared.root / "pylock.toml"
                locked = load_lockfile(staged)
                hash_validation = prepared.plan.lockfile_hash_validation[0]

            self.assertEqual(locked.versions["demo"], "2.0")
            self.assertEqual(
                locked.packages[0].artifacts[0].hashes,
                (("sha256", "a" * 64),),
            )
            self.assertTrue(hash_validation.applicable)
            self.assertTrue(hash_validation.valid)
            self.assertEqual(hash_validation.format, "pylock.toml")
            self.assertEqual(hash_validation.artifact_count, 1)
            self.assertEqual(hash_validation.hashed_artifact_count, 1)

    def test_native_uv_writer_uses_fixed_argv_and_no_shell(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []

        def runner(command, **kwargs):
            command = list(command)
            calls.append((command, kwargs))
            cwd = Path(str(kwargs["cwd"]))
            (cwd / "uv.lock").write_text(
                "\n".join(
                    [
                        "version = 1",
                        "",
                        "[[package]]",
                        'name = "demo"',
                        'version = "2.0"',
                        'source = { registry = "https://pypi.org/simple" }',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "uv.lock"
            target.write_text(
                "\n".join(
                    [
                        "version = 1",
                        "",
                        "[[package]]",
                        'name = "demo"',
                        'version = "1.0"',
                        'source = { registry = "https://pypi.org/simple" }',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["demo==1.0"]\n',
                encoding="utf-8",
            )
            plan = validated_plan(target)

            with prepare_remediation(target, plan, runner=runner):
                pass

        command, kwargs = calls[0]
        self.assertEqual(
            command,
            ["uv", "lock", "--upgrade-package", "demo==2.0"],
        )
        self.assertIs(kwargs["shell"], False)
        self.assertIn(["uv", "lock", "--upgrade-package", "demo==2.0"], plan.commands)

    def test_hash_pinned_requirements_require_available_pip_compile(self) -> None:
        def missing_runner(command, **kwargs):
            del command, kwargs
            raise FileNotFoundError("pip-compile")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            source = root / "requirements.in"
            source.write_text("demo\n", encoding="utf-8")
            target.write_text(
                "demo==1.0 \\\n"
                f"    --hash=sha256:{'a' * 64}\n",
                encoding="utf-8",
            )
            plan = validated_plan(target)

            with self.assertRaisesRegex(RemediationError, "pip-compile"):
                prepare_remediation(
                    target,
                    plan,
                    source_manifest=source,
                    runner=missing_runner,
                )

    def test_pip_compile_success_and_source_discovery(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            command = list(command)
            calls.append(command)
            output = Path(command[command.index("--output-file") + 1])
            output.write_text(
                "demo==2.0 \\\n"
                f"    --hash=sha256:{'a' * 64}\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            (root / "requirements.in").write_text("demo\n", encoding="utf-8")
            target.write_text(
                "demo==1.0 \\\n"
                f"    --hash=sha256:{'b' * 64}\n",
                encoding="utf-8",
            )
            plan = validated_plan(target)

            with prepare_remediation(target, plan, runner=runner) as prepared:
                staged = prepared.root / "requirements.txt"
                self.assertIn("demo==2.0", staged.read_text(encoding="utf-8"))

        self.assertEqual(calls[0][0], "pip-compile")
        self.assertIn("--generate-hashes", calls[0])
        self.assertIn("--upgrade-package", calls[0])

    def test_poetry_and_pdm_native_commands(self) -> None:
        cases = [
            (
                "poetry.lock",
                ["poetry", "update", "demo", "--lock"],
            ),
            (
                "pdm.lock",
                ["pdm", "update", "--no-sync", "demo==2.0"],
            ),
        ]
        for lock_name, expected in cases:
            with self.subTest(lock_name=lock_name), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                target = root / lock_name
                target.write_text(
                    "[[package]]\nname = \"demo\"\nversion = \"1.0\"\n",
                    encoding="utf-8",
                )
                (root / "pyproject.toml").write_text(
                    '[project]\ndependencies = ["demo==1.0"]\n',
                    encoding="utf-8",
                )
                calls: list[list[str]] = []

                def runner(command, **kwargs):
                    command = list(command)
                    calls.append(command)
                    cwd = Path(str(kwargs["cwd"]))
                    (cwd / lock_name).write_text(
                        '[[package]]\nname = "demo"\nversion = "2.0"\n',
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="",
                        stderr="",
                    )

                plan = validated_plan(target)
                with prepare_remediation(target, plan, runner=runner):
                    pass

                self.assertEqual(calls[0], expected)

    def test_pyproject_updates_all_supported_dependency_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pyproject.toml"
            target.write_text(
                "\n".join(
                    [
                        "[project]",
                        'dependencies = ["alpha>=1", 3]',
                        "",
                        "[project.optional-dependencies]",
                        'extra = ["beta==1", "not valid ???"]',
                        "",
                        "[dependency-groups]",
                        'test = ["gamma~=1"]',
                        "",
                        "[tool.poetry.dependencies]",
                        'python = "^3.11"',
                        'delta = "^1.0"',
                        'epsilon = {version = "~1.0", optional = true}',
                        "",
                        "[tool.poetry.group.dev.dependencies]",
                        'zeta = "*"',
                        "",
                        "[tool.pdm.dev-dependencies]",
                        'lint = ["eta==1"]',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            upgrades = [
                RemediationUpgrade(name, "1", "2", (f"CVE-{index}",))
                for index, name in enumerate(
                    ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"),
                    1,
                )
            ]
            resolution = Resolution(
                distributions=[
                    ResolvedDistribution(name=item.project, version="2")
                    for item in upgrades
                ]
            )
            plan = RemediationPlan(
                source=str(target),
                status="validated",
                minimal=True,
                upgrades=upgrades,
                candidate_resolution=resolution,
            )

            with prepare_remediation(target, plan) as prepared:
                rendered = (prepared.root / "pyproject.toml").read_text(
                    encoding="utf-8"
                )

        for name in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"):
            self.assertIn(name, rendered)
        self.assertGreaterEqual(rendered.count("2"), 7)
        self.assertIn("optional = true", rendered)

    def test_pylock_adds_packages_and_validates_artifact_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pylock.toml"
            target.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "test"',
                        "",
                        "[[packages]]",
                        'name = "other"',
                        'version = "1.0"',
                        "[[packages.wheels]]",
                        'name = "other-1.0.whl"',
                        'url = "https://files.example/other.whl"',
                        f'hashes = {{sha256 = "{"b" * 64}"}}',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            resolution = Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="2.0",
                        index_url="https://pypi.org/simple",
                        requires_dist=("dep==3", "not valid ???"),
                        artifacts=(
                            ArtifactReference(
                                filename="demo-2.0.tar.gz",
                                path="demo-2.0.tar.gz",
                                size=42,
                                hashes=(("sha256", "a" * 64),),
                            ),
                        ),
                    )
                ]
            )
            plan = RemediationPlan(
                source=str(target),
                status="validated",
                minimal=True,
                upgrades=[
                    RemediationUpgrade("demo", "1", "2", ("CVE-1",))
                ],
                candidate_resolution=resolution,
            )

            with prepare_remediation(
                target,
                plan,
                source_manifest=target,
            ) as prepared:
                locked = load_lockfile(prepared.root / "pylock.toml")

        self.assertEqual(locked.versions["demo"], "2.0")
        demo = next(package for package in locked.packages if package.name == "demo")
        self.assertEqual(demo.requires_dist, ("dep==3",))
        self.assertEqual(
            demo.artifacts[0].path.endswith("demo-2.0.tar.gz"),
            True,
        )

        artifact = ArtifactReference(filename="bad.whl")
        with self.assertRaisesRegex(RemediationError, "no secure hash"):
            remediation_module._pylock_artifact_table(artifact)
        with self.assertRaisesRegex(RemediationError, "URL or path"):
            remediation_module._pylock_artifact_table(
                ArtifactReference(hashes=(("sha256", "a"),))
            )

    def test_prepare_rejects_invalid_inputs_and_empty_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            missing = root / "missing.txt"
            plan = RemediationPlan(source=str(missing))
            with self.assertRaisesRegex(RemediationError, "validated"):
                prepare_remediation(missing, plan)

            plan.status = "validated"
            plan.candidate_resolution = Resolution()
            with self.assertRaisesRegex(RemediationError, "does not exist"):
                prepare_remediation(missing, plan)

            unsupported = root / "Pipfile.lock"
            unsupported.write_text("{}", encoding="utf-8")
            plan.source = str(unsupported)
            with self.assertRaisesRegex(RemediationError, "not supported"):
                prepare_remediation(unsupported, plan)

            unchanged = root / "requirements.txt"
            unchanged.write_text("# no packages\n", encoding="utf-8")
            plan.source = str(unchanged)
            with self.assertRaisesRegex(RemediationError, "no file changes"):
                prepare_remediation(unchanged, plan)

            uv = root / "uv.lock"
            uv.write_text("version = 1\n", encoding="utf-8")
            plan.source = str(uv)
            plan.upgrades = [RemediationUpgrade("demo", "1", "2")]
            with self.assertRaisesRegex(RemediationError, "pyproject.toml"):
                prepare_remediation(uv, plan)

    def test_apply_detects_missing_metadata_and_rolls_back_failed_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("before-one", encoding="utf-8")
            second.write_text("before-two", encoding="utf-8")
            prepared = PreparedRemediation(
                plan=RemediationPlan(source=str(first), status="validated"),
                root=root,
                source_root=root,
                changed_files={Path("first.txt"): b"after-one"},
            )
            with self.assertRaisesRegex(RemediationError, "missing patch metadata"):
                apply_prepared_remediation(prepared)

            prepared.changed_files = {
                Path("first.txt"): b"after-one",
                Path("second.txt"): b"after-two",
            }
            prepared.plan.patches = remediation_module._build_file_patches(
                root,
                prepared.changed_files,
                (),
            )
            real_replace = remediation_module.os.replace
            calls = 0

            def failing_replace(source, destination):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("replace failed")
                return real_replace(source, destination)

            with (
                patch("trustcheck.remediation.os.replace", side_effect=failing_replace),
                self.assertRaisesRegex(OSError, "replace failed"),
            ):
                apply_prepared_remediation(prepared)

            self.assertEqual(first.read_text(encoding="utf-8"), "before-one")
            self.assertEqual(second.read_text(encoding="utf-8"), "before-two")

    def test_command_and_git_failure_paths(self) -> None:
        def failed(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(
                command,
                2,
                stdout="stdout detail",
                stderr="",
            )

        with self.assertRaisesRegex(RemediationError, "status 2"):
            remediation_module._run_command(
                ["tool"],
                runner=failed,
                timeout=1,
            )
        with self.assertRaisesRegex(RemediationError, "unable to run"):
            remediation_module._run_command(
                ["tool"],
                runner=lambda command, **kwargs: (_ for _ in ()).throw(
                    subprocess.TimeoutExpired(command, 1)
                ),
                timeout=1,
            )
        with self.assertRaisesRegex(RemediationError, "unsupported native locker"):
            remediation_module._run_native_locker(
                "unknown",
                staged_root=Path("."),
                upgrades=(),
                commands=[],
                runner=failed,
                timeout=1,
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)
            with prepare_remediation(target, plan) as prepared:
                def dirty_runner(command, **kwargs):
                    del kwargs
                    stdout = (
                        "requirements.txt\n"
                        if list(command)[3:5] == ["status", "--porcelain"]
                        else ""
                    )
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=stdout,
                        stderr="",
                    )

                with self.assertRaisesRegex(RemediationError, "clean Git worktree"):
                    create_pull_request(prepared, runner=dirty_runner)

                def failing_pr_runner(command, **kwargs):
                    del kwargs
                    command = list(command)
                    if command[3:5] == ["worktree", "add"]:
                        Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    if command[:3] == ["gh", "pr", "create"]:
                        return subprocess.CompletedProcess(
                            command,
                            1,
                            stdout="",
                            stderr="denied",
                        )
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="",
                        stderr="",
                    )

                result = create_pull_request(
                    prepared,
                    base="main",
                    branch="trustcheck/failure",
                    runner=failing_pr_runner,
                )
                self.assertFalse(result.created)
                self.assertIn("retained for recovery", result.error or "")

    def test_helper_edge_cases(self) -> None:
        self.assertEqual(
            remediation_module._compatible_upper_bound("1.2.3"),
            "1.3",
        )
        self.assertEqual(
            remediation_module._compatible_upper_bound("1.2"),
            "2.0",
        )
        self.assertIn(
            "<2.0",
            remediation_module._raise_lower_bound("~=1.2", remediation_module.Version("1.5")),
        )
        widened = remediation_module._minimal_compatible_specifier(
            ">=3,<4,!=2.5",
            remediation_module.Version("2.0"),
        )
        self.assertTrue(widened.startswith(">=2.0"))
        self.assertNotIn(">=3", widened)
        self.assertIsNone(remediation_module._parse_requirement("not valid ???"))
        self.assertIsNone(remediation_module._exact_pin(remediation_module.Requirement("demo==1.*")))
        self.assertEqual(
            remediation_module._immutable_reason(
                ResolvedDistribution(name="demo", version="1", editable=True),
                "index",
            ),
            "editable dependencies are immutable during automated remediation",
        )
        self.assertIn(
            "direct dependencies",
            remediation_module._immutable_reason(
                ResolvedDistribution(name="demo", version="1"),
                "direct",
            )
            or "",
        )
        self.assertTrue(
            remediation_module._root_allows_any_candidate(
                [],
                "demo",
                (),
                allow_constraint_changes=False,
            )
        )
        self.assertEqual(
            remediation_module._default_pr_title([]),
            "Fix vulnerabilities in 0 Python dependencies",
        )
        self.assertTrue(
            remediation_module._default_branch_name([]).startswith(
                "trustcheck/fix-dependencies-"
            )
        )
        remediation_module._validate_git_identifier(None, "branch")
        with self.assertRaises(RemediationError):
            remediation_module._validate_git_identifier("bad//branch", "branch")

    def test_invalid_pull_request_branch_is_rejected_before_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                with self.assertRaisesRegex(RemediationError, "invalid"):
                    create_pull_request(
                        prepared,
                        branch="../unsafe",
                    )

    def test_pull_request_uses_isolated_worktree_and_draft_by_default(self) -> None:
        commands: list[list[str]] = []

        def runner(command, **kwargs):
            del kwargs
            command = list(command)
            commands.append(command)
            if command[3:5] == ["worktree", "add"]:
                Path(command[-1]).mkdir(parents=True, exist_ok=True)
            stdout = "https://github.com/example/repo/pull/1\n" if command[:3] == [
                "gh",
                "pr",
                "create",
            ] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)

            with prepare_remediation(target, plan) as prepared:
                result = create_pull_request(
                    prepared,
                    branch="trustcheck/fix-demo",
                    runner=runner,
                )

        self.assertTrue(result.created)
        self.assertEqual(result.url, "https://github.com/example/repo/pull/1")
        gh_command = next(command for command in commands if command[:3] == ["gh", "pr", "create"])
        self.assertIn("--draft", gh_command)
        self.assertTrue(any(command[3:5] == ["worktree", "add"] for command in commands))

    def test_ready_pull_request_and_minimal_text_rendering(self) -> None:
        commands: list[list[str]] = []

        def runner(command, **kwargs):
            del kwargs
            command = list(command)
            commands.append(command)
            if command[3:5] == ["worktree", "add"]:
                Path(command[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "https://github.com/example/repo/pull/2\n"
                    if command[:3] == ["gh", "pr", "create"]
                    else ""
                ),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            plan = validated_plan(target)
            with prepare_remediation(target, plan) as prepared:
                result = create_pull_request(
                    prepared,
                    branch="trustcheck/ready",
                    ready=True,
                    runner=runner,
                )

        self.assertTrue(result.created)
        gh_command = next(
            command for command in commands if command[:3] == ["gh", "pr", "create"]
        )
        self.assertNotIn("--draft", gh_command)
        rendered = remediation_module.render_remediation_text(
            RemediationPlan(source="requirements.txt")
        )
        self.assertEqual(
            rendered.splitlines(),
            ["remediation: planned", "minimal: no", "attempts: 0/256"],
        )

    def test_requirement_rewriting_covers_ranges_urls_and_invalid_pins(self) -> None:
        version = remediation_module.Version("2.0")
        adjusted = remediation_module._requirements_for_candidate(
            ["not valid ???", "other>=1", "demo>=1,<3"],
            {"demo": version, "added": remediation_module.Version("4")},
            allow_constraint_changes=False,
        )
        self.assertEqual(adjusted[0], "not valid ???")
        self.assertEqual(adjusted[1], "other>=1")
        self.assertIn("demo>=2.0,<3", adjusted)
        self.assertIn("added==4", adjusted)

        self.assertTrue(
            remediation_module._root_allows_any_candidate(
                ["demo>=1,<3"],
                "demo",
                (version,),
                allow_constraint_changes=False,
            )
        )
        self.assertIsNone(
            remediation_module._exact_pin(
                remediation_module.Requirement("demo===not-a-version")
            )
        )
        with self.assertRaisesRegex(RemediationError, "direct URL"):
            remediation_module._updated_requirement(
                remediation_module.Requirement(
                    "demo @ https://files.example/demo.whl"
                ),
                version,
                allow_constraint_changes=False,
            )
        with self.assertRaisesRegex(RemediationError, "excludes secure"):
            remediation_module._updated_requirement(
                remediation_module.Requirement("demo<2"),
                version,
                allow_constraint_changes=False,
            )
        with self.assertRaisesRegex(RemediationError, "direct URL"):
            remediation_module._pinned_requirement(
                remediation_module.Requirement(
                    "demo @ https://files.example/demo.whl"
                ),
                version,
            )
        self.assertEqual(
            set(
                remediation_module._raise_lower_bound(
                    ">=1,==1.*,!=1.5",
                    version,
                ).split(",")
            ),
            {">=2.0", "!=1.5", "==1.*"},
        )
        self.assertEqual(
            remediation_module._raise_lower_bound("==1.0", version),
            ">=2.0",
        )

    def test_version_selection_ignores_invalid_registry_and_advisory_versions(self) -> None:
        invalid_fix = VulnerabilityRecord(
            id="CVE-invalid",
            summary="invalid",
            fixed_in=["not-a-version"],
        )
        self.assertEqual(
            remediation_module._secure_fixed_versions(
                [invalid_fix],
                current="1",
            ),
            (),
        )
        valid_fix = VulnerabilityRecord(
            id="CVE-valid",
            summary="valid",
            fixed_in=["2"],
        )
        self.assertEqual(
            remediation_module._secure_fixed_versions(
                [valid_fix],
                current="1",
                available=["invalid", "2", "3"],
            ),
            (
                remediation_module.Version("2"),
                remediation_module.Version("3"),
            ),
        )
        self.assertTrue(
            remediation_module._resolution_has_disallowed_release(
                Resolution(),
                Resolution(
                    distributions=[
                        ResolvedDistribution(
                            name="demo",
                            version="invalid",
                        )
                    ]
                ),
            )
        )

    def test_pyproject_append_missing_supports_poetry_and_empty_project_tables(
        self,
    ) -> None:
        cases = (
            (
                "[tool.poetry]\nname = \"example\"\n"
                "[tool.poetry.dependencies]\npython = \"^3.11\"\n",
                "[tool.poetry.dependencies]",
            ),
            (
                "[project]\nname = \"example\"\n",
                "dependencies = [",
            ),
            (
                "[project]\nname = \"example\"\n[tool.example]\nvalue = 1\n",
                "dependencies = [",
            ),
        )
        for content, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmpdir:
                target = Path(tmpdir) / "pyproject.toml"
                target.write_text(content, encoding="utf-8")
                plan = validated_plan(target)
                with prepare_remediation(target, plan) as prepared:
                    rendered = (
                        prepared.root / "pyproject.toml"
                    ).read_text(encoding="utf-8")
                self.assertIn(expected, rendered)
                self.assertIn("demo", rendered)

    def test_poetry_constraint_helpers_cover_supported_and_invalid_forms(self) -> None:
        target = remediation_module.Version("1.5")
        self.assertEqual(
            remediation_module._updated_poetry_specifier(
                "*",
                target,
                allow_constraint_changes=False,
            ),
            ">=1.5",
        )
        self.assertIn(
            "<2.0.0",
            remediation_module._updated_poetry_specifier(
                "^1.0",
                target,
                allow_constraint_changes=False,
            ),
        )
        self.assertIn(
            "<1.6",
            remediation_module._updated_poetry_specifier(
                "~1.5",
                target,
                allow_constraint_changes=False,
            ),
        )
        self.assertEqual(
            remediation_module._poetry_caret_specifier("0.2"),
            ">=0.2,<0.3.0",
        )
        self.assertEqual(
            remediation_module._poetry_caret_specifier("0.0.2"),
            ">=0.0.2,<0.0.3",
        )
        self.assertEqual(
            remediation_module._poetry_tilde_specifier("1"),
            ">=1,<2.0",
        )
        with self.assertRaisesRegex(RemediationError, "unsupported Poetry"):
            remediation_module._updated_poetry_specifier(
                "this is invalid",
                target,
                allow_constraint_changes=False,
            )
        self.assertEqual(
            remediation_module._updated_poetry_specifier(
                "this is invalid",
                target,
                allow_constraint_changes=True,
            ),
            ">=1.5",
        )

    def test_pylock_updates_existing_metadata_and_rejects_missing_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pylock.toml"
            target.write_text(
                'lock-version = "1.0"\ncreated-by = "test"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RemediationError, "packages array"):
                remediation_module._write_pylock(
                    target,
                    Resolution(),
                )

            target.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "test"',
                        "",
                        "[[packages]]",
                        'name = "demo"',
                        'version = "1.0"',
                        "[[packages.wheels]]",
                        'name = "old.whl"',
                        'url = "https://files.example/old.whl"',
                        f'hashes = {{sha256 = "{"b" * 64}"}}',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            resolution = Resolution(
                distributions=[
                    ResolvedDistribution(
                        name="demo",
                        version="2.0",
                        index_url="https://private.example/simple",
                        requires_dist=("dep==3", "other>=1", "invalid ???"),
                        artifacts=(
                            ArtifactReference(
                                filename="demo-2.whl",
                                url="https://files.example/demo-2.whl",
                                hashes=(("sha256", "a" * 64),),
                            ),
                            ArtifactReference(
                                filename="demo-2.tar.gz",
                                path="demo-2.tar.gz",
                                hashes=(("sha256", "c" * 64),),
                            ),
                        ),
                    )
                ]
            )
            remediation_module._write_pylock(target, resolution)
            rendered = target.read_text(encoding="utf-8")

        self.assertIn('index = "https://private.example/simple"', rendered)
        self.assertIn('version = "3"', rendered)
        self.assertIn('name = "other"', rendered)
        self.assertIn("[[packages.wheels]]", rendered)
        self.assertIn("[packages.sdist]", rendered)

    def test_pylock_source_manifest_is_updated_before_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "pylock.toml"
            manifest = root / "pyproject.toml"
            target.write_text(
                "\n".join(
                    [
                        'lock-version = "1.0"',
                        'created-by = "test"',
                        "[[packages]]",
                        'name = "demo"',
                        'version = "1.0"',
                        "[[packages.wheels]]",
                        'name = "demo.whl"',
                        'url = "https://files.example/demo.whl"',
                        f'hashes = {{sha256 = "{"b" * 64}"}}',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            manifest.write_text(
                '[project]\ndependencies = ["demo>=1"]\n',
                encoding="utf-8",
            )
            plan = validated_plan(target)
            with prepare_remediation(
                target,
                plan,
                source_manifest=manifest,
            ) as prepared:
                rendered = (
                    prepared.root / "pyproject.toml"
                ).read_text(encoding="utf-8")

        self.assertIn("demo>=2.0", rendered)

    def test_pip_compile_discovers_pyproject_and_rejects_missing_source(self) -> None:
        calls: list[list[str]] = []

        def runner(command, **kwargs):
            command = list(command)
            calls.append(command)
            output = Path(command[command.index("--output-file") + 1])
            output.write_text(
                "demo==2.0 \\\n"
                f"    --hash=sha256:{'a' * 64}\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "compiled.txt"
            target.write_text(
                "demo==1.0 \\\n"
                f"    --hash=sha256:{'b' * 64}\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["demo"]\n',
                encoding="utf-8",
            )
            plan = validated_plan(target)
            with prepare_remediation(target, plan, runner=runner):
                pass
            self.assertTrue(calls[0][1].endswith("pyproject.toml"))

            (root / "pyproject.toml").unlink()
            with self.assertRaisesRegex(RemediationError, "source file"):
                prepare_remediation(target, plan, runner=runner)

    def test_project_root_rejects_external_manifests_and_constraints(self) -> None:
        with (
            tempfile.TemporaryDirectory() as project_dir,
            tempfile.TemporaryDirectory() as external_dir,
        ):
            target = Path(project_dir) / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            external = Path(external_dir) / "pyproject.toml"
            external.write_text("[project]\n", encoding="utf-8")
            with self.assertRaisesRegex(RemediationError, "source-manifest"):
                remediation_module._project_root(target, external)
            with self.assertRaisesRegex(RemediationError, "constraint file"):
                remediation_module._project_root(
                    target,
                    None,
                    constraint_files=[external],
                )

    def test_new_files_are_removed_when_atomic_application_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            existing = root / "existing.txt"
            existing.write_text("before", encoding="utf-8")
            changed = {
                Path("created.txt"): b"created",
                Path("existing.txt"): b"after",
            }
            plan = RemediationPlan(source=str(existing), status="validated")
            plan.patches = remediation_module._build_file_patches(
                root,
                changed,
                (),
            )
            prepared = PreparedRemediation(
                plan=plan,
                root=root,
                source_root=root,
                changed_files=changed,
            )
            real_replace = remediation_module.os.replace
            calls = 0

            def fail_second(source, destination):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("stop")
                return real_replace(source, destination)

            with (
                patch("trustcheck.remediation.os.replace", side_effect=fail_second),
                self.assertRaisesRegex(OSError, "stop"),
            ):
                apply_prepared_remediation(prepared)

            self.assertFalse((root / "created.txt").exists())
            self.assertEqual(existing.read_text(encoding="utf-8"), "before")

    def test_pull_request_rejects_source_outside_reported_repository(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            tempfile.TemporaryDirectory() as repository,
        ):
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            plan = validated_plan(target)

            def runner(command, **kwargs):
                del kwargs
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=f"{repository}\n",
                    stderr="",
                )

            with prepare_remediation(target, plan) as prepared:
                with self.assertRaisesRegex(RemediationError, "outside Git"):
                    create_pull_request(prepared, runner=runner)

    def test_low_level_writer_guards_cover_unmatched_and_cyclic_inputs(self) -> None:
        upgrade = RemediationUpgrade("demo", "1", "2")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            requirements = root / "requirements.txt"
            requirements.write_text(
                "--index-url https://pypi.org/simple\n"
                "other==1\n"
                "\n",
                encoding="utf-8",
            )
            remediation_module._edit_requirements_file(
                requirements,
                [upgrade],
                allow_constraint_changes=False,
            )
            self.assertIn("demo==2", requirements.read_text(encoding="utf-8"))

            cyclic = root / "cyclic.txt"
            cyclic.write_text("-r cyclic.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(RemediationError, "cyclic"):
                remediation_module._edit_requirements_file(
                    cyclic,
                    [upgrade],
                    allow_constraint_changes=False,
                )

        matched: set[str] = set()
        remediation_module._edit_requirement_array(
            ["demo==1"],
            {"demo": upgrade},
            allow_constraint_changes=False,
            matched=matched,
            pin_exact=True,
        )
        unrelated = remediation_module.tomlkit.array()
        unrelated.append("other==1")
        remediation_module._edit_requirement_array(
            unrelated,
            {"demo": upgrade},
            allow_constraint_changes=False,
            matched=matched,
            pin_exact=True,
        )
        remediation_module._edit_poetry_table(
            [],
            {"demo": upgrade},
            allow_constraint_changes=False,
            matched=matched,
            pin_exact=True,
        )

    def test_pylock_guards_cover_unnamed_and_unhashed_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "pylock.toml"
            target.write_text(
                'lock-version = "1.0"\n'
                'created-by = "test"\n'
                "[[packages]]\n"
                "name = 1\n"
                'version = "1"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RemediationError, "without a hashed artifact"):
                remediation_module._write_pylock(
                    target,
                    Resolution(
                        distributions=[
                            ResolvedDistribution(name="demo", version="2")
                        ]
                    ),
                )

    def test_pip_compile_private_source_discovery_paths(self) -> None:
        def runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        for source_name in ("requirements.in", "pyproject.toml"):
            with self.subTest(source_name=source_name), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                target = root / "requirements.txt"
                target.write_text("demo==1\n", encoding="utf-8")
                (root / source_name).write_text(
                    (
                        "[project]\ndependencies = [\"demo\"]\n"
                        if source_name == "pyproject.toml"
                        else "demo\n"
                    ),
                    encoding="utf-8",
                )
                commands: list[list[str]] = []
                remediation_module._run_pip_compile(
                    target,
                    staged_root=root,
                    source_root=root,
                    upgrades=(),
                    commands=commands,
                    runner=runner,
                    timeout=1,
                    source_manifest=None,
                )
                self.assertTrue(commands[0][1].endswith(source_name))


class RemediationCliTests(unittest.TestCase):
    @staticmethod
    def _args(**overrides):
        values = {
            "source_manifest": None,
            "extra": [],
            "group": [],
            "constraint": [],
            "keyring_provider": "auto",
            "allow_constraint_changes": False,
            "max_fix_attempts": 16,
            "fix": False,
            "dry_run": False,
            "create_pr": False,
            "pr_base": None,
            "pr_branch": None,
            "pr_title": None,
            "pr_ready": False,
            "fix_test_commands": [],
            "with_deps": False,
            "with_transitive_deps": False,
            "inspect_artifacts": False,
            "trusted_project": [],
            "python_version": None,
            "platform": [],
            "implementation": None,
            "abi": [],
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    @staticmethod
    def _runtime_results(*commands: CommandValidationResult):
        return (
            CommandValidationResult(
                command="python -m pip install -r <resolved graph>",
                argv=("python", "-m", "pip", "install"),
                returncode=0,
            ),
            CommandValidationResult(
                command="python -m pip check",
                argv=("python", "-m", "pip", "check"),
                returncode=0,
            ),
            commands,
        )

    def test_parser_exposes_remediation_modes(self) -> None:
        parser = build_parser()
        planned = parser.parse_args(
            [
                "scan",
                "-f",
                "requirements.txt",
                "--plan-fixes",
                "--allow-constraint-changes",
                "--max-fix-attempts",
                "12",
            ]
        )
        fixed = parser.parse_args(
            [
                "scan",
                "-f",
                "requirements.txt",
                "--fix",
                "--dry-run",
                "--source-manifest",
                "requirements.in",
            ]
        )

        self.assertTrue(planned.plan_fixes)
        self.assertTrue(planned.allow_constraint_changes)
        self.assertEqual(planned.max_fix_attempts, 12)
        self.assertTrue(fixed.fix)
        self.assertTrue(fixed.dry_run)

    def test_cli_rejects_invalid_remediation_flag_combinations(self) -> None:
        for arguments in (
            ["scan", "-f", "requirements.txt", "--dry-run"],
            ["scan", "-f", "requirements.txt", "--create-pr"],
            ["scan", "-f", "requirements.txt", "--fix", "--dry-run", "--create-pr"],
            ["scan", "-f", "requirements.txt", "--plan-fixes", "--max-fix-attempts", "0"],
        ):
            with self.subTest(arguments=arguments):
                with (
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    main(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_scan_json_embeds_machine_readable_remediation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = RemediationPlan(
                source=str(target),
                status="not-needed",
                minimal=True,
                message="nothing to fix",
            )
            stdout = io.StringIO()
            with (
                patch(
                    "trustcheck.cli._load_scan_targets",
                    return_value=[
                        ScanTarget(
                            requirement="demo==1.0",
                            project="demo",
                            version="1.0",
                        )
                    ],
                ),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=make_report("1.0"),
                ),
                patch("trustcheck.cli._run_remediation", return_value=plan),
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "scan",
                        "-f",
                        str(target),
                        "--plan-fixes",
                        "--format",
                        "json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(payload["remediation"]["status"], "not-needed")
        self.assertEqual(
            payload["reports"][0]["remediation"]["status"],
            "not-needed",
        )

    def test_cli_remediation_input_helpers_cover_manifests_and_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            pyproject = root / "pyproject.toml"
            pyproject.write_text(
                "[project]\n"
                "dependencies = [\"demo>=1\"]\n"
                "[project.optional-dependencies]\n"
                "test = [\"pytest>=8\"]\n",
                encoding="utf-8",
            )
            requirements = root / "requirements.txt"
            requirements.write_text("demo==1.0\n", encoding="utf-8")

            discovered = cli_module._discover_remediation_manifest(requirements)
            self.assertEqual(discovered, pyproject)
            roots = cli_module._remediation_root_requirements(
                requirements,
                source_manifest=str(pyproject),
                extras=("test",),
                groups=(),
                target_environment=cli_module.TargetEnvironment(),
            )
            self.assertIn("demo>=1", roots)
            self.assertIn("pytest>=8", roots)

            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("-r second.txt\n", encoding="utf-8")
            second.write_text("-r first.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(RemediationError, "cyclic"):
                cli_module._read_remediation_requirements(first)

            empty = root / "empty.txt"
            empty.write_text("# no roots\n", encoding="utf-8")
            with self.assertRaisesRegex(RemediationError, "no root requirements"):
                cli_module._remediation_root_requirements(
                    empty,
                    source_manifest=str(empty),
                    extras=(),
                    groups=(),
                    target_environment=cli_module.TargetEnvironment(),
                )

            invalid = root / "invalid.toml"
            invalid.write_text("[project\n", encoding="utf-8")
            with self.assertRaisesRegex(RemediationError, "invalid remediation"):
                cli_module._remediation_root_requirements(
                    invalid,
                    source_manifest=str(invalid),
                    extras=(),
                    groups=(),
                    target_environment=cli_module.TargetEnvironment(),
                )

            lockfile = root / "uv.lock"
            lockfile.write_text("version = 1\n", encoding="utf-8")
            pyproject.unlink()
            with self.assertRaisesRegex(RemediationError, "--source-manifest"):
                cli_module._remediation_root_requirements(
                    lockfile,
                    source_manifest=None,
                    extras=(),
                    groups=(),
                    target_environment=cli_module.TargetEnvironment(),
                )

    def test_cli_builds_resolution_versions_and_report_summary(self) -> None:
        targets = [
            ScanTarget(
                requirement="demo==1",
                project="demo",
                version="1.0",
                requested=True,
                source_type="direct",
                artifacts=(
                    ArtifactReference(
                        filename="demo.whl",
                        hashes=(("sha256", "a" * 64),),
                    ),
                ),
            ),
            ScanTarget(
                requirement="broken",
                project="broken",
                failure_message="failed",
            ),
        ]
        resolution = cli_module._resolution_from_scan_targets(targets)
        self.assertEqual(resolution.versions, {"demo": "1.0"})
        self.assertTrue(resolution.distributions[0].is_direct)

        plan = RemediationPlan(
            source="requirements.txt",
            status="pull-request-created",
            minimal=True,
            attempts=3,
            upgrades=[
                RemediationUpgrade(
                    project="demo",
                    from_version="1.0",
                    to_version="2.0",
                )
            ],
            blocked=[
                BlockedFix(
                    project="local",
                    version="1",
                    advisory_ids=("CVE-1",),
                    reason="immutable",
                )
            ],
            patches=[
                FilePatch(
                    path="requirements.txt",
                    before_sha256="a",
                    after_sha256="b",
                    diff="patch",
                )
            ],
            pull_request=PullRequestResult(
                created=True,
                url="https://example.test/pull/1",
            ),
        )
        reports = [make_report("1.0")]
        cli_module._attach_remediation_summary(reports, plan)
        summary = reports[0].remediation
        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary.upgrades_planned, 1)
        self.assertEqual(summary.blocked_fixes, 1)
        self.assertEqual(summary.pull_request_url, "https://example.test/pull/1")

    def test_available_versions_and_candidate_scan_use_configured_inputs(self) -> None:
        class FakeClient:
            offline = True

            def get_project(self, project):
                self.project = project
                return {"releases": {"1.0": [], "2.0": [], 3: []}}

        client = FakeClient()
        target = ScanTarget(
            requirement="demo==1.0",
            project="demo",
            version="1.0",
        )
        versions = cli_module._remediation_available_versions(
            [target],
            [vulnerable_report()],
            client=client,
            keyring_provider="auto",
        )
        self.assertEqual(versions, {"demo": ("1.0", "2.0")})

        resolution = Resolution(
            distributions=[
                ResolvedDistribution(
                    name="demo",
                    version="2.0",
                    artifacts=(
                        ArtifactReference(
                            filename="demo.whl",
                            hashes=(("sha256", "b" * 64),),
                        ),
                    ),
                )
            ]
        )
        observed: dict[str, object] = {}

        def inspect(project, **kwargs):
            observed["project"] = project
            observed.update(kwargs)
            return make_report("2.0")

        with patch("trustcheck.cli.inspect_package", side_effect=inspect):
            scanned = cli_module._scan_resolution_for_remediation(
                resolution,
                args=self._args(
                    with_transitive_deps=True,
                    inspect_artifacts=True,
                    trusted_project=["demo"],
                ),
                client=client,
                vulnerability_client=object(),
                policy=cli_module.resolve_policy(builtin_name="default"),
                progress_callback=None,
                dependency_progress_callback=None,
            )
        self.assertEqual(set(scanned), {"demo"})
        self.assertTrue(observed["include_transitive_dependencies"])
        self.assertTrue(observed["include_osv"])
        self.assertEqual(observed["locked_versions"], {"demo": "2.0"})

    def test_fix_runtime_installs_graph_and_runs_configured_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            prepared = PreparedRemediation(
                plan=validated_plan(root / "requirements.txt"),
                root=root,
                source_root=root,
            )
            resolution = Resolution(
                distributions=[
                    ResolvedDistribution(name="demo", version="2.0")
                ]
            )
            calls: list[list[str]] = []

            def runner(command, **kwargs):
                del kwargs
                calls.append(list(command))
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="ok",
                    stderr="",
                )

            with patch("trustcheck.cli.subprocess.run", side_effect=runner):
                install, pip_check, command_results = cli_module._validate_fix_runtime(
                    prepared,
                    resolution,
                    args=self._args(
                        fix_test_commands=[
                            "python -m compileall src",
                            "pytest -q",
                        ],
                    ),
                    offline=True,
                )

        self.assertTrue(install.passed)
        self.assertTrue(pip_check.passed)
        self.assertEqual(
            [result.command for result in command_results],
            ["python -m compileall src", "pytest -q"],
        )
        self.assertEqual(calls[0][1:3], ["-m", "venv"])
        self.assertIn("--no-index", calls[1])
        self.assertEqual(calls[2][-2:], ["pip", "check"])
        self.assertEqual(calls[3][1:], ["-m", "compileall", "src"])
        self.assertEqual(calls[4], ["pytest", "-q"])

    def test_generated_requirements_reuses_hashes_from_pip_tools_output(self) -> None:
        class FakeResolver:
            def resolve_requirements_file(self, path, **kwargs):
                self.path = path
                self.kwargs = kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(name="demo", version="2.0")
                    ]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            plan = validated_plan(target)
            resolver = FakeResolver()
            with prepare_remediation(target, plan) as prepared:
                staged_target = prepared.root / "requirements.txt"
                staged_target.write_text(
                    "demo==2.0 \\\n"
                    f"    --hash=sha256:{'c' * 64}\n",
                    encoding="utf-8",
                )
                resolution = cli_module._resolution_from_prepared(
                    prepared,
                    source_path=target,
                    args=self._args(),
                    resolver=resolver,
                    offline=True,
                )

        artifacts = resolution.distributions[0].artifacts
        self.assertEqual(artifacts[0].hashes, (("sha256", "c" * 64),))
        self.assertTrue(resolver.kwargs["offline"])

    def test_staged_paths_are_derived_from_resolved_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            aliased = root / "nested" / ".." / "requirements.txt"

            self.assertEqual(
                cli_module._relative_to_resolved_root(aliased, root),
                Path("requirements.txt"),
            )
            with self.assertRaisesRegex(RemediationError, "outside"):
                cli_module._relative_to_resolved_root(
                    root.parent / "outside.txt",
                    root,
                )

    def test_run_remediation_supports_plan_dry_run_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1.0\n", encoding="utf-8")
            baseline_target = ScanTarget(
                requirement="demo==1.0",
                project="demo",
                version="1.0",
            )
            client = SimpleNamespace(offline=True)
            policy = cli_module.resolve_policy(builtin_name="default")
            planned = RemediationPlan(
                source=str(target),
                status="not-needed",
                minimal=True,
            )

            with (
                patch(
                    "trustcheck.cli._remediation_root_requirements",
                    return_value=["demo==1.0"],
                ),
                patch(
                    "trustcheck.cli._remediation_available_versions",
                    return_value={},
                ),
                patch("trustcheck.cli.plan_remediation", return_value=planned),
            ):
                result = cli_module._run_remediation(
                    str(target),
                    targets=[baseline_target],
                    reports=[vulnerable_report()],
                    args=self._args(),
                    client=client,
                    vulnerability_client=None,
                    policy=policy,
                    resolver=object(),
                    progress_callback=None,
                    dependency_progress_callback=None,
                )
            self.assertIs(result, planned)

            for dry_run in (True, False):
                with self.subTest(dry_run=dry_run):
                    plan = validated_plan(target)
                    prepared = PreparedRemediation(
                        plan=plan,
                        root=root / "stage",
                        source_root=root,
                    )
                    apply_mock = unittest.mock.Mock()
                    patch_path = root / "trustcheck-fix.patch"

                    def write_patch(prepared):
                        prepared.plan.patch_path = str(patch_path)
                        return patch_path

                    with (
                        patch(
                            "trustcheck.cli._remediation_root_requirements",
                            return_value=["demo==1.0"],
                        ),
                        patch(
                            "trustcheck.cli._remediation_available_versions",
                            return_value={"demo": ("2.0",)},
                        ),
                        patch("trustcheck.cli.plan_remediation", return_value=plan),
                        patch(
                            "trustcheck.cli.prepare_remediation",
                            return_value=prepared,
                        ),
                        patch(
                            "trustcheck.cli._resolution_from_prepared",
                            return_value=plan.candidate_resolution,
                        ),
                        patch(
                            "trustcheck.cli._scan_resolution_for_remediation",
                            return_value={"demo": make_report("2.0")},
                        ),
                        patch(
                            "trustcheck.cli._validate_fix_runtime",
                            return_value=self._runtime_results(
                                CommandValidationResult(
                                    command="pytest -q",
                                    argv=("pytest", "-q"),
                                    returncode=0,
                                    stdout="1 passed",
                                )
                            ),
                        ),
                        patch(
                            "trustcheck.cli._write_default_fix_patch",
                            side_effect=write_patch,
                        ),
                        patch(
                            "trustcheck.cli.apply_prepared_remediation",
                            apply_mock,
                        ),
                    ):
                        result = cli_module._run_remediation(
                            str(target),
                            targets=[baseline_target],
                            reports=[vulnerable_report()],
                            args=self._args(fix=True, dry_run=dry_run),
                            client=client,
                            vulnerability_client=None,
                            policy=policy,
                            resolver=object(),
                            progress_callback=None,
                            dependency_progress_callback=None,
                        )
                    self.assertEqual(result.status, "validated")
                    self.assertEqual(apply_mock.called, not dry_run)
                    self.assertIsNotNone(result.after_graph)
                    self.assertIsNotNone(result.post_fix_result)
                    assert result.after_graph is not None
                    assert result.post_fix_result is not None
                    self.assertTrue(result.post_fix_result.reproduced_resolution)
                    self.assertEqual(
                        result.post_fix_result.dependency_graph_sha256,
                        result.after_graph.sha256,
                    )
                    self.assertIsNotNone(result.post_fix_result.clean_install)
                    self.assertEqual(
                        result.post_fix_result.test_commands[0].command,
                        "pytest -q",
                    )
                    self.assertEqual(
                        result.patch_path,
                        str(patch_path),
                    )
                    self.assertIn("trustcheck", result.post_fix_result.command[0])
                    if dry_run:
                        self.assertIn("no project files", result.message)

    def test_cli_requirement_reader_handles_continuations_hashes_and_missing_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            nested = root / "nested.txt"
            nested.write_text("dep==3\n", encoding="utf-8")
            target = root / "requirements.txt"
            target.write_text(
                "-r nested.txt\n"
                "demo==2 \\\n"
                f"  --hash=sha256:{'a' * 64}\n"
                "--index-url https://pypi.org/simple\n",
                encoding="utf-8",
            )
            self.assertEqual(
                cli_module._read_remediation_requirements(target),
                ["dep==3", "demo==2"],
            )
            with self.assertRaisesRegex(RemediationError, "does not exist"):
                cli_module._read_remediation_requirements(root / "missing.txt")

            pyproject = root / "pyproject.toml"
            pyproject.write_text("[project]\n", encoding="utf-8")
            self.assertEqual(
                cli_module._discover_remediation_manifest(pyproject),
                pyproject,
            )
            pyproject.unlink()
            source = root / "requirements.in"
            source.write_text("demo\n", encoding="utf-8")
            self.assertEqual(
                cli_module._discover_remediation_manifest(target),
                source,
            )
            self.assertEqual(
                cli_module._discover_remediation_manifest(source),
                source,
            )
            binary = root / "archive.whl"
            binary.write_bytes(b"")
            self.assertIsNone(
                cli_module._discover_remediation_manifest(binary)
            )

    def test_available_versions_ignores_inactive_and_failed_projects(self) -> None:
        class FailingClient:
            offline = True

            def get_project(self, project):
                del project
                raise cli_module.PypiClientError("unavailable")

        inactive = make_report("1.0")
        inactive.vulnerabilities = [
            VulnerabilityRecord(
                id="CVE-withdrawn",
                summary="withdrawn",
                fixed_in=["2"],
                withdrawn=True,
            )
        ]
        target = ScanTarget(
            requirement="demo==1",
            project="demo",
            version="1",
        )
        self.assertEqual(
            cli_module._remediation_available_versions(
                [target],
                [inactive],
                client=FailingClient(),
                keyring_provider="auto",
            ),
            {},
        )
        self.assertEqual(
            cli_module._remediation_available_versions(
                [target],
                [vulnerable_report()],
                client=FailingClient(),
                keyring_provider="auto",
            ),
            {},
        )

    def test_generated_resolution_supports_lock_toml_and_plain_requirements(
        self,
    ) -> None:
        class FakeResolver:
            def resolve_requirements(self, requirements, **kwargs):
                self.requirements = requirements
                self.requirement_kwargs = kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(name="demo", version="2")
                    ]
                )

            def resolve_requirements_file(self, path, **kwargs):
                self.file_path = path
                self.file_kwargs = kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(name="demo", version="2")
                    ]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stage = root / "stage"
            stage.mkdir()
            resolver = FakeResolver()

            pylock = root / "pylock.toml"
            pylock.write_text("", encoding="utf-8")
            (stage / "pylock.toml").write_text(
                'lock-version = "1.0"\n'
                'created-by = "test"\n'
                "[[packages]]\n"
                'name = "demo"\n'
                'version = "2"\n'
                'index = "https://pypi.org/simple"\n'
                "[[packages.wheels]]\n"
                'name = "demo.whl"\n'
                'url = "https://files.example/demo.whl"\n'
                f'hashes = {{sha256 = "{"a" * 64}"}}\n',
                encoding="utf-8",
            )
            prepared = PreparedRemediation(
                plan=RemediationPlan(source=str(pylock)),
                root=stage,
                source_root=root,
            )
            locked = cli_module._resolution_from_prepared(
                prepared,
                source_path=pylock,
                args=self._args(),
                resolver=resolver,
                offline=True,
            )
            self.assertEqual(locked.versions, {"demo": "2"})
            self.assertEqual(
                locked.distributions[0].source_url,
                "https://files.example/demo.whl",
            )

            pyproject = root / "pyproject.toml"
            pyproject.write_text("", encoding="utf-8")
            (stage / "pyproject.toml").write_text(
                '[project]\ndependencies = ["demo==2"]\n',
                encoding="utf-8",
            )
            resolved = cli_module._resolution_from_prepared(
                prepared,
                source_path=pyproject,
                args=self._args(),
                resolver=resolver,
                offline=False,
            )
            self.assertEqual(resolved.versions, {"demo": "2"})
            self.assertEqual(resolver.requirements, ["demo==2"])

            (stage / "pyproject.toml").write_text(
                "[project\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RemediationError, "generated TOML"):
                cli_module._resolution_from_prepared(
                    prepared,
                    source_path=pyproject,
                    args=self._args(),
                    resolver=resolver,
                    offline=False,
                )

            requirements = root / "requirements.txt"
            requirements.write_text("", encoding="utf-8")
            (stage / "requirements.txt").write_text(
                "demo==2\n",
                encoding="utf-8",
            )
            resolved = cli_module._resolution_from_prepared(
                prepared,
                source_path=requirements,
                args=self._args(),
                resolver=resolver,
                offline=True,
            )
            self.assertEqual(resolved.versions, {"demo": "2"})
            self.assertTrue(resolver.file_kwargs["offline"])

    def test_run_remediation_executes_solver_callbacks_and_constraints(self) -> None:
        class FakeResolver:
            def resolve_requirements(self, requirements, **kwargs):
                self.requirements = requirements
                self.kwargs = kwargs
                return Resolution(
                    distributions=[
                        ResolvedDistribution(name="demo", version="2")
                    ]
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            constraint = root / "constraints.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            constraint.write_text("demo<3\n", encoding="utf-8")
            resolver = FakeResolver()
            client = SimpleNamespace(offline=True)

            def planner(**kwargs):
                candidate = kwargs["resolve"](["demo==2"])
                scanned = kwargs["scan"](candidate)
                self.assertEqual(set(scanned), {"demo"})
                return RemediationPlan(
                    source=str(target),
                    status="not-needed",
                    minimal=True,
                )

            with (
                patch(
                    "trustcheck.cli._remediation_available_versions",
                    return_value={"demo": ("2",)},
                ),
                patch("trustcheck.cli.plan_remediation", side_effect=planner),
                patch(
                    "trustcheck.cli._scan_resolution_for_remediation",
                    return_value={"demo": make_report("2")},
                ),
            ):
                result = cli_module._run_remediation(
                    str(target),
                    targets=[
                        ScanTarget(
                            requirement="demo==1",
                            project="demo",
                            version="1",
                        )
                    ],
                    reports=[vulnerable_report()],
                    args=self._args(constraint=[str(constraint)]),
                    client=client,
                    vulnerability_client=None,
                    policy=cli_module.resolve_policy(builtin_name="default"),
                    resolver=resolver,
                    progress_callback=None,
                    dependency_progress_callback=None,
                )

        self.assertEqual(result.status, "not-needed")
        self.assertEqual(resolver.requirements, ["demo==2"])
        self.assertTrue(resolver.kwargs["offline"])

    def test_run_remediation_rejects_generated_graph_and_failed_rescan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            scan_target = ScanTarget(
                requirement="demo==1",
                project="demo",
                version="1.0",
            )
            client = SimpleNamespace(offline=True)
            policy = cli_module.resolve_policy(builtin_name="default")

            for generated, generated_reports, message in (
                (
                    Resolution(
                        distributions=[
                            ResolvedDistribution(name="demo", version="3")
                        ]
                    ),
                    {"demo": make_report("3")},
                    "minimal resolution",
                ),
                (
                    validated_plan(target).candidate_resolution,
                    {"demo": vulnerable_report()},
                    "security validation",
                ),
            ):
                with self.subTest(message=message):
                    plan = validated_plan(target)
                    prepared = PreparedRemediation(
                        plan=plan,
                        root=root / "stage",
                        source_root=root,
                    )
                    with (
                        patch(
                            "trustcheck.cli._remediation_root_requirements",
                            return_value=["demo==1"],
                        ),
                        patch(
                            "trustcheck.cli._remediation_available_versions",
                            return_value={"demo": ("2",)},
                        ),
                        patch("trustcheck.cli.plan_remediation", return_value=plan),
                        patch(
                            "trustcheck.cli.prepare_remediation",
                            return_value=prepared,
                        ),
                        patch(
                            "trustcheck.cli._resolution_from_prepared",
                            return_value=generated,
                        ),
                        patch(
                            "trustcheck.cli._scan_resolution_for_remediation",
                            return_value=generated_reports,
                        ),
                        self.assertRaisesRegex(RemediationError, message),
                    ):
                        cli_module._run_remediation(
                            str(target),
                            targets=[scan_target],
                            reports=[vulnerable_report()],
                            args=self._args(fix=True),
                            client=client,
                            vulnerability_client=None,
                            policy=policy,
                            resolver=object(),
                            progress_callback=None,
                            dependency_progress_callback=None,
                        )

    def test_run_remediation_records_pull_request_failure_and_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            scan_target = ScanTarget(
                requirement="demo==1",
                project="demo",
                version="1.0",
            )
            client = SimpleNamespace(offline=True)
            policy = cli_module.resolve_policy(builtin_name="default")

            for created in (False, True):
                with self.subTest(created=created):
                    plan = validated_plan(target)
                    prepared = PreparedRemediation(
                        plan=plan,
                        root=root / "stage",
                        source_root=root,
                    )
                    pr_result = PullRequestResult(
                        created=created,
                        branch="trustcheck/fix-demo",
                    )
                    with (
                        patch(
                            "trustcheck.cli._remediation_root_requirements",
                            return_value=["demo==1"],
                        ),
                        patch(
                            "trustcheck.cli._remediation_available_versions",
                            return_value={"demo": ("2",)},
                        ),
                        patch("trustcheck.cli.plan_remediation", return_value=plan),
                        patch(
                            "trustcheck.cli.prepare_remediation",
                            return_value=prepared,
                        ),
                        patch(
                            "trustcheck.cli._resolution_from_prepared",
                            return_value=plan.candidate_resolution,
                        ),
                        patch(
                            "trustcheck.cli._scan_resolution_for_remediation",
                            return_value={"demo": make_report("2")},
                        ),
                        patch(
                            "trustcheck.cli._validate_fix_runtime",
                            return_value=self._runtime_results(),
                        ),
                        patch(
                            "trustcheck.cli.create_pull_request",
                            return_value=pr_result,
                        ),
                    ):
                        result = cli_module._run_remediation(
                            str(target),
                            targets=[scan_target],
                            reports=[vulnerable_report()],
                            args=self._args(
                                fix=True,
                                create_pr=True,
                                pr_base="main",
                                pr_branch="trustcheck/fix-demo",
                                pr_title="Fix demo",
                                pr_ready=True,
                            ),
                            client=client,
                            vulnerability_client=None,
                            policy=policy,
                            resolver=object(),
                            progress_callback=None,
                            dependency_progress_callback=None,
                        )
                    self.assertEqual(
                        result.status,
                        "validated" if created else "failed",
                    )

    def test_scan_maps_remediation_errors_and_post_fix_policy_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "requirements.txt"
            target.write_text("demo==1\n", encoding="utf-8")
            bundle = root / "remediation.json"
            scan_target = ScanTarget(
                requirement="demo==1",
                project="demo",
                version="1",
            )

            with (
                patch(
                    "trustcheck.cli._load_scan_targets",
                    return_value=[scan_target],
                ),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=make_report("1"),
                ),
                patch(
                    "trustcheck.cli._run_remediation",
                    side_effect=RemediationError("solver failed"),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "scan",
                        "-f",
                        str(target),
                        "--plan-fixes",
                        "--remediation-output",
                        str(bundle),
                        "--format",
                        "text",
                    ]
                )

            self.assertEqual(exit_code, EXIT_REMEDIATION_FAILURE)
            self.assertEqual(
                json.loads(bundle.read_text(encoding="utf-8"))["status"],
                "failed",
            )

            plan = validated_plan(target)
            plan.validation = RemediationValidation(
                resolution_passed=True,
                rescan_passed=True,
                targeted_advisories_removed=True,
                no_new_vulnerabilities=True,
                no_new_policy_violations=True,
                index_provenance_preserved=True,
                policy_passed=False,
            )
            with (
                patch(
                    "trustcheck.cli._load_scan_targets",
                    return_value=[scan_target],
                ),
                patch(
                    "trustcheck.cli.inspect_package",
                    return_value=make_report("1"),
                ),
                patch("trustcheck.cli._run_remediation", return_value=plan),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "scan",
                        "-f",
                        str(target),
                        "--fix",
                        "--dry-run",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(exit_code, EXIT_POLICY_FAILURE)


if __name__ == "__main__":
    unittest.main()
