from __future__ import annotations

import argparse
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from packaging.utils import canonicalize_name

from scripts.validate_sarif import validate_sarif
from trustcheck.cli import EXIT_OK, EXIT_POLICY_FAILURE, ScanTarget, main
from trustcheck.cli_commands import diff as diff_command
from trustcheck.diff import (
    TrustDiffChange,
    TrustDiffFinding,
    TrustDiffReport,
    build_dependency_diff,
    enrich_dependency_diff,
    manifest_exception_changes,
    merge_manifest_exception_changes,
    render_trust_diff_markdown,
    render_trust_diff_sarif,
    render_trust_diff_text,
    should_fail_diff,
)
from trustcheck.manifest import build_manifest
from trustcheck.models import (
    ArtifactInspection,
    CoverageSummary,
    FileProvenance,
    MaliciousPackageAssessment,
    PublisherIdentity,
    SlsaProvenance,
    TrustReport,
    VulnerabilityRecord,
)
from trustcheck.pypi import PypiClientError


def make_target(
    project: str,
    version: str,
    *,
    requested: bool = True,
    index_url: str | None = "https://pypi.org/simple",
    source_type: str = "index",
    line: int | None = 1,
) -> ScanTarget:
    return ScanTarget(
        requirement=f"{project}=={version}",
        project=project,
        version=version,
        requested=requested,
        index_url=index_url,
        source_type=source_type,
        source_file="requirements.lock",
        source_line=line,
    )


def make_report(
    project: str,
    version: str,
    *,
    repository: str = "https://github.com/example/demo",
    workflow: str = ".github/workflows/release.yml",
    builder: str = "https://github.com/actions/runner",
    build_type: str = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
    verified: bool = True,
    has_provenance: bool = True,
    native: bool = False,
    malicious_score: int = 0,
    vulnerabilities: tuple[str, ...] = (),
    ownership: dict[str, object] | None = None,
    artifact_kind: str = "wheel",
) -> TrustReport:
    filename = (
        f"{project}-{version}.tar.gz"
        if artifact_kind == "sdist"
        else f"{project}-{version}-py3-none-any.whl"
    )
    return TrustReport(
        project=project,
        version=version,
        summary=f"{project} package",
        package_url=f"https://pypi.org/project/{project}/{version}/",
        declared_repository_urls=[repository],
        repository_urls=[repository],
        ownership=ownership or {"organization": "example", "license": "MIT"},
        vulnerabilities=[
            VulnerabilityRecord(id=identifier, summary="Advisory")
            for identifier in vulnerabilities
        ],
        files=[
            FileProvenance(
                filename=filename,
                url=f"https://files.example/{project}.whl",
                sha256="a" * 64,
                has_provenance=has_provenance,
                verified=verified,
                attestation_count=1 if has_provenance else 0,
                verified_attestation_count=1 if verified else 0,
                publisher_identities=(
                    [
                        PublisherIdentity(
                            kind="GitHub",
                            repository=repository,
                            workflow=workflow,
                            environment=None,
                        )
                    ]
                    if verified
                    else []
                ),
                slsa_provenance=(
                    [
                        SlsaProvenance(
                            valid=True,
                            source_repository=repository,
                            builder_id=builder,
                            build_type=build_type,
                            workflow_path=workflow,
                        )
                    ]
                    if verified
                    else []
                ),
                artifact=ArtifactInspection(
                    inspected=True,
                    kind=artifact_kind,
                    native_files=([f"{project}/native.so"] if native else []),
                ),
            )
        ],
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1 if has_provenance else 0,
            verified_files=1 if verified else 0,
            status="all-verified" if verified else "none",
        ),
        malicious_package=MaliciousPackageAssessment(score=malicious_score),
    )


class DiffModelTests(unittest.TestCase):
    def test_build_dependency_diff_detects_graph_and_origin_changes(self) -> None:
        old = [
            make_target("requests", "2.32.3", line=1),
            make_target("urllib3", "2.4.0", requested=False, line=2),
            make_target("removed", "1.0", line=3),
            make_target("sourcey", "1.0", source_type="index", line=4),
        ]
        new = [
            make_target("requests", "2.32.5", line=1),
            make_target("urllib3", "2.5.0", requested=False, line=2),
            make_target("added", "1.0", requested=False, line=3),
            make_target("sourcey", "1.0", source_type="vcs", line=4),
        ]

        changes = build_dependency_diff(old, new)
        by_name = {canonicalize_name(change.project): change for change in changes}

        self.assertEqual(by_name["requests"].change_type, "updated")
        self.assertEqual(by_name["urllib3"].old_version, "2.4.0")
        self.assertEqual(by_name["added"].change_type, "added")
        self.assertEqual(
            by_name["removed"].findings[0].message,
            "package removed from the dependency graph",
        )
        self.assertEqual(by_name["sourcey"].change_type, "source-changed")

    def test_enrich_dependency_diff_reports_trust_regressions_and_manifest_violations(self) -> None:
        old_targets = [make_target("urllib3", "2.4.0", requested=False)]
        new_targets = [
            make_target(
                "urllib3",
                "2.5.0",
                requested=False,
                index_url="https://private.example/simple",
            )
        ]
        changes = build_dependency_diff(old_targets, new_targets)
        old_report = make_report("urllib3", "2.4.0")
        new_report = make_report(
            "urllib3",
            "2.5.0",
            repository="https://github.com/other/urllib3",
            workflow=".github/workflows/publish.yml",
            builder="https://example.com/builder",
            build_type="https://example.com/build/v1",
            verified=False,
            has_provenance=False,
            native=True,
            malicious_score=60,
            vulnerabilities=("GHSA-new",),
            ownership={"organization": "other", "license": "Apache-2.0"},
            artifact_kind="sdist",
        )
        manifest = build_manifest([old_report], old_targets)

        enriched = enrich_dependency_diff(
            changes,
            old_reports={"urllib3": old_report},
            new_reports={"urllib3": new_report},
            manifest=manifest,
            new_targets=new_targets,
        )
        codes = {finding.code for finding in enriched[0].findings}

        self.assertEqual(enriched[0].severity, "HIGH")
        self.assertIn("index_origin_changed", codes)
        self.assertIn("new_vulnerability_signal", codes)
        self.assertIn("malicious_score_increased", codes)
        self.assertIn("provenance_unavailable", codes)
        self.assertIn("repository_changed", codes)
        self.assertIn("trusted_publisher_changed", codes)
        self.assertIn("slsa_identity_changed", codes)
        self.assertIn("maintainer_metadata_changed", codes)
        self.assertIn("license_changed", codes)
        self.assertIn("artifact_distribution_changed", codes)
        self.assertIn("native_binary_introduced", codes)
        self.assertIn("manifest_repository_changed", codes)

    def test_manifest_exception_changes_merge_into_dependency_changes(self) -> None:
        old_targets = [make_target("requests", "2.32.3")]
        new_targets = [make_target("requests", "2.32.5")]
        old_report = make_report("requests", "2.32.3")
        new_report = make_report("requests", "2.32.5")
        old_manifest = build_manifest([old_report], old_targets)
        new_manifest = build_manifest([new_report], new_targets)
        new_manifest["packages"]["requests"]["exceptions"] = [
            {
                "code": "provenance_missing",
                "owner": "security",
                "reason": "Reviewing publisher migration.",
                "expires": "2026-08-01",
            }
        ]
        merged = merge_manifest_exception_changes(
            build_dependency_diff(old_targets, new_targets),
            old_manifest=old_manifest,
            new_manifest=new_manifest,
            source="trustcheck.manifest.json",
        )

        enriched = enrich_dependency_diff(
            merged,
            old_reports={"requests": old_report},
            new_reports={"requests": new_report},
            new_targets=new_targets,
        )

        self.assertEqual(enriched[0].severity, "MED")
        self.assertEqual(enriched[0].findings[0].code, "manifest_exception_added")

    def test_enrich_dependency_diff_adds_low_no_regression_finding(self) -> None:
        old_targets = [make_target("requests", "2.32.3")]
        new_targets = [make_target("requests", "2.32.5")]
        changes = build_dependency_diff(old_targets, new_targets)

        enriched = enrich_dependency_diff(
            changes,
            old_reports={"requests": make_report("requests", "2.32.3")},
            new_reports={"requests": make_report("requests", "2.32.5")},
            new_targets=new_targets,
        )

        self.assertEqual(enriched[0].severity, "LOW")
        self.assertEqual(enriched[0].findings[0].code, "no_trust_regression")

    def test_renderers_and_fail_policy_cover_text_markdown_json_and_sarif(self) -> None:
        change = build_dependency_diff(
            [make_target("requests", "2.32.3")],
            [make_target("requests", "2.32.5")],
        )[0]
        change.findings.append(
            change.findings[0]
            if change.findings
            else enrich_dependency_diff(
                [change],
                old_reports={"requests": make_report("requests", "2.32.3")},
                new_reports={"requests": make_report("requests", "2.32.5")},
            )[0].findings[0]
        )
        report = TrustDiffReport("old.lock", "new.lock", [change])

        self.assertIn("1 package changed", render_trust_diff_text(report))
        self.assertIn("Changed Packages", render_trust_diff_markdown(report))
        payload = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(payload["schema"], "urn:trustcheck:diff:1.0")
        sarif = json.loads(render_trust_diff_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertFalse(should_fail_diff(report, fail_on="high"))
        self.assertTrue(should_fail_diff(report, fail_on="low"))


class DiffEdgeCaseTests(unittest.TestCase):
    def test_empty_failure_and_fallback_rendering_paths(self) -> None:
        empty_change = TrustDiffChange("demo", "unchanged", None, None)
        self.assertEqual(empty_change.severity, "LOW")

        empty_report = TrustDiffReport("old.lock", "new.lock", [])
        self.assertEqual(empty_report.max_severity, "LOW")
        self.assertIn("0 packages changed", render_trust_diff_markdown(empty_report))

        failure_report = TrustDiffReport(
            "old.lock",
            "new.lock",
            [],
            failures=[{"requirement": "demo==1.0", "message": "boom"}],
        )
        self.assertEqual(failure_report.max_severity, "HIGH")
        self.assertTrue(should_fail_diff(failure_report, fail_on="none"))
        self.assertIn("failures:", render_trust_diff_text(failure_report))
        self.assertIn("## Failures", render_trust_diff_markdown(failure_report))
        self.assertIn("TC-DIFF-SCAN-FAILURE", render_trust_diff_sarif(failure_report))

        version_report = TrustDiffReport(
            "old.lock",
            "new.lock",
            [
                TrustDiffChange(
                    "added",
                    "added",
                    None,
                    "1.0",
                    findings=[TrustDiffFinding("added", "LOW", "added")],
                ),
                TrustDiffChange(
                    "removed",
                    "removed",
                    "1.0",
                    None,
                    findings=[TrustDiffFinding("removed", "LOW", "removed")],
                ),
                TrustDiffChange(
                    "sourcey",
                    "source-changed",
                    None,
                    None,
                    findings=[TrustDiffFinding("source", "LOW", "source")],
                ),
            ],
        )
        rendered = render_trust_diff_text(version_report)
        self.assertIn("new 1.0", rendered)
        self.assertIn("removed 1.0", rendered)
        self.assertIn("source-changed", rendered)

    def test_enrich_covers_direct_additions_source_changes_and_verified_loss(self) -> None:
        added = enrich_dependency_diff(
            build_dependency_diff([], [make_target("native", "1.0", requested=True)]),
            old_reports={},
            new_reports={"native": make_report("native", "1.0", native=True)},
        )
        added_codes = {finding.code for finding in added[0].findings}
        self.assertIn("new_direct_dependency", added_codes)
        self.assertIn("new_native_binary", added_codes)

        source_changed = enrich_dependency_diff(
            build_dependency_diff(
                [make_target("sourcey", "1.0", source_type="index")],
                [make_target("sourcey", "1.0", source_type="vcs")],
            ),
            old_reports={"sourcey": make_report("sourcey", "1.0")},
            new_reports={"sourcey": make_report("sourcey", "1.0")},
        )
        self.assertEqual(source_changed[0].findings[0].code, "source_type_changed")

        provenance = enrich_dependency_diff(
            build_dependency_diff(
                [make_target("prov", "1.0")],
                [make_target("prov", "1.1")],
            ),
            old_reports={"prov": make_report("prov", "1.0", verified=True)},
            new_reports={
                "prov": make_report(
                    "prov",
                    "1.1",
                    has_provenance=True,
                    verified=False,
                )
            },
        )
        self.assertIn(
            "verified_provenance_disappeared",
            {finding.code for finding in provenance[0].findings},
        )

        fallback_old = make_report("artifact", "1.0", artifact_kind="unknown")
        fallback_new = make_report("artifact", "1.1", artifact_kind="unknown")
        fallback_new.files[0].filename = "artifact-1.1.tar.gz"
        artifact = enrich_dependency_diff(
            build_dependency_diff(
                [make_target("artifact", "1.0")],
                [make_target("artifact", "1.1")],
            ),
            old_reports={"artifact": fallback_old},
            new_reports={"artifact": fallback_new},
        )
        self.assertIn(
            "artifact_distribution_changed",
            {finding.code for finding in artifact[0].findings},
        )

    def test_manifest_exception_changes_cover_new_and_unchanged_exceptions(self) -> None:
        current = build_manifest([make_report("requests", "2.32.5")])
        current["packages"]["requests"]["exceptions"] = [
            {
                "code": "provenance_missing",
                "owner": "security",
                "reason": "Temporary migration.",
                "expires": "2026-08-01",
            }
        ]

        changes = merge_manifest_exception_changes(
            [],
            old_manifest=None,
            new_manifest=current,
            source="trustcheck.manifest.json",
        )
        self.assertEqual(changes[0].change_type, "manifest-exception-added")
        self.assertEqual(changes[0].findings[0].code, "manifest_exception_added")
        self.assertEqual(
            manifest_exception_changes(current, current),
            [],
        )

    def test_cli_diff_helpers_cover_git_and_comment_error_paths(self) -> None:
        positional = argparse.Namespace(old_file="old.lock", new_file="new.lock")
        self.assertEqual(
            diff_command._diff_file_pairs(positional, Path("."))[0][2:],
            ("old.lock", "new.lock"),
        )
        self.assertEqual(
            diff_command._changed_dependency_paths(
                "base",
                "head",
                restricted_paths=["requirements.lock", "requirements.lock"],
            ),
            ["requirements.lock"],
        )
        self.assertTrue(diff_command._is_dependency_file("uv.lock"))

        with patch(
            "trustcheck.cli_commands.diff.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["git", "diff"],
                1,
                stdout="",
                stderr="bad diff",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "bad diff"):
                diff_command._changed_dependency_paths(
                    "base",
                    "head",
                    restricted_paths=[],
                )

        with patch(
            "trustcheck.cli_commands.diff.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["git", "show"],
                1,
                stdout=b"",
                stderr=b"missing",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "missing"):
                diff_command._git_show("HEAD", "requirements.lock")

        manifest = build_manifest([make_report("requests", "2.32.5")])
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "trustcheck.manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            args = argparse.Namespace(
                base="origin/main",
                head="HEAD",
                manifest=str(manifest_path),
            )
            with patch(
                "trustcheck.cli_commands.diff._git_show",
                side_effect=ValueError("missing"),
            ):
                loaded = diff_command._load_manifest_for_diff(
                    args,
                    Path(directory),
                )
                base = diff_command._load_base_manifest_for_diff(
                    args,
                    Path(directory),
                )
        self.assertEqual(loaded["packages"]["requests"]["approved_version"], "2.32.5")
        self.assertIsNone(base)

        with patch(
            "trustcheck.cli_commands.diff.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["gh", "pr", "comment"],
                1,
                stdout="",
                stderr="comment failed",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "comment failed"):
                diff_command._post_github_comment("body")

    def test_inspect_targets_records_upstream_and_payload_failures(self) -> None:
        targets = [
            make_target("missing", "1.0"),
            make_target("invalid", "1.0"),
            make_target("skipped", "1.0"),
        ]

        class FakeCli:
            def _client_for_target(self, client, target, **kwargs):
                return client

            def _clone_pypi_client(self, client):
                return client

            def _target_environment_from_args(self, args):
                return None

            def _format_upstream_error(self, exc):
                return f"upstream: {exc}"

            def inspect_package(self, project, **kwargs):
                if project == "missing":
                    raise PypiClientError("not found", transient=False)
                raise ValueError("bad payload")

        args = argparse.Namespace(
            keyring_provider="auto",
            dynamic_analysis=False,
            trusted_project=[],
            diff_artifact_scope="all",
            max_workers=1,
        )
        _reports, failures = diff_command._inspect_targets(
            args,
            cli=FakeCli(),
            targets=targets,
            selected_names={"missing", "invalid"},
            client=object(),
            resolver=None,
            plugin_manager=None,
            vulnerability_client=object(),
        )

        self.assertEqual(len(failures), 2)
        self.assertIn("upstream", failures[0]["message"])
        self.assertIn("bad payload", failures[1]["message"])


class DiffCliTests(unittest.TestCase):
    def test_diff_cli_scans_only_changed_packages_and_renders_json(self) -> None:
        old_targets = [
            make_target("requests", "2.32.3"),
            make_target("unchanged", "1.0"),
        ]
        new_targets = [
            make_target("requests", "2.32.5"),
            make_target("unchanged", "1.0"),
        ]
        calls: list[tuple[str, str | None, bool]] = []

        def fake_inspect(project: str, **kwargs):
            calls.append((project, kwargs["version"], kwargs["include_osv"]))
            return make_report(project, kwargs["version"] or "0")

        stdout = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", side_effect=[old_targets, new_targets]),
            patch("trustcheck.cli.inspect_package", side_effect=fake_inspect),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(
                [
                    "diff",
                    "old.lock",
                    "new.lock",
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                    "--with-osv",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(payload["package_count"], 1)
        self.assertEqual(
            calls,
            [("requests", "2.32.3", True), ("requests", "2.32.5", True)],
        )

    def test_diff_cli_returns_policy_failure_for_high_regression(self) -> None:
        old_targets = [make_target("urllib3", "2.4.0")]
        new_targets = [make_target("urllib3", "2.5.0")]

        def fake_inspect(project: str, **kwargs):
            version = kwargs["version"]
            if version == "2.4.0":
                return make_report(project, version)
            return make_report(project, version, has_provenance=False, verified=False)

        stdout = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", side_effect=[old_targets, new_targets]),
            patch("trustcheck.cli.inspect_package", side_effect=fake_inspect),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(["diff", "old.lock", "new.lock"])

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertIn("release provenance unavailable", stdout.getvalue())

    def test_diff_cli_validates_target_modes(self) -> None:
        cases = [
            ["diff", "old.lock"],
            ["diff", "old.lock", "new.lock", "--base", "origin/main"],
            ["diff", "--comment", "--base", "origin/main", "--head", "HEAD"],
            ["diff"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                with (
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    main(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_diff_cli_supports_github_pr_mode_and_comment(self) -> None:
        old_targets = [make_target("requests", "2.32.3")]
        new_targets = [make_target("requests", "2.32.5")]
        subprocess_calls: list[list[str]] = []

        def fake_run(command, **kwargs):
            subprocess_calls.append(command)
            if command[:3] == ["git", "diff", "--name-only"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="requirements.lock\nREADME.md\n",
                    stderr="",
                )
            if command[:2] == ["git", "show"]:
                return subprocess.CompletedProcess(command, 0, stdout=b"requests==2\n", stderr=b"")
            if command[:3] == ["gh", "pr", "comment"]:
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            raise AssertionError(command)

        stdout = io.StringIO()
        with (
            patch("trustcheck.cli_commands.diff.subprocess.run", side_effect=fake_run),
            patch("trustcheck.cli._load_scan_targets", side_effect=[old_targets, new_targets]),
            patch("trustcheck.cli.inspect_package", side_effect=[
                make_report("requests", "2.32.3"),
                make_report("requests", "2.32.5"),
            ]),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(
                [
                    "diff",
                    "--base",
                    "origin/main",
                    "--head",
                    "HEAD",
                    "--github-pr",
                    "--comment",
                    "--format",
                    "markdown",
                    "--fail-on",
                    "none",
                ]
            )

        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("trustcheck dependency trust diff", stdout.getvalue())
        self.assertTrue(any(call[:3] == ["gh", "pr", "comment"] for call in subprocess_calls))

    def test_diff_cli_reports_manifest_exception_added_in_pr_mode(self) -> None:
        old_targets = [make_target("requests", "2.32.3")]
        new_targets = [make_target("requests", "2.32.5")]
        old_report = make_report("requests", "2.32.3")
        new_report = make_report("requests", "2.32.5")
        old_manifest = build_manifest([old_report], old_targets)
        new_manifest = build_manifest([new_report], new_targets)
        new_manifest["packages"]["requests"]["exceptions"] = [
            {
                "code": "provenance_missing",
                "owner": "security",
                "reason": "Reviewing publisher migration.",
                "expires": "2026-08-01",
            }
        ]
        git_payloads = {
            "origin/main:requirements.lock": b"requests==2.32.3\n",
            "HEAD:requirements.lock": b"requests==2.32.5\n",
            "origin/main:trustcheck.manifest.json": json.dumps(old_manifest).encode(),
            "HEAD:trustcheck.manifest.json": json.dumps(new_manifest).encode(),
        }

        def fake_run(command, **kwargs):
            if command[:3] == ["git", "diff", "--name-only"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="requirements.lock\ntrustcheck.manifest.json\n",
                    stderr="",
                )
            if command[:2] == ["git", "show"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=git_payloads[command[2]],
                    stderr=b"",
                )
            raise AssertionError(command)

        stdout = io.StringIO()
        with (
            patch("trustcheck.cli_commands.diff.subprocess.run", side_effect=fake_run),
            patch("trustcheck.cli._load_scan_targets", side_effect=[old_targets, new_targets]),
            patch("trustcheck.cli.inspect_package", side_effect=[old_report, new_report]),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(
                [
                    "diff",
                    "--base",
                    "origin/main",
                    "--head",
                    "HEAD",
                    "--github-pr",
                    "--manifest",
                    "trustcheck.manifest.json",
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )

        payload = json.loads(stdout.getvalue())
        codes = {
            finding["code"]
            for change in payload["changes"]
            for finding in change["findings"]
        }
        self.assertEqual(exit_code, EXIT_OK)
        self.assertIn("manifest_exception_added", codes)

    def test_diff_sarif_output_validates(self) -> None:
        old_targets = [make_target("requests", "2.32.3")]
        new_targets = [make_target("requests", "2.32.5")]
        stdout = io.StringIO()
        with (
            patch("trustcheck.cli._load_scan_targets", side_effect=[old_targets, new_targets]),
            patch("trustcheck.cli.inspect_package", side_effect=[
                make_report("requests", "2.32.3"),
                make_report("requests", "2.32.5", has_provenance=False, verified=False),
            ]),
            redirect_stdout(stdout),
            redirect_stderr(io.StringIO()),
        ):
            exit_code = main(
                [
                    "diff",
                    "old.lock",
                    "new.lock",
                    "--format",
                    "sarif",
                ]
            )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".sarif",
            delete=False,
        ) as tmp:
            tmp.write(stdout.getvalue())
            path = tmp.name
        try:
            fingerprints = validate_sarif(Path(path))
        finally:
            Path(path).unlink(missing_ok=True)
        self.assertGreaterEqual(len(fingerprints), 1)
