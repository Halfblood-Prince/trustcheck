from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from trustcheck.cli import EXIT_OK, EXIT_POLICY_FAILURE, build_parser, main
from trustcheck.cli_commands import install as install_command
from trustcheck.cli_models import ScanTarget
from trustcheck.models import (
    CoverageSummary,
    FileProvenance,
    PolicyEvaluation,
    PolicyViolation,
    TrustReport,
)
from trustcheck.policy import PolicySettings
from trustcheck.pypi import PypiClientError
from trustcheck.resolver import ArtifactReference, TargetEnvironment

WHEEL_BYTES = b"verified wheel bytes"
WHEEL_DIGEST = hashlib.sha256(WHEEL_BYTES).hexdigest()
WHEEL_FILENAME = "demo-1.0-py3-none-any.whl"
WHEEL_URL = f"https://files.pythonhosted.org/packages/{WHEEL_FILENAME}"


class FakeDownloadClient:
    timeout = 10.0
    max_retries = 0
    backoff_factor = 0.0
    offline = False
    request_hook = None

    def __init__(self) -> None:
        self.downloads: list[str] = []

    def download_distribution(self, url: str) -> bytes:
        self.downloads.append(url)
        return WHEEL_BYTES


class FakeInstallCli:
    __version__ = "test-version"

    class ArtifactDigestCache:
        pass

    def __init__(self) -> None:
        self.outputs: list[tuple[str, str | None]] = []

    def _merge_exit_codes(self, first: int, second: int) -> int:
        return max(first, second)

    def _format_upstream_error(self, exc: Exception) -> str:
        return f"upstream: {exc}"

    def _clone_pypi_client(self, client):
        return client

    def _client_for_target(self, client, target, **kwargs):
        del target, kwargs
        return client

    def _target_environment_from_args(self, args) -> TargetEnvironment:
        del args
        return TargetEnvironment()

    def _emit_output(self, rendered: str, output_file: str | None) -> None:
        self.outputs.append((rendered, output_file))

    def inspect_package(self, project: str, **kwargs) -> TrustReport:
        del kwargs
        if project == "upstream":
            raise PypiClientError("registry unavailable")
        if project == "invalid":
            raise ValueError("invalid payload")
        return make_report()

    def evaluate_policy(
        self,
        report: TrustReport,
        policy: PolicySettings,
        **kwargs,
    ) -> PolicyEvaluation:
        del report, policy, kwargs
        return PolicyEvaluation(
            passed=False,
            violations=[
                PolicyViolation(
                    code="policy",
                    severity="high",
                    message="policy blocked package",
                )
            ],
        )

    def _load_scan_targets(self, *args, **kwargs):
        del args, kwargs
        return [make_target()]

    def _scan_targets_from_resolution(self, resolution):
        del resolution
        return [make_target()]


def make_target() -> ScanTarget:
    return ScanTarget(
        requirement="demo==1.0",
        project="demo",
        version="1.0",
        locked_versions={"demo": "1.0"},
        complete_locked_versions=True,
        artifacts=(
            ArtifactReference(
                filename=WHEEL_FILENAME,
                url=WHEEL_URL,
                hashes=(("sha256", WHEEL_DIGEST),),
            ),
        ),
    )


def make_report(*, verified: bool = True) -> TrustReport:
    return TrustReport(
        project="demo",
        version="1.0",
        summary="demo package",
        package_url="https://pypi.org/project/demo/1.0/",
        files=[
            FileProvenance(
                filename=WHEEL_FILENAME,
                url=WHEEL_URL,
                sha256=WHEEL_DIGEST,
                observed_sha256=WHEEL_DIGEST if verified else None,
                has_provenance=verified,
                verified=verified,
                attestation_count=1 if verified else 0,
                verified_attestation_count=1 if verified else 0,
            )
        ],
        coverage=CoverageSummary(
            total_files=1,
            files_with_provenance=1 if verified else 0,
            verified_files=1 if verified else 0,
            status="all-verified" if verified else "none",
        ),
        recommendation="verified" if verified else "metadata-only",
    )


def install_args(**overrides) -> argparse.Namespace:
    defaults = {
        "requirement_file": "requirements.txt",
        "requirements": [],
        "lock": "trustcheck.lock",
        "report": "trustcheck-install-report.json",
        "attestation": "trustcheck-install-attestation.json",
        "python_version": None,
        "platform": None,
        "implementation": None,
        "abi": None,
        "constraint": [],
        "extra": [],
        "group": [],
        "keyring_provider": "auto",
        "max_workers": 1,
        "dynamic_analysis": False,
        "trusted_project": [],
        "dry_run": False,
        "allow_sdist": False,
        "require_provenance": False,
        "format": "text",
        "output_file": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def file_provenance(
    filename: str,
    *,
    url: str = WHEEL_URL,
    sha256: str | None = WHEEL_DIGEST,
    observed_sha256: str | None = WHEEL_DIGEST,
    verified: bool = True,
) -> FileProvenance:
    return FileProvenance(
        filename=filename,
        url=url,
        sha256=sha256,
        observed_sha256=observed_sha256,
        has_provenance=verified,
        verified=verified,
    )


def report_with_files(files: list[FileProvenance]) -> TrustReport:
    payload = make_report()
    payload.files = files
    return payload


def install_plan(
    *,
    target: ScanTarget | None = None,
    report: TrustReport | None = None,
    artifact: install_command.InstallArtifact | None = None,
    evaluation: PolicyEvaluation | None = None,
    failures: list[str] | None = None,
) -> install_command.InstallPlanItem:
    return install_command.InstallPlanItem(
        target=target or make_target(),
        report=report,
        artifact=artifact,
        evaluation=evaluation,
        failures=failures or [],
    )


class InstallCommandTests(unittest.TestCase):
    def test_parser_accepts_secure_install_examples(self) -> None:
        parser = build_parser()

        file_args = parser.parse_args(
            ["install", "-r", "requirements.txt", "--policy", "strict"]
        )
        self.assertEqual(file_args.command, "install")
        self.assertEqual(file_args.requirement_file, "requirements.txt")
        self.assertEqual(file_args.policy, "strict")

        lock_args = parser.parse_args(
            ["install", "-r", "requirements.txt", "--lock", "trustcheck.lock"]
        )
        self.assertEqual(lock_args.lock, "trustcheck.lock")

        direct_args = parser.parse_args(
            ["install", "requests==2.32.5", "--require-provenance"]
        )
        self.assertEqual(direct_args.requirements, ["requests==2.32.5"])
        self.assertTrue(direct_args.require_provenance)

    def test_install_downloads_verified_artifact_then_invokes_local_pip(self) -> None:
        stdout = io.StringIO()
        fake_client = FakeDownloadClient()
        target = make_target()

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            lock = root / "trustcheck.lock"
            report_path = root / "trustcheck-install-report.json"
            attestation = root / "trustcheck-install-attestation.json"
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            )

            def fake_inspect_package(project: str, **kwargs):
                self.assertEqual(project, "demo")
                self.assertTrue(kwargs["inspect_artifacts"])
                self.assertEqual(kwargs["scan_profile"], "full")
                self.assertEqual(kwargs["artifact_scope"], "target")
                return make_report()

            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch("trustcheck.cli._client_for_target", return_value=fake_client),
                patch(
                    "trustcheck.cli.inspect_package",
                    side_effect=fake_inspect_package,
                ),
                patch(
                    "trustcheck.cli_commands.install.subprocess.run",
                    return_value=completed,
                ) as pip_run,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "install",
                        "-r",
                        "requirements.txt",
                        "--lock",
                        str(lock),
                        "--report",
                        str(report_path),
                        "--attestation",
                        str(attestation),
                    ]
                )

            self.assertEqual(exit_code, EXIT_OK)
            self.assertEqual(fake_client.downloads, [WHEEL_URL])
            command = pip_run.call_args.args[0]
            self.assertIn("--no-index", command)
            self.assertIn("--find-links", command)
            self.assertIn("--require-hashes", command)
            self.assertIn("--no-deps", command)
            self.assertIn("--only-binary", command)
            self.assertIn("[ok] demo 1.0", stdout.getvalue())
            self.assertIn(
                "Installed packages from the verified local wheelhouse",
                stdout.getvalue(),
            )

            lock_payload = json.loads(lock.read_text(encoding="utf-8"))
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            attestation_payload = json.loads(attestation.read_text(encoding="utf-8"))
            self.assertEqual(lock_payload["schema"], "urn:trustcheck:install-lock:1.0.0")
            self.assertEqual(report_payload["status"], "installed")
            self.assertTrue(report_payload["installed"])
            self.assertEqual(
                report_payload["packages"][0]["install_artifact"]["observed_sha256"],
                WHEEL_DIGEST,
            )
            self.assertEqual(
                attestation_payload["subject"][0]["digest"]["sha256"],
                WHEEL_DIGEST,
            )

    def test_provenance_policy_failure_stops_before_download_or_install(self) -> None:
        stdout = io.StringIO()
        fake_client = FakeDownloadClient()
        target = make_target()

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            report_path = root / "report.json"
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch("trustcheck.cli._client_for_target", return_value=fake_client),
                patch("trustcheck.cli.inspect_package", return_value=make_report(verified=False)),
                patch("trustcheck.cli_commands.install.subprocess.run") as pip_run,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "install",
                        "-r",
                        "requirements.txt",
                        "--require-provenance",
                        "--lock",
                        str(root / "lock.json"),
                        "--report",
                        str(report_path),
                        "--attestation",
                        str(root / "attestation.json"),
                    ]
                )

            self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
            self.assertEqual(fake_client.downloads, [])
            pip_run.assert_not_called()
            rendered = stdout.getvalue()
            self.assertIn("[blocked] demo 1.0", rendered)
            self.assertIn("Policy requires verified provenance", rendered)
            self.assertIn("No packages were installed.", rendered)
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report_payload["status"], "blocked")
            self.assertFalse(report_payload["installed"])

    def test_validate_args_rejects_unsafe_install_targets_and_outputs(self) -> None:
        class RaisingParser(argparse.ArgumentParser):
            def error(self, message: str) -> None:
                raise ValueError(message)

        parser = RaisingParser()
        cases = [
            (
                install_args(requirements=["demo==1"]),
                "either PACKAGE... or -r/--requirement",
            ),
            (
                install_args(requirement_file=None),
                "requires PACKAGE... or -r/--requirement",
            ),
            (
                install_args(python_version="3.13"),
                "targets the current interpreter",
            ),
            (
                install_args(report="trustcheck.lock"),
                "must be distinct paths",
            ),
            (
                install_args(requirement_file="trustcheck.lock"),
                "must not overwrite the input file",
            ),
        ]

        for args, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                install_command.validate_args(args, parser)

    def test_inspect_plan_maps_target_and_upstream_failures(self) -> None:
        cli = FakeInstallCli()
        targets = [
            ScanTarget(
                requirement="broken==1",
                project="broken",
                failure_message="resolver failed",
                failure_exit_code=3,
            ),
            ScanTarget(requirement="unresolved", project="unresolved"),
            ScanTarget(requirement="upstream==1", project="upstream", version="1"),
            ScanTarget(requirement="invalid==1", project="invalid", version="1"),
            ScanTarget(requirement="blocked==1", project="blocked", version="1"),
        ]

        plans, exit_code = install_command._inspect_install_plan(
            install_args(),
            cli=cli,
            targets=targets,
            client=FakeDownloadClient(),
            policy=PolicySettings(),
            resolver=object(),
            vulnerability_client=None,
            plugin_manager=None,
        )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        failures = {plan.target.project: plan.failures for plan in plans}
        self.assertEqual(failures["broken"], ["resolver failed"])
        self.assertIn("exact version", failures["unresolved"][0])
        self.assertIn("upstream: registry unavailable", failures["upstream"][0])
        self.assertIn("invalid response", failures["invalid"][0])
        self.assertEqual(plans[-1].evaluation.violations[0].message, "policy blocked package")

    def test_select_install_artifacts_reports_all_rejection_reasons(self) -> None:
        plans = [
            install_plan(),
            install_plan(report=make_report(), failures=["already blocked"]),
            install_plan(report=report_with_files([])),
            install_plan(
                report=report_with_files(
                    [
                        file_provenance(WHEEL_FILENAME),
                        file_provenance("demo-1.0.tar.gz"),
                    ]
                )
            ),
            install_plan(report=report_with_files([file_provenance("", url="")])),
            install_plan(report=report_with_files([file_provenance("demo.exe")])),
            install_plan(report=report_with_files([file_provenance("demo-1.0.tar.gz")])),
            install_plan(
                report=report_with_files(
                    [file_provenance(WHEEL_FILENAME, url="")]
                )
            ),
            install_plan(
                report=report_with_files(
                    [file_provenance("", url=f"https://files.example/{WHEEL_FILENAME}")]
                )
            ),
        ]

        install_command._select_install_artifacts(plans, allow_sdist=False)

        self.assertIsNone(plans[0].artifact)
        self.assertIn("already blocked", plans[1].failures)
        self.assertIn("no target-compatible artifact", plans[2].failures[0])
        self.assertIn("expected exactly one", plans[3].failures[0])
        self.assertIn("no filename", plans[4].failures[0])
        self.assertIn("only wheels", plans[5].failures[0])
        self.assertIn("source distributions are disabled", plans[6].failures[0])
        self.assertIn("has no URL", plans[7].failures[0])
        self.assertEqual(plans[8].artifact.filename, WHEEL_FILENAME)

        sdist = install_plan(
            report=report_with_files([file_provenance("demo-1.0.tar.gz")])
        )
        install_command._select_install_artifacts([sdist], allow_sdist=True)
        self.assertEqual(sdist.artifact.filename, "demo-1.0.tar.gz")

    def test_materialize_verified_wheelhouse_covers_hash_and_write_failures(self) -> None:
        class DownloadClient(FakeDownloadClient):
            def __init__(self, payload: bytes = WHEEL_BYTES, fail: bool = False) -> None:
                super().__init__()
                self.payload = payload
                self.fail = fail

            def download_distribution(self, url: str) -> bytes:
                if self.fail:
                    raise PypiClientError("download failed")
                self.downloads.append(url)
                return self.payload

        cli = FakeInstallCli()
        args = install_args()
        with tempfile.TemporaryDirectory() as tempdir:
            wheelhouse = Path(tempdir) / "wheelhouse"

            upstream = install_plan(
                artifact=install_command.InstallArtifact(WHEEL_FILENAME, WHEEL_URL)
            )
            exit_code = install_command._materialize_verified_wheelhouse(
                [upstream],
                wheelhouse,
                args=args,
                cli=cli,
                client=DownloadClient(fail=True),
                plugin_manager=None,
            )
            self.assertNotEqual(exit_code, EXIT_OK)
            self.assertIn("download failed", upstream.failures[0])

            wrong_digest = install_plan(
                artifact=install_command.InstallArtifact(
                    WHEEL_FILENAME,
                    WHEEL_URL,
                    sha256="0" * 64,
                )
            )
            install_command._materialize_verified_wheelhouse(
                [wrong_digest],
                wheelhouse,
                args=args,
                cli=cli,
                client=DownloadClient(),
                plugin_manager=None,
            )
            self.assertIn("expected sha256", wrong_digest.failures[0])

            target_mismatch = install_plan(
                artifact=install_command.InstallArtifact(WHEEL_FILENAME, WHEEL_URL)
            )
            install_command._materialize_verified_wheelhouse(
                [target_mismatch],
                wheelhouse,
                args=args,
                cli=cli,
                client=DownloadClient(b"different bytes"),
                plugin_manager=None,
            )
            self.assertIn("resolver-selected hash", target_mismatch.failures[0])

            collision = install_plan(
                target=ScanTarget(
                    requirement="demo==1.0",
                    project="demo",
                    version="1.0",
                    artifacts=(
                        ArtifactReference(
                            filename=WHEEL_FILENAME,
                            url=WHEEL_URL,
                            hashes=(),
                        ),
                    ),
                ),
                artifact=install_command.InstallArtifact(WHEEL_FILENAME, WHEEL_URL),
            )
            wheelhouse.mkdir(exist_ok=True)
            (wheelhouse / WHEEL_FILENAME).write_bytes(b"other")
            install_command._materialize_verified_wheelhouse(
                [collision],
                wheelhouse,
                args=args,
                cli=cli,
                client=DownloadClient(),
                plugin_manager=None,
            )
            self.assertIn("filename collision", collision.failures[0])

            write_failure = install_plan(
                target=collision.target,
                artifact=install_command.InstallArtifact("other.whl", WHEEL_URL),
            )
            with patch(
                "trustcheck.cli_commands.install._atomic_write_bytes",
                side_effect=OSError("disk full"),
            ):
                install_command._materialize_verified_wheelhouse(
                    [write_failure],
                    wheelhouse,
                    args=args,
                    cli=cli,
                    client=DownloadClient(),
                    plugin_manager=None,
                )
            self.assertIn("disk full", write_failure.failures[0])

            success = install_plan(
                artifact=install_command.InstallArtifact(WHEEL_FILENAME, WHEEL_URL)
            )
            empty = install_plan()
            (wheelhouse / WHEEL_FILENAME).write_bytes(WHEEL_BYTES)
            exit_code = install_command._materialize_verified_wheelhouse(
                [empty, success],
                wheelhouse,
                args=args,
                cli=cli,
                client=DownloadClient(),
                plugin_manager=None,
            )
            self.assertEqual(exit_code, EXIT_OK)
            self.assertEqual(success.artifact.observed_sha256, WHEEL_DIGEST)
            self.assertEqual(success.artifact.size, len(WHEEL_BYTES))

    def test_install_helpers_render_and_emit_edge_cases(self) -> None:
        cli = FakeInstallCli()
        verified_plan = install_plan(
            report=make_report(),
            artifact=install_command.InstallArtifact(
                WHEEL_FILENAME,
                "https://user:pass@example.test/demo.whl",
                observed_sha256=WHEEL_DIGEST,
            ),
            evaluation=PolicyEvaluation(passed=True),
        )
        blocked_plan = install_plan(
            evaluation=PolicyEvaluation(
                passed=False,
                violations=[
                    PolicyViolation("rule", "high", "blocked by policy"),
                ],
            )
        )
        payload = {
            "status": "install-failed",
            "install_error": "pip exited with status 2",
            "evidence": {"lock": "lock.json", "report": "report.json", "attestation": "att.json"},
        }

        rendered = install_command._render_install_text(
            payload,
            [verified_plan, blocked_plan],
        )

        self.assertIn("provenance verified", rendered)
        self.assertIn("hash verified", rendered)
        self.assertIn("policy passed", rendered)
        self.assertIn("blocked by policy", rendered)
        self.assertIn("pip install failed after verification", rendered)
        self.assertIn("Evidence written: lock.json, report.json, att.json", rendered)
        self.assertIn(
            "Dry run: no packages were installed.",
            install_command._render_install_text({"status": "verified"}, []),
        )
        self.assertIn(
            "No packages were installed.",
            install_command._render_install_text({"status": "blocked"}, []),
        )

        install_command._emit_install_result(
            install_args(format="json", output_file="out.json"),
            cli=cli,
            payload={"status": "verified", "value": 1},
            plans=[],
        )
        self.assertEqual(cli.outputs[0][1], "out.json")
        self.assertIn('"value": 1', cli.outputs[0][0])

        self.assertIsNone(install_command._artifact_payload(None))
        self.assertIsNone(install_command._redact(None))
        self.assertEqual(
            install_command._source_payload(
                install_args(requirement_file=None, requirements=["demo==1"]),
                "command line requirements",
            )["requirements"],
            ["demo==1"],
        )
        self.assertEqual(
            install_command._merge_plan_exit_code(cli, EXIT_OK, EXIT_POLICY_FAILURE),
            EXIT_POLICY_FAILURE,
        )
        self.assertEqual(
            install_command._merge_plan_exit_code(cli, EXIT_POLICY_FAILURE, EXIT_OK),
            EXIT_POLICY_FAILURE,
        )
        self.assertEqual(
            install_command._merge_plan_exit_code(cli, 1, EXIT_POLICY_FAILURE),
            EXIT_POLICY_FAILURE,
        )

    def test_write_requirements_and_subprocess_failures_are_reported(self) -> None:
        verified = install_plan(
            artifact=install_command.InstallArtifact(
                WHEEL_FILENAME,
                WHEEL_URL,
                observed_sha256=WHEEL_DIGEST,
            )
        )
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            output = root / "resolved.txt"
            install_command._write_resolved_requirements(output, [verified])
            self.assertIn(f"--hash=sha256:{WHEEL_DIGEST}", output.read_text(encoding="utf-8"))

            with self.assertRaisesRegex(ValueError, "missing verified bytes"):
                install_command._write_resolved_requirements(
                    root / "broken.txt",
                    [install_plan()],
                )

            command = install_command._pip_install_command(
                root / "wheelhouse",
                output,
                allow_sdist=True,
            )
            self.assertNotIn("--only-binary", command)

            with patch(
                "trustcheck.cli_commands.install.subprocess.run",
                side_effect=OSError("no executable"),
            ):
                completed = install_command._run_pip_install(["python", "-m", "pip"])
            self.assertEqual(completed.returncode, 1)
            self.assertIn("no executable", completed.stderr)

            with patch(
                "trustcheck.cli_commands.install.os.replace",
                side_effect=OSError("replace failed"),
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    install_command._atomic_write_bytes(root / "atomic.txt", b"data")
            with (
                patch(
                    "trustcheck.cli_commands.install.os.replace",
                    side_effect=OSError("replace failed"),
                ),
                patch(
                    "trustcheck.cli_commands.install.os.unlink",
                    side_effect=OSError("cleanup failed"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    install_command._atomic_write_bytes(
                        root / "atomic-cleanup.txt",
                        b"data",
                    )

    def test_load_install_targets_uses_direct_requirements_resolver(self) -> None:
        class Resolver:
            def resolve_requirements(self, requirements, **kwargs):
                self.requirements = requirements
                self.kwargs = kwargs
                return SimpleNamespace()

        cli = FakeInstallCli()
        resolver = Resolver()
        client = FakeDownloadClient()
        source, targets = install_command._load_install_targets(
            install_args(requirement_file=None, requirements=["demo==1.0"]),
            cli=cli,
            client=client,
            resolver=resolver,
        )

        self.assertEqual(source, "command line requirements")
        self.assertEqual(targets[0].project, "demo")
        self.assertEqual(resolver.requirements, ["demo==1.0"])
        self.assertFalse(resolver.kwargs["offline"])

    def test_dry_run_and_pip_failure_paths_stop_after_verification(self) -> None:
        target = make_target()
        for pip_result, args, expected_text, expected_exit in (
            (
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                [
                    "install",
                    "-r",
                    "requirements.txt",
                    "--dry-run",
                ],
                "Dry run: no packages were installed.",
                EXIT_OK,
            ),
            (
                subprocess.CompletedProcess(args=[], returncode=17, stdout="", stderr=""),
                [
                    "install",
                    "-r",
                    "requirements.txt",
                ],
                "pip exited with status 17",
                1,
            ),
        ):
            with self.subTest(expected_text=expected_text):
                stdout = io.StringIO()
                with tempfile.TemporaryDirectory() as tempdir:
                    root = Path(tempdir)
                    command_args = [
                        *args,
                        "--lock",
                        str(root / "trustcheck.lock"),
                        "--report",
                        str(root / "report.json"),
                        "--attestation",
                        str(root / "attestation.json"),
                    ]
                    with (
                        patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                        patch(
                            "trustcheck.cli._client_for_target",
                            return_value=FakeDownloadClient(),
                        ),
                        patch("trustcheck.cli.inspect_package", return_value=make_report()),
                        patch(
                            "trustcheck.cli_commands.install.subprocess.run",
                            return_value=pip_result,
                        ) as pip_run,
                        redirect_stdout(stdout),
                        redirect_stderr(io.StringIO()),
                    ):
                        exit_code = main(command_args)

                self.assertEqual(exit_code, expected_exit)
                self.assertIn(expected_text, stdout.getvalue())
                if "--dry-run" in args:
                    pip_run.assert_not_called()

    def test_download_hash_failure_flushes_vulnerability_cache_and_blocks_install(self) -> None:
        class BadDownloadClient(FakeDownloadClient):
            def download_distribution(self, url: str) -> bytes:
                self.downloads.append(url)
                return b"tampered wheel bytes"

        class VulnerabilityClient:
            def __init__(self) -> None:
                self.flushed = False

            def flush_snapshots(self) -> None:
                self.flushed = True

        stdout = io.StringIO()
        target = make_target()
        bad_client = BadDownloadClient()
        vulnerability_client = VulnerabilityClient()

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            with (
                patch("trustcheck.cli._load_scan_targets", return_value=[target]),
                patch("trustcheck.cli._client_for_target", return_value=bad_client),
                patch(
                    "trustcheck.cli._build_vulnerability_client",
                    return_value=vulnerability_client,
                ),
                patch("trustcheck.cli.inspect_package", return_value=make_report()),
                patch("trustcheck.cli_commands.install.subprocess.run") as pip_run,
                redirect_stdout(stdout),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "install",
                        "-r",
                        "requirements.txt",
                        "--lock",
                        str(root / "trustcheck.lock"),
                        "--report",
                        str(root / "report.json"),
                        "--attestation",
                        str(root / "attestation.json"),
                    ]
                )

        self.assertEqual(exit_code, EXIT_POLICY_FAILURE)
        self.assertTrue(vulnerability_client.flushed)
        self.assertEqual(bad_client.downloads, [WHEEL_URL])
        pip_run.assert_not_called()
        rendered = stdout.getvalue()
        self.assertIn("hash verification failed", rendered)
        self.assertIn("No packages were installed.", rendered)


if __name__ == "__main__":
    unittest.main()
