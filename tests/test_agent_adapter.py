from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import textwrap
import time
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "trustcheck-gate"
ADAPTER_IN_ARCHIVE = Path(
    "trustcheck-gate/skills/trustcheck-gate/scripts/trustcheck_agent_adapter.py"
)


@contextmanager
def _working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _build_plugin_archive(target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(PLUGIN_ROOT.rglob("*")):
            if path.is_file():
                archive.write(path, Path("trustcheck-gate") / path.relative_to(PLUGIN_ROOT))


def _load_adapter(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("trustcheck_agent_adapter_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _adapter_environment(bin_dir: Path) -> dict[str, str]:
    env = {
        "PATH": str(bin_dir),
        "PYTHONIOENCODING": "utf-8",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _write_fake_trustcheck(bin_dir: Path, *, version: str = "2.2.0") -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "fake_trustcheck.py"
    script.write_text(
        textwrap.dedent(
            f"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:] == ["--version"]:
    print("trustcheck {version} (report schema 1.11.0)")
    raise SystemExit(0)

args = sys.argv[1:]
output_format = "json"
if "--format" in args:
    output_format = args[args.index("--format") + 1]
if output_format != "json":
    print(f"fake {{output_format}} report from {{os.getcwd()}}")
    raise SystemExit(0)

project = "demo"
scenario = "pass"
if "-f" in args:
    source = Path(args[args.index("-f") + 1])
    project = source.name
    try:
        first_line = source.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError):
        first_line = ""
    if first_line.startswith("# scenario:"):
        scenario = first_line.split(":", 1)[1].strip()
elif len(args) > 1 and not args[1].startswith("-"):
    project = args[1]
if project.startswith("case-"):
    scenario = project.removeprefix("case-")

payload = {{
    "schema_version": "1.11.0",
    "reports": [
        {{
            "project": project,
            "version": "1.0",
            "recommendation": "verified",
            "policy": {{"passed": True, "violations": []}},
            "coverage": {{"status": "verified", "verified_files": 1, "total_files": 1}},
            "vulnerabilities": [],
            "risk_flags": [],
            "malicious_package": {{"findings": []}},
            "diagnostics": {{"cwd": os.getcwd(), "argv": args}},
        }}
    ],
    "failures": [],
}}
if scenario == "malformed":
    print("{{not-json")
    raise SystemExit(0)
if scenario == "empty":
    raise SystemExit(0)
if scenario == "array":
    print("[]")
    raise SystemExit(0)
if scenario == "empty_object":
    print("{{}}")
    raise SystemExit(0)
if scenario == "unknown_schema":
    payload["schema_version"] = "9.0.0"
if scenario == "missing_policy":
    del payload["reports"][0]["policy"]
if scenario == "contradictory_findings":
    payload["reports"][0]["vulnerabilities"] = [
        {{
            "id": "PYSEC-1",
            "summary": "known issue",
            "severity": "HIGH",
            "fixed_in": ["1.1"],
        }}
    ]
if scenario == "explicit_block":
    payload["reports"][0]["policy"] = {{
        "passed": False,
        "violations": [
            {{"code": "blocked", "severity": "high", "message": "blocked by policy"}}
        ],
    }}
if scenario == "nonzero_clean":
    print(json.dumps(payload))
    raise SystemExit(4)
if scenario == "partial_json":
    print('{{"schema_version": "1.11.0", "reports": [')
    raise SystemExit(0)
if scenario == "timeout":
    time.sleep(10)
    raise SystemExit(0)
if scenario == "output_limit":
    sys.stdout.write("x" * 20000)
    raise SystemExit(0)
if scenario == "stderr_limit":
    sys.stderr.write("x" * 20000)
    raise SystemExit(0)
if scenario == "stderr_secret":
    print(
        "Authorization: Bearer abc.def "
        "PIP_INDEX_URL=https://user:pass@example.com/simple?token=secret&ok=1",
        file=sys.stderr,
    )
    print(json.dumps(payload))
    raise SystemExit(4)
if scenario == "env_dump":
    payload["reports"][0]["diagnostics"]["env"] = {{
        key: os.environ.get(key)
        for key in [
            "PATH",
            "SECRET_TOKEN",
            "PIP_INDEX_URL",
            "HTTPS_PROXY",
            "TRUSTCHECK_FAKE_SCENARIO",
        ]
    }}
if scenario == "slow_valid":
    time.sleep(0.75)
if scenario == "child_process":
    subprocess.Popen([
        sys.executable,
        "-c",
        (
            "import pathlib,time;"
            "time.sleep(2);"
            "pathlib.Path('child-marker.txt').write_text('alive', encoding='utf-8')"
        ),
    ])
    time.sleep(10)
print(json.dumps(payload))
"""
        ).lstrip(),
        encoding="utf-8",
    )
    if os.name == "nt":
        launcher = bin_dir / "trustcheck.cmd"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n',
            encoding="utf-8",
        )
        return launcher

    launcher = bin_dir / "trustcheck"
    launcher.write_text(
        f"#!{sys.executable}\n"
        "from pathlib import Path\n"
        "import runpy\n"
        f"runpy.run_path(str(Path({str(script)!r})), run_name='__main__')\n",
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)
    return launcher


def _run_adapter(
    adapter: Path,
    request: dict[str, object],
    *,
    cwd: Path,
    env: dict[str, str],
) -> tuple[int, dict[str, object]]:
    completed = subprocess.run(
        [sys.executable, str(adapter)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=False,
        cwd=str(cwd),
        env=env,
        timeout=30,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - assertion detail
        raise AssertionError(completed.stdout + completed.stderr) from exc
    assert isinstance(payload, dict)
    return completed.returncode, payload


class TrustcheckGateAdapterTests(unittest.TestCase):
    def test_extracted_plugin_runs_supported_operations_from_cwd(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()
            (project / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
            env = _adapter_environment(bin_dir)

            operations: list[dict[str, object]] = [
                {"operation": "check_package", "package": "demo", "version": "1.0"},
                {
                    "operation": "verify_release",
                    "package": "demo",
                    "version": "1.0",
                    "expected_repository": "https://github.com/example/demo",
                    "release_tag": "v1.0.0",
                },
                {"operation": "check_requirements", "path": "requirements.txt"},
                {"operation": "scan_project"},
                {"operation": "plan_remediation", "path": "requirements.txt"},
                {
                    "operation": "compare_versions",
                    "package": "demo",
                    "current_version": "1.0",
                    "proposed_version": "1.1",
                },
                {
                    "operation": "generate_report",
                    "target_type": "package",
                    "package": "demo",
                    "format": "json",
                },
                {
                    "operation": "explain_findings",
                    "report": {
                        "schema_version": "1.11.0",
                        "reports": [
                            {
                                "project": "demo",
                                "version": "1.0",
                                "recommendation": "verified",
                                "policy": {"passed": True, "violations": []},
                                "coverage": {"status": "verified"},
                                "vulnerabilities": [],
                                "risk_flags": [],
                                "malicious_package": {"findings": []},
                            }
                        ],
                    },
                },
            ]

            for request in operations:
                with self.subTest(operation=request["operation"]):
                    exit_code, payload = _run_adapter(
                        adapter,
                        request,
                        cwd=project,
                        env=env,
                    )
                self.assertEqual(exit_code, 0, payload)
                self.assertEqual(payload["classification"], "passed")
                self.assertTrue(payload["policy_permits_install"])
                self.assertEqual(payload["execution_status"], "completed")
                self.assertEqual(payload["report_status"], "valid")
                self.assertEqual(payload["security_status"], "passed")
                if request["operation"] != "explain_findings":
                    self.assertEqual(payload.get("trustcheck_version"), "2.2.0")
                    self.assertEqual(payload.get("trustcheck_command_source"), "path")
                    if "command" in payload:
                        self.assertNotIn(
                            str(ROOT / "src"),
                            os.pathsep.join(payload["command"]),
                        )
                    for report in payload.get("reports", []):
                        self.assertNotIn(
                            str(ROOT / "src"),
                            os.pathsep.join(report.get("command", [])),
                        )
                    for side in ("current", "proposed"):
                        child = payload.get(side, {})
                        if isinstance(child, dict):
                            self.assertNotIn(
                                str(ROOT / "src"),
                                os.pathsep.join(child.get("command", [])),
                            )

            _, scan_project = _run_adapter(
                adapter,
                {"operation": "scan_project"},
                cwd=project,
                env=env,
            )
            self.assertEqual(scan_project["workspace"], str(project.resolve()))
            self.assertEqual(
                scan_project["dependency_files"],
                [str((project / "requirements.txt").resolve())],
            )

    def test_plugin_archive_includes_parseable_adapter_schemas(self) -> None:
        schema_names = {
            "adapter-request-0.1.json",
            "adapter-result-0.1.json",
            "accepted-trustcheck-report-1.11.0.json",
        }
        for schema_name in schema_names:
            schema_path = PLUGIN_ROOT / "schemas" / schema_name
            with self.subTest(schema=schema_name):
                self.assertTrue(schema_path.exists())
                json.loads(schema_path.read_text(encoding="utf-8"))

        with TemporaryDirectory() as directory:
            archive = Path(directory) / "trustcheck-gate.zip"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                archive_names = set(plugin.namelist())

        for schema_name in schema_names:
            self.assertIn(
                f"trustcheck-gate/schemas/{schema_name}",
                archive_names,
            )

    def test_workspace_argument_expands_and_must_be_existing_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = _load_adapter(
                PLUGIN_ROOT
                / "skills"
                / "trustcheck-gate"
                / "scripts"
                / "trustcheck_agent_adapter.py"
            )
            workspace = root / "workspace"
            workspace.mkdir()
            with _working_directory(root):
                self.assertEqual(adapter._workspace("workspace"), workspace.resolve())
                with self.assertRaisesRegex(adapter.AdapterError, "workspace does not exist"):
                    adapter._workspace("missing")
                with self.assertRaisesRegex(adapter.AdapterError, "non-empty path"):
                    adapter._workspace("")

    def test_command_discovery_supports_path_and_python_module_fallback(self) -> None:
        adapter = _load_adapter(
            PLUGIN_ROOT
            / "skills"
            / "trustcheck-gate"
            / "scripts"
            / "trustcheck_agent_adapter.py"
        )
        with patch.object(adapter, "which", return_value="/tools/trustcheck"):
            self.assertEqual(
                adapter._discover_trustcheck_command(),
                (("/tools/trustcheck",), "path"),
            )

        with patch.object(adapter, "which", return_value=None), patch.object(
            adapter.importlib.util,
            "find_spec",
            return_value=object(),
        ):
            self.assertEqual(
                adapter._discover_trustcheck_command(),
                ((sys.executable, "-m", "trustcheck"), "python-module"),
            )

    def test_runtime_resolution_accepts_python_module_fallback(self) -> None:
        adapter = _load_adapter(
            PLUGIN_ROOT
            / "skills"
            / "trustcheck-gate"
            / "scripts"
            / "trustcheck_agent_adapter.py"
        )
        completed = subprocess.CompletedProcess(
            args=[sys.executable, "-m", "trustcheck", "--version"],
            returncode=0,
            stdout=b"trustcheck 2.2.3.post1.dev1 (report schema 1.11.0)\n",
            stderr=b"",
        )
        with patch.object(
            adapter,
            "_discover_trustcheck_command",
            return_value=((sys.executable, "-m", "trustcheck"), "python-module"),
        ), patch.object(adapter.subprocess, "run", return_value=completed):
            runtime = adapter._resolve_trustcheck_runtime(timeout=1)

        self.assertEqual(runtime.command_prefix, (sys.executable, "-m", "trustcheck"))
        self.assertEqual(runtime.source, "python-module")
        self.assertEqual(runtime.version, "2.2.3.post1.dev1")

    def test_missing_trustcheck_returns_structured_scan_failure(self) -> None:
        with TemporaryDirectory() as directory:
            project = Path(directory)
            adapter = _load_adapter(
                PLUGIN_ROOT
                / "skills"
                / "trustcheck-gate"
                / "scripts"
                / "trustcheck_agent_adapter.py"
            )
            with _working_directory(project), patch.object(
                adapter,
                "_discover_trustcheck_command",
                return_value=None,
            ):
                result = adapter.run_operation(
                    {"operation": "check_package", "package": "demo"}
                )

        self.assertEqual(result["classification"], "scan_failed")
        self.assertFalse(result["policy_permits_install"])
        self.assertIn("trustcheck executable was not found", " ".join(result["errors"]))
        self.assertIsNone(result["trustcheck_version"])
        self.assertEqual(result["execution_status"], "failed_to_start")
        self.assertEqual(result["report_status"], "missing")
        self.assertEqual(result["security_status"], "scan_failed")

    def test_unsupported_trustcheck_version_blocks_scan(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir, version="1.9.0")
            project.mkdir()

            exit_code, payload = _run_adapter(
                adapter,
                {"operation": "check_package", "package": "demo"},
                cwd=project,
                env=_adapter_environment(bin_dir),
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["classification"], "scan_failed")
        self.assertFalse(payload["policy_permits_install"])
        self.assertIn("supports trustcheck >=2.2,<3.0", " ".join(payload["errors"]))
        self.assertEqual(payload["execution_status"], "failed_to_start")
        self.assertEqual(payload["security_status"], "scan_failed")

    def test_extracted_plugin_fails_closed_for_ambiguous_trustcheck_results(self) -> None:
        cases = {
            "malformed": ("completed", "malformed", "scan_failed", "scan_failed"),
            "empty": ("completed", "missing", "scan_failed", "scan_failed"),
            "array": ("completed", "malformed", "scan_failed", "scan_failed"),
            "empty_object": ("completed", "invalid_schema", "scan_failed", "scan_failed"),
            "unknown_schema": ("completed", "incompatible", "scan_failed", "scan_failed"),
            "missing_policy": ("completed", "invalid_schema", "scan_failed", "scan_failed"),
            "contradictory_findings": (
                "completed",
                "valid",
                "findings",
                "security_findings",
            ),
            "partial_json": ("completed", "malformed", "scan_failed", "scan_failed"),
            "explicit_block": ("completed", "valid", "blocked", "security_findings"),
            "nonzero_clean": ("completed", "valid", "scan_failed", "scan_failed"),
            "timeout": ("timed_out", "missing", "scan_failed", "scan_failed"),
            "output_limit": (
                "output_limit_exceeded",
                "malformed",
                "scan_failed",
                "scan_failed",
            ),
            "stderr_limit": (
                "output_limit_exceeded",
                "malformed",
                "scan_failed",
                "scan_failed",
            ),
        }

        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()
            base_env = _adapter_environment(bin_dir)

            for scenario, expected in cases.items():
                with self.subTest(scenario=scenario):
                    request: dict[str, object] = {
                        "operation": "check_package",
                        "package": f"case-{scenario}",
                        "version": "1.0",
                    }
                    if scenario == "timeout":
                        request["timeout_seconds"] = 1
                    if scenario in {"output_limit", "stderr_limit"}:
                        request["max_output_bytes"] = 10000

                    exit_code, payload = _run_adapter(
                        adapter,
                        request,
                        cwd=project,
                        env=base_env,
                    )

                execution_status, report_status, security_status, classification = expected
                self.assertEqual(exit_code, 4 if classification == "security_findings" else 1)
                self.assertEqual(payload["classification"], classification)
                self.assertFalse(payload["policy_permits_install"])
                self.assertEqual(payload["execution_status"], execution_status)
                self.assertEqual(payload["report_status"], report_status)
                self.assertEqual(payload["security_status"], security_status)
                if report_status != "valid":
                    self.assertTrue(payload["errors"], payload)

    def test_valid_report_with_explicit_pass_is_required_for_explanations(self) -> None:
        adapter = _load_adapter(
            PLUGIN_ROOT
            / "skills"
            / "trustcheck-gate"
            / "scripts"
            / "trustcheck_agent_adapter.py"
        )

        blocked = adapter.run_operation({"operation": "explain_findings", "report": {}})

        self.assertEqual(blocked["classification"], "scan_failed")
        self.assertFalse(blocked["policy_permits_install"])
        self.assertEqual(blocked["report_status"], "invalid_schema")
        self.assertEqual(blocked["security_status"], "scan_failed")

    def test_non_json_report_generation_never_permits_install(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()

            exit_code, payload = _run_adapter(
                adapter,
                {
                    "operation": "generate_report",
                    "target_type": "package",
                    "package": "demo",
                    "format": "markdown",
                },
                cwd=project,
                env=_adapter_environment(bin_dir),
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["classification"], "scan_failed")
        self.assertFalse(payload["policy_permits_install"])
        self.assertEqual(payload["security_status"], "unknown")
        self.assertIn("non-JSON reports", " ".join(payload["errors"]))

    def test_request_schema_rejects_unsupported_and_mutating_fields(self) -> None:
        adapter = _load_adapter(
            PLUGIN_ROOT
            / "skills"
            / "trustcheck-gate"
            / "scripts"
            / "trustcheck_agent_adapter.py"
        )
        with self.assertRaisesRegex(adapter.AdapterError, "dynamic_analysis"):
            adapter.run_operation(
                {
                    "operation": "check_package",
                    "package": "demo",
                    "dynamic_analysis": True,
                }
            )
        with self.assertRaisesRegex(adapter.AdapterError, "enable_plugins"):
            adapter.run_operation(
                {
                    "operation": "check_package",
                    "package": "demo",
                    "enable_plugins": True,
                }
            )
        with self.assertRaisesRegex(adapter.AdapterError, "unexpected"):
            adapter.run_operation(
                {
                    "operation": "check_package",
                    "package": "demo",
                    "surprise": "nope",
                }
            )
        with self.assertRaisesRegex(adapter.AdapterError, "unexpected"):
            adapter.run_operation(
                {
                    "operation": "check_package",
                    "packages": ["demo", "other", "third"],
                }
            )
        with self.assertRaisesRegex(adapter.AdapterError, "max_files"):
            adapter.run_operation(
                {
                    "operation": "scan_project",
                    "max_files": adapter.MAX_PROJECT_FILES + 1,
                }
            )

    def test_request_loader_rejects_excessive_stdin_size(self) -> None:
        adapter = _load_adapter(
            PLUGIN_ROOT
            / "skills"
            / "trustcheck-gate"
            / "scripts"
            / "trustcheck_agent_adapter.py"
        )
        huge = " " * (adapter.MAX_REQUEST_BYTES + 1)
        with patch.object(adapter.sys, "stdin", io.StringIO(huge)):
            with self.assertRaisesRegex(adapter.AdapterError, "maximum size"):
                adapter._load_request(None)

    def test_url_and_path_validators_reject_abuse(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = _load_adapter(
                PLUGIN_ROOT
                / "skills"
                / "trustcheck-gate"
                / "scripts"
                / "trustcheck_agent_adapter.py"
            )
            workspace = root / "workspace"
            outside = root / "outside.txt"
            workspace.mkdir()
            outside.write_text("demo==1.0\n", encoding="utf-8")
            with _working_directory(workspace):
                with self.assertRaisesRegex(adapter.AdapterError, "credentials"):
                    adapter.run_operation(
                        {
                            "operation": "verify_release",
                            "package": "demo",
                            "expected_repository": "https://user:pass@example.com/repo",
                        }
                    )
                with self.assertRaisesRegex(adapter.AdapterError, "query"):
                    adapter.run_operation(
                        {
                            "operation": "verify_release",
                            "package": "demo",
                            "expected_repository": "https://example.com/repo?token=abc",
                        }
                    )
                with self.assertRaisesRegex(adapter.AdapterError, "outside workspace"):
                    adapter.run_operation(
                        {
                            "operation": "check_requirements",
                            "path": str(outside),
                        }
                    )

    def test_sanitized_environment_and_structural_redaction(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()
            env = _adapter_environment(bin_dir) | {
                "SECRET_TOKEN": "super-secret",
                "PIP_INDEX_URL": "https://user:pass@example.com/simple",
                "HTTPS_PROXY": "https://proxy-user:proxy-pass@example.com",
                "TRUSTCHECK_FAKE_SCENARIO": "should-not-leak",
            }

            exit_code, payload = _run_adapter(
                adapter,
                {
                    "operation": "check_package",
                    "package": "case-env_dump",
                    "version": "1.0",
                },
                cwd=project,
                env=env,
            )

            self.assertEqual(exit_code, 0, payload)
            diagnostics = payload["report"]["reports"][0]["diagnostics"]
            child_env = diagnostics["env"]
            self.assertIsNotNone(child_env["PATH"])
            self.assertIsNone(child_env["SECRET_TOKEN"])
            self.assertIsNone(child_env["PIP_INDEX_URL"])
            self.assertIsNone(child_env["HTTPS_PROXY"])
            self.assertIsNone(child_env["TRUSTCHECK_FAKE_SCENARIO"])

            exit_code, payload = _run_adapter(
                adapter,
                {
                    "operation": "check_package",
                    "package": "case-stderr_secret",
                    "version": "1.0",
                },
                cwd=project,
                env=env,
            )

            self.assertEqual(exit_code, 1, payload)
            stderr = payload["stderr"]
            self.assertNotIn("abc.def", stderr)
            self.assertNotIn("user:pass", stderr)
            self.assertNotIn("token=secret", stderr)
            self.assertIn("[REDACTED]", stderr)

    def test_timeout_terminates_spawned_child_process_tree(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()

            exit_code, payload = _run_adapter(
                adapter,
                {
                    "operation": "check_package",
                    "package": "case-child_process",
                    "timeout_seconds": 1,
                },
                cwd=project,
                env=_adapter_environment(bin_dir),
            )

            self.assertEqual(exit_code, 1, payload)
            self.assertEqual(payload["execution_status"], "timed_out")
            time.sleep(3)
            self.assertFalse((project / "child-marker.txt").exists())

    def test_scan_project_uses_one_total_deadline(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "trustcheck-gate.zip"
            extracted = root / "extracted"
            project = root / "project"
            bin_dir = root / "bin"
            _build_plugin_archive(archive)
            with zipfile.ZipFile(archive) as plugin:
                plugin.extractall(extracted)
            adapter = extracted / ADAPTER_IN_ARCHIVE
            _write_fake_trustcheck(bin_dir)
            project.mkdir()
            (project / "requirements.txt").write_text(
                "# scenario: slow_valid\ndemo==1.0\n",
                encoding="utf-8",
            )
            (project / "requirements.lock").write_text(
                "# scenario: slow_valid\ndemo==1.0\n",
                encoding="utf-8",
            )

            exit_code, payload = _run_adapter(
                adapter,
                {
                    "operation": "scan_project",
                    "timeout_seconds": 1,
                    "max_files": 2,
                },
                cwd=project,
                env=_adapter_environment(bin_dir),
            )

        self.assertEqual(exit_code, 1, payload)
        self.assertEqual(payload["classification"], "scan_failed")
        self.assertEqual(payload["execution_status"], "timed_out")
        self.assertTrue(
            any(report["execution_status"] == "timed_out" for report in payload["reports"])
        )


if __name__ == "__main__":
    unittest.main()
