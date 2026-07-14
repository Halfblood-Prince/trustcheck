from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any

from .models import (
    DynamicAnalysisEvidence,
    DynamicAnalysisPhase,
    DynamicAnalysisResult,
)

BOUNDED_INSTALL_ANALYSIS_MODE = "bounded-install-analysis"
SUPPORTED_DYNAMIC_PYTHONS = ("3.11", "3.12", "3.13", "3.14")
DEFAULT_DYNAMIC_PYTHON = "3.12"
DEFAULT_DYNAMIC_IMAGE: str | None = None
DYNAMIC_ANALYZER_IMAGES: dict[str, str] = {}
DIGEST_PINNED_IMAGE_PATTERN = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")
MAX_DYNAMIC_SECONDS = 30.0
MAX_DYNAMIC_CPU_SECONDS = 10
MAX_DYNAMIC_MEMORY = "512m"
MAX_DYNAMIC_OUTPUT_LINES = 25
RESULT_PREFIX = "TRUSTCHECK_DYNAMIC_RESULT="
# This private tmpfs must be executable because the disposable venv lives there.
CONTAINER_TEMPFS = "/tmp:rw,exec,nosuid,nodev,size=256m"  # nosec B108


def analyze_artifact_dynamic(
    filename: str,
    payload: bytes,
    *,
    image: str | None = None,
    python_version: str = DEFAULT_DYNAMIC_PYTHON,
    import_probe: bool = False,
    entry_point_probe: bool = False,
    timeout: float = MAX_DYNAMIC_SECONDS,
) -> DynamicAnalysisResult:
    selected_image = image or default_dynamic_image(python_version)
    result = _base_result(
        image=selected_image,
        python_version=python_version,
        timeout=timeout,
    )
    if python_version not in SUPPORTED_DYNAMIC_PYTHONS:
        _fail_before_execution(
            result,
            error=(
                "bounded install analysis supports Python "
                + ", ".join(SUPPORTED_DYNAMIC_PYTHONS)
            ),
            classification="unsupported",
            failure_type="unsupported_python",
        )
        return result
    if selected_image is None:
        _fail_before_execution(
            result,
            error=(
                "no digest-pinned bounded install analyzer image is configured for "
                f"Python {python_version}; provide --dynamic-image"
            ),
            classification="unsupported",
            failure_type="analyzer_image_unavailable",
        )
        return result
    if DIGEST_PINNED_IMAGE_PATTERN.fullmatch(selected_image) is None:
        _fail_before_execution(
            result,
            error=(
                "bounded install analysis image must be pinned by a full sha256 digest"
            ),
            classification="policy-blocked",
            failure_type="policy_blocked",
        )
        return result
    if shutil.which("docker") is None:
        _fail_before_execution(
            result,
            error="bounded install analysis requires the Docker CLI to be available",
            classification="unsupported",
            failure_type="container_runtime_unavailable",
        )
        return result

    artifact_name = Path(filename).name or "artifact"
    with tempfile.TemporaryDirectory(prefix="trustcheck-dynamic-") as directory:
        artifact_path = Path(directory) / artifact_name
        artifact_path.write_bytes(payload)
        try:
            artifact_path.parent.chmod(0o711)
            artifact_path.chmod(0o644)
        except OSError as exc:
            _fail_before_execution(
                result,
                error=(
                    "unable to make artifact readable by bounded install analysis "
                    f"container: {exc}"
                ),
                classification="unsupported",
                failure_type="container_setup_failed",
            )
            return result
        container_path = f"/work/{artifact_name}"
        runner = _runner_source(
            container_path,
            import_probe=import_probe,
            entry_point_probe=entry_point_probe,
        )
        docker_command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "65534:65534",
            "--cpus",
            "1",
            "--memory",
            MAX_DYNAMIC_MEMORY,
            "--memory-swap",
            MAX_DYNAMIC_MEMORY,
            "--pids-limit",
            "128",
            "--ulimit",
            f"cpu={MAX_DYNAMIC_CPU_SECONDS}",
            "--ulimit",
            "nofile=256:256",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            CONTAINER_TEMPFS,
            "--volume",
            f"{artifact_path.parent.resolve()}:/work:ro",
            "--workdir",
            "/work",
            selected_image,
            "python",
            "-I",
            "-c",
            runner,
        ]
        result.command = [*docker_command[:-1], "<bounded-install-runner>"]
        try:
            completed = subprocess.run(  # nosec B603
                docker_command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            result.stdout = _excerpt(exc.stdout or "")
            result.stderr = _excerpt(exc.stderr or "")
            result.error = (
                f"bounded install analysis exceeded the {timeout:g}-second time limit"
            )
            result.classification = "timed-out"
            result.failure_type = "timed_out"
            result.phases = [
                DynamicAnalysisPhase(
                    name="sandbox_execution",
                    status="failed",
                    classification="timed-out",
                    failure_type="timed_out",
                    error=result.error,
                    stdout=result.stdout,
                    stderr=result.stderr,
                )
            ]
            return result
        except OSError as exc:
            _fail_before_execution(
                result,
                error=f"unable to start bounded install analysis container: {exc}",
                classification="unsupported",
                failure_type="container_start_failed",
            )
            return result

    result.executed = True
    result.exit_code = completed.returncode
    parsed, stdout_without_result = _parse_runner_result(completed.stdout)
    result.stdout = _excerpt(stdout_without_result)
    result.stderr = _excerpt(completed.stderr)
    if parsed is not None:
        result.phases = _parse_phases(parsed.get("phases"))
        result.evidence = _parse_evidence(parsed.get("evidence"))
    result.classification, result.failure_type = _classify_result(
        completed.returncode,
        result.phases,
        result.evidence,
    )
    if completed.returncode != 0:
        result.error = _error_from_phases(result.phases) or (
            "bounded install analysis completed with a non-zero exit code "
            f"{completed.returncode}"
        )
    return result


def default_dynamic_image(python_version: str = DEFAULT_DYNAMIC_PYTHON) -> str | None:
    return DYNAMIC_ANALYZER_IMAGES.get(python_version)


def _base_result(
    *,
    image: str | None,
    python_version: str,
    timeout: float,
) -> DynamicAnalysisResult:
    return DynamicAnalysisResult(
        enabled=True,
        mode=BOUNDED_INSTALL_ANALYSIS_MODE,
        mode_label="sandboxed installation probe",
        classification="inconclusive",
        sandbox="docker",
        network="none",
        user="65534:65534",
        cpu_limit=f"1 CPU, {MAX_DYNAMIC_CPU_SECONDS} CPU seconds",
        memory_limit="512 MiB",
        pids_limit=128,
        root_filesystem="read-only",
        artifact_mount="read-only",
        temp_filesystem="private tmpfs",
        timeout_seconds=timeout,
        python_version=python_version,
        image=image,
    )


def _fail_before_execution(
    result: DynamicAnalysisResult,
    *,
    error: str,
    classification: str,
    failure_type: str,
) -> None:
    result.error = error
    result.classification = classification
    result.failure_type = failure_type
    result.phases = [
        DynamicAnalysisPhase(
            name="sandbox_setup",
            status="failed",
            classification=classification,
            failure_type=failure_type,
            error=error,
        )
    ]


def _parse_runner_result(stdout: str) -> tuple[dict[str, Any] | None, str]:
    parsed: dict[str, Any] | None = None
    kept_lines: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(RESULT_PREFIX):
            try:
                payload = json.loads(line.removeprefix(RESULT_PREFIX))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                parsed = payload
            continue
        kept_lines.append(line)
    return parsed, "\n".join(kept_lines)


def _parse_phases(value: Any) -> list[DynamicAnalysisPhase]:
    if not isinstance(value, list):
        return []
    phases: list[DynamicAnalysisPhase] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        phases.append(
            DynamicAnalysisPhase(
                name=str(item["name"]),
                status=str(item.get("status", "pending")),
                classification=str(item.get("classification", "inconclusive")),
                failure_type=(
                    str(item["failure_type"])
                    if item.get("failure_type") is not None
                    else None
                ),
                exit_code=(
                    int(item["exit_code"])
                    if isinstance(item.get("exit_code"), int)
                    else None
                ),
                stdout=_string_list(item.get("stdout")),
                stderr=_string_list(item.get("stderr")),
                error=str(item["error"]) if item.get("error") is not None else None,
            )
        )
    return phases


def _parse_evidence(value: Any) -> DynamicAnalysisEvidence:
    if not isinstance(value, dict):
        return DynamicAnalysisEvidence()
    return DynamicAnalysisEvidence(
        child_processes=_string_list(value.get("child_processes")),
        executable_paths=_string_list(value.get("executable_paths")),
        files_created=_string_list(value.get("files_created")),
        files_modified=_string_list(value.get("files_modified")),
        writes_outside_expected_locations=_string_list(
            value.get("writes_outside_expected_locations")
        ),
        attempted_network_connections=_string_list(
            value.get("attempted_network_connections")
        ),
        credential_path_accesses=_string_list(value.get("credential_path_accesses")),
        persistence_attempts=_string_list(value.get("persistence_attempts")),
        environment_accesses=_string_list(value.get("environment_accesses")),
        subprocess_arguments=_argument_list(value.get("subprocess_arguments")),
    )


def _classify_result(
    returncode: int,
    phases: list[DynamicAnalysisPhase],
    evidence: DynamicAnalysisEvidence,
) -> tuple[str, str | None]:
    if _has_suspicious_evidence(evidence):
        return "suspicious", "suspicious_behavior"
    for phase in phases:
        if phase.classification == "suspicious":
            return "suspicious", phase.failure_type or "suspicious_behavior"
    for phase in phases:
        if phase.status == "failed":
            return "inconclusive", phase.failure_type or "phase_failed"
    if returncode != 0:
        return "inconclusive", "analysis_failed"
    if phases:
        return "passed", None
    return "inconclusive", "result_unavailable"


def _has_suspicious_evidence(evidence: DynamicAnalysisEvidence) -> bool:
    return bool(
        evidence.writes_outside_expected_locations
        or evidence.attempted_network_connections
        or evidence.credential_path_accesses
        or evidence.persistence_attempts
    )


def _error_from_phases(phases: list[DynamicAnalysisPhase]) -> str | None:
    for phase in phases:
        if phase.status == "failed" and phase.error:
            return f"{phase.name}: {phase.error}"
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _argument_list(value: Any) -> list[list[str]]:
    if not isinstance(value, list):
        return []
    arguments: list[list[str]] = []
    for item in value:
        if isinstance(item, list):
            arguments.append([str(part) for part in item])
    return arguments


def _runner_source(
    artifact_path: str,
    *,
    import_probe: bool,
    entry_point_probe: bool,
) -> str:
    payload = {
        "artifact_path": artifact_path,
        "import_probe": import_probe,
        "entry_point_probe": entry_point_probe,
        "result_prefix": RESULT_PREFIX,
        "max_output_lines": MAX_DYNAMIC_OUTPUT_LINES,
    }
    return (
        "import json, os, pathlib, runpy, socket, subprocess, sys, tarfile, zipfile, venv\n"
        f"CONFIG = json.loads({json.dumps(json.dumps(payload, sort_keys=True))})\n"
        "ARTIFACT = pathlib.Path(CONFIG['artifact_path'])\n"
        "MAX_LINES = CONFIG['max_output_lines']\n"
        "AUDIT_LOG = pathlib.Path('/tmp/trustcheck-audit.jsonl')\n"
        "PIP_WRAPPER = pathlib.Path('/tmp/trustcheck-pip-wrapper.py')\n"
        "phases = []\n"
        "evidence = {\n"
        "    'child_processes': [], 'executable_paths': [], 'files_created': [],\n"
        "    'files_modified': [], 'writes_outside_expected_locations': [],\n"
        "    'attempted_network_connections': [], 'credential_path_accesses': [],\n"
        "    'persistence_attempts': [], 'environment_accesses': [],\n"
        "    'subprocess_arguments': [],\n"
        "}\n"
        "def excerpt(value):\n"
        "    lines = str(value or '').splitlines()\n"
        "    if len(lines) <= MAX_LINES:\n"
        "        return lines\n"
        "    return [*lines[:MAX_LINES], f'... truncated {len(lines) - MAX_LINES} line(s)']\n"
        "def add_unique(key, value):\n"
        "    if value and value not in evidence[key]:\n"
        "        evidence[key].append(value)\n"
        "def add_args(value):\n"
        "    if isinstance(value, (list, tuple)):\n"
        "        rendered = [str(part) for part in value]\n"
        "    else:\n"
        "        rendered = [str(value)]\n"
        "    if rendered not in evidence['subprocess_arguments']:\n"
        "        evidence['subprocess_arguments'].append(rendered)\n"
        "def suspicious_path(path):\n"
        "    lowered = path.lower()\n"
        "    credential_markers = (\n"
        "        '.pypirc', '.netrc', '.ssh', 'id_rsa',\n"
        "        'credentials', 'keyring',\n"
        "    )\n"
        "    if any(part in lowered for part in credential_markers):\n"
        "        add_unique('credential_path_accesses', path)\n"
        "    persistence_markers = (\n"
        "        'sitecustomize.py', 'usercustomize.py', '.pth', 'cron',\n"
        "        'systemd', '.bashrc', '.profile',\n"
        "    )\n"
        "    if any(part in lowered for part in persistence_markers):\n"
        "        add_unique('persistence_attempts', path)\n"
        "def classify_write(path):\n"
        "    text = str(path)\n"
        "    add_unique('files_modified', text)\n"
        "    suspicious_path(text)\n"
        "    allowed = (\n"
        "        '/tmp/trustcheck-venv', '/tmp/trustcheck-wheelhouse',\n"
        "        '/tmp/trustcheck-metadata', '/tmp/pip-', '/tmp/tmp',\n"
        "    )\n"
        "    if text.startswith('/') and not text.startswith(allowed):\n"
        "        add_unique('writes_outside_expected_locations', text)\n"
        "def merge_audit_log():\n"
        "    if not AUDIT_LOG.exists():\n"
        "        return\n"
        "    for raw in AUDIT_LOG.read_text(encoding='utf-8', errors='replace').splitlines():\n"
        "        try:\n"
        "            event = json.loads(raw)\n"
        "        except json.JSONDecodeError:\n"
        "            continue\n"
        "        name = event.get('event')\n"
        "        args = event.get('args') or []\n"
        "        if name == 'subprocess.Popen':\n"
        "            add_unique('child_processes', str(args[0]) if args else '')\n"
        "            add_unique('executable_paths', str(args[0]) if args else '')\n"
        "            if len(args) > 1:\n"
        "                add_args(args[1])\n"
        "        elif name == 'open' and args:\n"
        "            path = str(args[0])\n"
        "            mode = str(args[1]) if len(args) > 1 else ''\n"
        "            suspicious_path(path)\n"
        "            if any(flag in mode for flag in ('w', 'a', '+', 'x')):\n"
        "                classify_write(path)\n"
        "        elif name == 'os.mkdir' and args:\n"
        "            add_unique('files_created', str(args[0]))\n"
        "            suspicious_path(str(args[0]))\n"
        "        elif name == 'socket.connect' and args:\n"
        "            add_unique('attempted_network_connections', repr(args[-1]))\n"
        "        elif name in {'os.putenv', 'os.unsetenv'} and args:\n"
        "            add_unique('environment_accesses', str(args[0]))\n"
        "def write_pip_wrapper():\n"
        "    PIP_WRAPPER.write_text(\"\"\"\n"
        "import json, pathlib, runpy, sys\n"
        "AUDIT_LOG = pathlib.Path('/tmp/trustcheck-audit.jsonl')\n"
        "def hook(event, args):\n"
        "    tracked_events = {\n"
        "        'subprocess.Popen', 'open', 'os.mkdir', 'socket.connect',\n"
        "        'os.putenv', 'os.unsetenv',\n"
        "    }\n"
        "    if event in tracked_events:\n"
        "        try:\n"
        "            rendered = []\n"
        "            for item in args:\n"
        "                if isinstance(item, (list, tuple)):\n"
        "                    rendered.append([str(part) for part in item])\n"
        "                else:\n"
        "                    rendered.append(str(item))\n"
        "            with AUDIT_LOG.open('a', encoding='utf-8') as stream:\n"
        "                record = {'event': event, 'args': rendered}\n"
        "                stream.write(json.dumps(record, sort_keys=True) + '\\\\n')\n"
        "        except Exception:\n"
        "            pass\n"
        "sys.addaudithook(hook)\n"
        "sys.argv = ['pip', *sys.argv[1:]]\n"
        "runpy.run_module('pip', run_name='__main__')\n"
        "\"\"\".strip() + \"\\n\", encoding='utf-8')\n"
        "def phase(\n"
        "    name, status='passed', classification='passed', failure_type=None,\n"
        "    exit_code=None, stdout='', stderr='', error=None,\n"
        "):\n"
        "    phases.append({\n"
        "        'name': name,\n"
        "        'status': status,\n"
        "        'classification': classification,\n"
        "        'failure_type': failure_type,\n"
        "        'exit_code': exit_code,\n"
        "        'stdout': excerpt(stdout),\n"
        "        'stderr': excerpt(stderr),\n"
        "        'error': error,\n"
        "    })\n"
        "def failure_type(name, stderr):\n"
        "    text = str(stderr).lower()\n"
        "    if (\n"
        "        'backendunavailable' in text\n"
        "        or 'no module named' in text\n"
        "        or 'build backend' in text\n"
        "    ):\n"
        "        return 'backend_unavailable'\n"
        "    if name == 'metadata_preparation':\n"
        "        return 'metadata_invalid'\n"
        "    if name == 'wheel_build':\n"
        "        return 'build_failed'\n"
        "    if name == 'wheel_installation':\n"
        "        return 'install_hook_failed'\n"
        "    return 'analysis_failed'\n"
        "def run_phase(name, cmd):\n"
        "    completed = subprocess.run(cmd, text=True, capture_output=True, check=False)\n"
        "    merge_audit_log()\n"
        "    if completed.returncode == 0:\n"
        "        phase(name, exit_code=0, stdout=completed.stdout, stderr=completed.stderr)\n"
        "        return True\n"
        "    kind = failure_type(name, completed.stderr)\n"
        "    error = f'{name} failed with exit code {completed.returncode}'\n"
        "    phase(\n"
        "        name,\n"
        "        status='failed',\n"
        "        classification='inconclusive',\n"
        "        failure_type=kind,\n"
        "        exit_code=completed.returncode,\n"
        "        stdout=completed.stdout,\n"
        "        stderr=completed.stderr,\n"
        "        error=error,\n"
        "    )\n"
        "    return False\n"
        "def validate_archive():\n"
        "    suffixes = ''.join(ARTIFACT.suffixes).lower()\n"
        "    try:\n"
        "        if ARTIFACT.suffix.lower() == '.whl' or ARTIFACT.suffix.lower() == '.zip':\n"
        "            if not zipfile.is_zipfile(ARTIFACT):\n"
        "                raise ValueError('artifact is not a valid zip archive')\n"
        "        elif suffixes.endswith(('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')):\n"
        "            if not tarfile.is_tarfile(ARTIFACT):\n"
        "                raise ValueError('artifact is not a valid tar archive')\n"
        "        else:\n"
        "            raise ValueError('artifact is not a supported wheel or source archive')\n"
        "        phase('archive_validation')\n"
        "        return True\n"
        "    except Exception as exc:\n"
        "        phase(\n"
        "            'archive_validation',\n"
        "            status='failed',\n"
        "            classification='inconclusive',\n"
        "            failure_type='metadata_invalid',\n"
        "            error=str(exc),\n"
        "        )\n"
        "        return False\n"
        "ok = validate_archive()\n"
        "venv_dir = '/tmp/trustcheck-venv'\n"
        "wheel_dir = pathlib.Path('/tmp/trustcheck-wheelhouse')\n"
        "metadata_dir = pathlib.Path('/tmp/trustcheck-metadata')\n"
        "if ok:\n"
        "    venv.create(venv_dir, with_pip=True)\n"
        "    write_pip_wrapper()\n"
        "    python = venv_dir + '/bin/python'\n"
        "    find_links = pathlib.Path('/opt/trustcheck/wheelhouse')\n"
        "    find_links_args = ['--find-links', str(find_links)] if find_links.exists() else []\n"
        "    metadata_dir.mkdir(parents=True, exist_ok=True)\n"
        "    metadata_cmd = [\n"
        "        python, str(PIP_WRAPPER), 'install', '--dry-run', '--report',\n"
        "        str(metadata_dir / 'report.json'), '--no-input',\n"
        "        '--disable-pip-version-check', '--no-cache-dir', '--no-deps',\n"
        "        '--no-index', '--no-build-isolation', *find_links_args,\n"
        "        str(ARTIFACT),\n"
        "    ]\n"
        "    ok = run_phase('metadata_preparation', metadata_cmd)\n"
        "if ok and ARTIFACT.suffix.lower() == '.whl':\n"
        "    phase('wheel_build', status='skipped', classification='passed')\n"
        "elif ok:\n"
        "    wheel_dir.mkdir(parents=True, exist_ok=True)\n"
        "    wheel_cmd = [\n"
        "        python, str(PIP_WRAPPER), 'wheel', '--no-input',\n"
        "        '--disable-pip-version-check', '--no-cache-dir', '--no-deps',\n"
        "        '--no-index', '--no-build-isolation', *find_links_args,\n"
        "        '--wheel-dir', str(wheel_dir), str(ARTIFACT),\n"
        "    ]\n"
        "    ok = run_phase('wheel_build', wheel_cmd)\n"
        "if ok:\n"
        "    wheels = sorted(wheel_dir.glob('*.whl'))\n"
        "    install_target = str(wheels[0]) if wheels else str(ARTIFACT)\n"
        "    install_cmd = [\n"
        "        python, str(PIP_WRAPPER), 'install', '--no-input',\n"
        "        '--disable-pip-version-check', '--no-cache-dir', '--no-deps',\n"
        "        '--no-index', '--no-build-isolation', *find_links_args,\n"
        "        install_target,\n"
        "    ]\n"
        "    ok = run_phase('wheel_installation', install_cmd)\n"
        "if ok and CONFIG['import_probe']:\n"
        "    import_error = (\n"
        "        'import probe is not enabled until package import targets are '\n"
        "        'policy-defined'\n"
        "    )\n"
        "    phase(\n"
        "        'import_probe', status='skipped',\n"
        "        classification='inconclusive',\n"
        "        failure_type='unsupported_behavior',\n"
        "        error=import_error,\n"
        "    )\n"
        "else:\n"
        "    phase('import_probe', status='skipped', classification='inconclusive')\n"
        "if ok and CONFIG['entry_point_probe']:\n"
        "    entry_point_error = (\n"
        "        'entry point probe is not enabled until command targets are '\n"
        "        'policy-defined'\n"
        "    )\n"
        "    phase(\n"
        "        'entry_point_probe', status='skipped',\n"
        "        classification='inconclusive',\n"
        "        failure_type='unsupported_behavior',\n"
        "        error=entry_point_error,\n"
        "    )\n"
        "else:\n"
        "    phase('entry_point_probe', status='skipped', classification='inconclusive')\n"
        "merge_audit_log()\n"
        "payload = {'phases': phases, 'evidence': evidence}\n"
        "print(CONFIG['result_prefix'] + json.dumps(payload, sort_keys=True))\n"
        "raise SystemExit(0 if ok else 1)\n"
    )


def _excerpt(value: str | bytes) -> list[str]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    lines = value.splitlines()
    if len(lines) <= MAX_DYNAMIC_OUTPUT_LINES:
        return lines
    return [
        *lines[:MAX_DYNAMIC_OUTPUT_LINES],
        f"... truncated {len(lines) - MAX_DYNAMIC_OUTPUT_LINES} line(s)",
    ]
