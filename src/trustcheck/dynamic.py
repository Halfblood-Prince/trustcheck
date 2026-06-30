from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import tempfile
from pathlib import Path

from .models import DynamicAnalysisResult

DEFAULT_DYNAMIC_IMAGE = "python:3.12-slim"
MAX_DYNAMIC_SECONDS = 30.0
MAX_DYNAMIC_CPU_SECONDS = 10
MAX_DYNAMIC_MEMORY = "512m"
MAX_DYNAMIC_OUTPUT_LINES = 25
# This path is a private tmpfs mount inside the disposable analysis container.
CONTAINER_TEMPFS = "/tmp:rw,nosuid,nodev,size=256m"  # nosec B108


def analyze_artifact_dynamic(
    filename: str,
    payload: bytes,
    *,
    image: str = DEFAULT_DYNAMIC_IMAGE,
    timeout: float = MAX_DYNAMIC_SECONDS,
) -> DynamicAnalysisResult:
    result = DynamicAnalysisResult(
        enabled=True,
        sandbox="docker",
        network="none",
        user="65534:65534",
        cpu_limit=f"1 CPU, {MAX_DYNAMIC_CPU_SECONDS} CPU seconds",
        memory_limit="512 MiB",
        timeout_seconds=timeout,
        image=image,
    )
    if shutil.which("docker") is None:
        result.error = "dynamic analysis requires the Docker CLI to be available"
        return result

    artifact_name = Path(filename).name or "artifact"
    with tempfile.TemporaryDirectory(prefix="trustcheck-dynamic-") as directory:
        artifact_path = Path(directory) / artifact_name
        artifact_path.write_bytes(payload)
        container_path = f"/work/{artifact_name}"
        runner = _runner_source(container_path)
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
            image,
            "python",
            "-I",
            "-c",
            runner,
        ]
        result.command = [*docker_command[:-1], "<dynamic-analysis-runner>"]
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
            result.error = f"dynamic analysis exceeded the {timeout:g}-second time limit"
            return result
        except OSError as exc:
            result.error = f"unable to start dynamic-analysis container: {exc}"
            return result

    result.executed = True
    result.exit_code = completed.returncode
    result.stdout = _excerpt(completed.stdout)
    result.stderr = _excerpt(completed.stderr)
    if completed.returncode != 0:
        result.error = (
            "dynamic analysis completed with a non-zero exit code "
            f"{completed.returncode}"
        )
    return result


def _runner_source(artifact_path: str) -> str:
    return (
        "import subprocess, sys, venv\n"
        "venv_dir = '/tmp/trustcheck-venv'\n"
        "venv.create(venv_dir, with_pip=True)\n"
        "python = venv_dir + '/bin/python'\n"
        "cmd = [\n"
        "    python, '-m', 'pip', 'install',\n"
        "    '--no-input', '--disable-pip-version-check', '--no-cache-dir',\n"
        "    '--no-deps', '--no-index', '--no-build-isolation',\n"
        f"    {json.dumps(artifact_path)},\n"
        "]\n"
        "raise SystemExit(subprocess.call(cmd))\n"
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
