from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess  # nosec B404
import sys
import sysconfig
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from urllib import parse

from .indexes import DEFAULT_INDEX_URL, normalize_index_url, redact_url_credentials
from .lockfiles import PYLOCK_NAME, SUPPORTED_LOCKFILES
from .resolver import (
    DEFAULT_SANDBOX_IMAGE,
    DIGEST_PINNED_IMAGE_PATTERN,
    MINIMUM_SUPPORTED_PIP,
    SANDBOX_MODES,
    is_supported_pip_version,
    parse_pip_version_text,
)

DoctorStatus = Literal["pass", "warn", "fail"]
ExecutableFinder = Callable[[str], str | None]
ModuleChecker = Callable[[str], bool]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: DoctorStatus
    message: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def passed(self) -> bool:
        return not any(check.status == "fail" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "checks": [asdict(check) for check in self.checks],
        }


def collect_doctor_report(
    *,
    cache_dir: str | None = None,
    index_urls: Sequence[str] = (DEFAULT_INDEX_URL,),
    keyring_provider: str = "auto",
    sandbox_mode: str = "auto",
    sandbox_image: str | None = None,
    python_executable: str = sys.executable,
    executable_finder: ExecutableFinder = shutil.which,
    command_runner: CommandRunner = subprocess.run,
    module_checker: ModuleChecker | None = None,
    environ: Mapping[str, str] | None = None,
    platform_system: str | None = None,
    home: Path | None = None,
    stdlib_path: Path | None = None,
    in_virtualenv: bool | None = None,
) -> DoctorReport:
    env = environ if environ is not None else os.environ
    module_available = module_checker or _module_available
    system = platform_system or platform.system()
    checks = [
        _executable_check("Docker", "docker", executable_finder=executable_finder),
        _executable_check("Podman", "podman", executable_finder=executable_finder),
        _bubblewrap_check(
            executable_finder=executable_finder,
            platform_system=system,
        ),
        _pip_runtime_check(
            python_executable=python_executable,
            command_runner=command_runner,
        ),
        _externally_managed_environment_check(
            stdlib_path=stdlib_path,
            in_virtualenv=in_virtualenv,
        ),
        _keyring_check(
            keyring_provider=keyring_provider,
            module_checker=module_available,
        ),
        _sigstore_check(
            module_checker=module_available,
            environ=env,
            home=home,
        ),
        _private_index_auth_check(
            index_urls=index_urls,
            keyring_provider=keyring_provider,
            keyring_available=module_available("keyring"),
        ),
        _cache_permissions_check(cache_dir=cache_dir, environ=env),
        _lockfile_tools_check(executable_finder=executable_finder),
        _sandbox_selection_check(
            sandbox_mode=sandbox_mode,
            executable_finder=executable_finder,
            platform_system=system,
        ),
        _resolver_container_image_check(container_image=sandbox_image),
    ]
    return DoctorReport(checks=tuple(checks))


def render_doctor_text(report: DoctorReport) -> str:
    lines = [
        "trustcheck doctor",
        f"overall: {'pass' if report.passed else 'fail'}",
        "",
        "checks:",
    ]
    for check in report.checks:
        lines.append(f"  - [{check.status}] {check.name}: {check.message}")
        lines.extend(f"    evidence: {item}" for item in check.evidence)
    return "\n".join(lines)


def render_doctor_json(report: DoctorReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def _executable_check(
    name: str,
    executable: str,
    *,
    executable_finder: ExecutableFinder,
) -> DoctorCheck:
    path = executable_finder(executable)
    if path:
        return DoctorCheck(
            name=name,
            status="pass",
            message=f"{executable} is available.",
            evidence=(path,),
        )
    return DoctorCheck(
        name=name,
        status="warn",
        message=f"{executable} was not found on PATH.",
    )


def _bubblewrap_check(
    *,
    executable_finder: ExecutableFinder,
    platform_system: str,
) -> DoctorCheck:
    path = executable_finder("bwrap")
    if path:
        return DoctorCheck(
            name="Bubblewrap",
            status="pass",
            message="bwrap is available for resolver isolation.",
            evidence=(path,),
        )
    if platform_system != "Linux":
        return DoctorCheck(
            name="Bubblewrap",
            status="warn",
            message="bwrap is only supported on Linux and is not available here.",
            evidence=(f"platform={platform_system}",),
        )
    return DoctorCheck(
        name="Bubblewrap",
        status="warn",
        message="bwrap was not found on PATH.",
    )


def _pip_runtime_check(
    *,
    python_executable: str,
    command_runner: CommandRunner,
) -> DoctorCheck:
    command = [python_executable, "-m", "pip", "--version"]
    try:
        completed = command_runner(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
    except OSError as exc:
        return DoctorCheck(
            name="Resolver pip",
            status="fail",
            message="unable to start pip through the selected Python executable.",
            evidence=(str(exc), f"python={python_executable}"),
        )
    output = "\n".join(item for item in (completed.stdout, completed.stderr) if item)
    parsed = parse_pip_version_text(output)
    if completed.returncode != 0:
        evidence = [f"python={python_executable}", f"exit={completed.returncode}"]
        if output_line := _first_output_line(output):
            evidence.append(output_line)
        return DoctorCheck(
            name="Resolver pip",
            status="fail",
            message="pip is not available through the selected Python executable.",
            evidence=tuple(evidence),
        )
    if parsed is None:
        evidence = [f"python={python_executable}"]
        if output_line := _first_output_line(output):
            evidence.append(output_line)
        return DoctorCheck(
            name="Resolver pip",
            status="fail",
            message="unable to parse pip version from resolver subprocess.",
            evidence=tuple(evidence),
        )
    if not is_supported_pip_version(parsed):
        return DoctorCheck(
            name="Resolver pip",
            status="fail",
            message=(
                f"pip {parsed} is unsupported; trustcheck requires pip "
                f">= {MINIMUM_SUPPORTED_PIP} for dry-run installation reports."
            ),
            evidence=(f"python={python_executable}", f"pip={parsed}"),
        )
    return DoctorCheck(
        name="Resolver pip",
        status="pass",
        message="pip is available through the selected Python executable.",
        evidence=(f"python={python_executable}", f"pip={parsed}"),
    )


def _externally_managed_environment_check(
    *,
    stdlib_path: Path | None,
    in_virtualenv: bool | None,
) -> DoctorCheck:
    virtual = in_virtualenv if in_virtualenv is not None else sys.prefix != sys.base_prefix
    configured_stdlib = sysconfig.get_path("stdlib")
    raw_stdlib = stdlib_path or Path(configured_stdlib or sys.prefix)
    marker = raw_stdlib / "EXTERNALLY-MANAGED"
    if marker.exists() and not virtual:
        return DoctorCheck(
            name="Externally managed Python",
            status="warn",
            message=(
                "this Python installation is externally managed; resolver scans are "
                "read-only, but a virtualenv or pipx-style install avoids pip policy "
                "surprises."
            ),
            evidence=(str(marker),),
        )
    return DoctorCheck(
        name="Externally managed Python",
        status="pass",
        message="the resolver is running in a virtualenv-style or unmanaged Python.",
        evidence=(f"virtualenv={virtual}",),
    )


def _keyring_check(
    *,
    keyring_provider: str,
    module_checker: ModuleChecker,
) -> DoctorCheck:
    if keyring_provider == "disabled":
        return DoctorCheck(
            name="Keyring",
            status="warn",
            message="keyring integration is disabled by configuration.",
        )
    if module_checker("keyring"):
        return DoctorCheck(
            name="Keyring",
            status="pass",
            message="the Python keyring package is importable.",
            evidence=(f"provider={keyring_provider}",),
        )
    status: DoctorStatus = "fail" if keyring_provider == "import" else "warn"
    return DoctorCheck(
        name="Keyring",
        status=status,
        message="the Python keyring package is not importable.",
        evidence=(f"provider={keyring_provider}",),
    )


def _sigstore_check(
    *,
    module_checker: ModuleChecker,
    environ: Mapping[str, str],
    home: Path | None,
) -> DoctorCheck:
    if not module_checker("sigstore"):
        return DoctorCheck(
            name="Sigstore trust roots",
            status="fail",
            message="the sigstore package is not importable.",
        )
    roots = _sigstore_state_directories(environ=environ, home=home)
    unwritable = [
        str(path)
        for path in roots
        if not _directory_writable(path)
    ]
    if unwritable:
        return DoctorCheck(
            name="Sigstore trust roots",
            status="fail",
            message="one or more Sigstore state directories are not writable.",
            evidence=tuple(unwritable),
        )
    return DoctorCheck(
        name="Sigstore trust roots",
        status="pass",
        message="sigstore is importable and trust-root state directories are writable.",
        evidence=tuple(str(path) for path in roots),
    )


def _sigstore_state_directories(
    *,
    environ: Mapping[str, str],
    home: Path | None,
) -> tuple[Path, ...]:
    user_home = home or Path.home()
    if sys.platform == "win32":
        default_data = Path(environ.get("LOCALAPPDATA", user_home / "AppData" / "Local"))
        default_cache = default_data
        default_config = default_data
    else:
        default_data = user_home / ".local" / "share"
        default_cache = user_home / ".cache"
        default_config = user_home / ".config"
    return (
        Path(environ.get("XDG_DATA_HOME", str(default_data))) / "sigstore",
        Path(environ.get("XDG_CACHE_HOME", str(default_cache))) / "sigstore",
        Path(environ.get("XDG_CONFIG_HOME", str(default_config))) / "sigstore",
    )


def _private_index_auth_check(
    *,
    index_urls: Sequence[str],
    keyring_provider: str,
    keyring_available: bool,
) -> DoctorCheck:
    private_urls = [
        url
        for url in index_urls
        if redact_url_credentials(normalize_index_url(url))
        != normalize_index_url(DEFAULT_INDEX_URL)
    ]
    if not private_urls:
        return DoctorCheck(
            name="Private-index authentication",
            status="pass",
            message="only the public PyPI index is configured.",
        )

    credentialed = []
    username_only = []
    for raw_url in private_urls:
        parsed = parse.urlsplit(raw_url)
        redacted = redact_url_credentials(normalize_index_url(raw_url))
        if parsed.username and parsed.password:
            credentialed.append(redacted)
        elif parsed.username:
            username_only.append(redacted)

    if len(credentialed) == len(private_urls):
        return DoctorCheck(
            name="Private-index authentication",
            status="pass",
            message="configured private indexes include inline credentials.",
            evidence=tuple(credentialed),
        )
    if username_only and keyring_provider != "disabled" and keyring_available:
        return DoctorCheck(
            name="Private-index authentication",
            status="pass",
            message="private indexes include usernames and keyring is available.",
            evidence=tuple(username_only),
        )
    return DoctorCheck(
        name="Private-index authentication",
        status="warn",
        message=(
            "a private index is configured, but no complete inline credentials "
            "or importable keyring provider were detected."
        ),
        evidence=tuple(redact_url_credentials(normalize_index_url(url)) for url in private_urls),
    )


def _cache_permissions_check(
    *,
    cache_dir: str | None,
    environ: Mapping[str, str],
) -> DoctorCheck:
    selected = cache_dir or environ.get("TRUSTCHECK_CACHE_DIR")
    if not selected:
        return DoctorCheck(
            name="Cache permissions",
            status="warn",
            message="no persistent cache directory is configured.",
        )
    path = Path(selected)
    if _directory_writable(path):
        return DoctorCheck(
            name="Cache permissions",
            status="pass",
            message="the configured cache directory is writable.",
            evidence=(str(path),),
        )
    return DoctorCheck(
        name="Cache permissions",
        status="fail",
        message="the configured cache directory is not writable.",
        evidence=(str(path),),
    )


def _lockfile_tools_check(
    *,
    executable_finder: ExecutableFinder,
) -> DoctorCheck:
    tools = {
        "pip-tools": "pip-compile",
        "uv": "uv",
        "Poetry": "poetry",
        "PDM": "pdm",
    }
    found = [
        f"{name}={path}"
        for name, executable in tools.items()
        if (path := executable_finder(executable))
    ]
    missing = [
        name
        for name, executable in tools.items()
        if not executable_finder(executable)
    ]
    supported = ", ".join(sorted(SUPPORTED_LOCKFILES)) + ", pylock*.toml"
    evidence = [f"built-in parsers: {supported}"]
    evidence.extend(found)
    if missing:
        evidence.append("missing generators: " + ", ".join(missing))
    return DoctorCheck(
        name="Supported lockfile tools",
        status="pass",
        message="built-in lockfile parsers are available.",
        evidence=tuple(evidence),
    )


def _sandbox_selection_check(
    *,
    sandbox_mode: str,
    executable_finder: ExecutableFinder,
    platform_system: str,
) -> DoctorCheck:
    if sandbox_mode not in SANDBOX_MODES:
        return DoctorCheck(
            name="Resolver sandbox",
            status="fail",
            message=f"unsupported sandbox mode: {sandbox_mode}",
        )
    if sandbox_mode in {"off", "warn", "strict"}:
        message = (
            "strict wheel-only fallback is available without an OS sandbox runtime."
            if sandbox_mode == "strict"
            else f"resolver sandbox mode {sandbox_mode!r} does not require a runtime."
        )
        return DoctorCheck(
            name="Resolver sandbox",
            status="pass",
            message=message,
        )
    if sandbox_mode == "bubblewrap":
        status: DoctorStatus = (
            "pass"
            if platform_system == "Linux" and executable_finder("bwrap")
            else "fail"
        )
        return DoctorCheck(
            name="Resolver sandbox",
            status=status,
            message="bubblewrap sandbox runtime check completed.",
            evidence=(f"platform={platform_system}",),
        )
    if sandbox_mode == "container":
        runtime = executable_finder("docker") or executable_finder("podman")
        return DoctorCheck(
            name="Resolver sandbox",
            status="pass" if runtime else "fail",
            message="container sandbox runtime check completed.",
            evidence=(runtime,) if runtime else (),
        )
    runtime = executable_finder("bwrap") if platform_system == "Linux" else None
    runtime = runtime or executable_finder("docker") or executable_finder("podman")
    message = (
        "auto mode can use an enforced runtime."
        if runtime
        else "auto mode will fall back to strict wheel-only resolution."
    )
    return DoctorCheck(
        name="Resolver sandbox",
        status="pass" if runtime else "warn",
        message=message,
        evidence=(runtime,) if runtime else ("fallback=strict-wheel-only",),
    )


def _resolver_container_image_check(
    *,
    container_image: str | None,
) -> DoctorCheck:
    image = container_image or DEFAULT_SANDBOX_IMAGE
    if DIGEST_PINNED_IMAGE_PATTERN.fullmatch(image):
        return DoctorCheck(
            name="Resolver container image",
            status="pass",
            message="container resolver image is pinned by sha256 digest.",
            evidence=(image,),
        )
    return DoctorCheck(
        name="Resolver container image",
        status="fail",
        message="container resolver image must be pinned by a full sha256 digest.",
        evidence=(image,),
    )


def _first_output_line(output: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:240]
    return None


def _directory_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=".trustcheck-doctor-",
            dir=path,
            delete=True,
        ) as handle:
            handle.write(b"ok")
            handle.flush()
        return True
    except OSError:
        return False


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def supported_lockfile_patterns() -> tuple[str, ...]:
    return tuple(sorted((*SUPPORTED_LOCKFILES, PYLOCK_NAME.pattern)))
