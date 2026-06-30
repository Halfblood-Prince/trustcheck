from __future__ import annotations

import argparse

from packaging.markers import default_environment

from .cli_models import (
    EXIT_DATA_ERROR,
    EXIT_POLICY_FAILURE,
    EXIT_REMEDIATION_FAILURE,
    EXIT_UPSTREAM_FAILURE,
)
from .pypi import PypiClientError
from .resolver import TargetEnvironment


def _target_environment_from_args(args: argparse.Namespace) -> TargetEnvironment:
    return TargetEnvironment(
        python_version=getattr(args, "python_version", None),
        platforms=tuple(getattr(args, "platform", ())),
        implementation=getattr(args, "implementation", None),
        abis=tuple(getattr(args, "abi", ())),
    )


def _target_marker_environment(
    target: TargetEnvironment | None,
) -> dict[str, str]:
    environment = {key: str(value) for key, value in default_environment().items()}
    if target is not None and target.python_version:
        parts = target.python_version.split(".")
        if len(parts) >= 2:
            environment["python_version"] = ".".join(parts[:2])
            environment["python_full_version"] = target.python_version
        else:
            environment["python_version"] = target.python_version
            environment["python_full_version"] = target.python_version
    if target is not None and target.platforms:
        platform = target.platforms[0]
        if platform.startswith("win"):
            environment.update({"sys_platform": "win32", "os_name": "nt"})
        elif "macosx" in platform:
            environment.update({"sys_platform": "darwin", "os_name": "posix"})
        elif "linux" in platform:
            environment.update({"sys_platform": "linux", "os_name": "posix"})
    if target is not None and target.implementation:
        implementation_names = {
            "cp": ("cpython", "CPython"),
            "pp": ("pypy", "PyPy"),
        }
        implementation_name, platform_name = implementation_names.get(
            target.implementation,
            (target.implementation, target.implementation),
        )
        environment["implementation_name"] = implementation_name
        environment["platform_python_implementation"] = platform_name
    return environment


def _format_upstream_error(exc: PypiClientError) -> str:
    if exc.code == "advisory":
        source = "advisory service"
    elif exc.code == "dependency":
        source = "dependency resolver"
    else:
        source = "PyPI"
    return (
        f"error: unable to inspect package from {source}: "
        f"{exc} [code={exc.code} subcode={exc.subcode}]"
    )


def _merge_exit_codes(current: int, new: int) -> int:
    if current == EXIT_REMEDIATION_FAILURE or new == EXIT_REMEDIATION_FAILURE:
        return EXIT_REMEDIATION_FAILURE
    if current == EXIT_DATA_ERROR or new == EXIT_DATA_ERROR:
        return EXIT_DATA_ERROR
    if current == EXIT_UPSTREAM_FAILURE or new == EXIT_UPSTREAM_FAILURE:
        return EXIT_UPSTREAM_FAILURE
    if current == EXIT_POLICY_FAILURE or new == EXIT_POLICY_FAILURE:
        return EXIT_POLICY_FAILURE
    return max(current, new)
