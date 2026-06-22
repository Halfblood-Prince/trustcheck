from __future__ import annotations

import argparse
import tomllib
from pathlib import Path
from typing import Sequence

from packaging.requirements import Requirement
from packaging.version import Version


def lower_bound_constraints(
    pyproject: Path,
    *,
    extras: Sequence[str] = (),
) -> list[str]:
    with pyproject.open("rb") as pyproject_file:
        payload = tomllib.load(pyproject_file)
    project = payload.get("project")
    dependencies = project.get("dependencies") if isinstance(project, dict) else None
    if not isinstance(dependencies, list):
        raise ValueError("pyproject.toml project.dependencies must be an array")

    raw_dependencies = list(dependencies)
    optional = project.get("optional-dependencies")
    if extras and not isinstance(optional, dict):
        raise ValueError("pyproject.toml project.optional-dependencies must be a table")
    for extra in extras:
        extra_dependencies = optional.get(extra) if isinstance(optional, dict) else None
        if not isinstance(extra_dependencies, list):
            raise ValueError(f"optional dependency group {extra!r} does not exist")
        raw_dependencies.extend(extra_dependencies)

    constraints: list[str] = []
    for raw_dependency in raw_dependencies:
        if not isinstance(raw_dependency, str):
            raise ValueError("project dependency entries must be strings")
        requirement = Requirement(raw_dependency)
        candidates = [
            Version(specifier.version)
            for specifier in requirement.specifier
            if specifier.operator in {">=", "==", "~="}
            and "*" not in specifier.version
        ]
        lower_bound = next(
            (
                candidate
                for candidate in sorted(set(candidates))
                if requirement.specifier.contains(candidate, prereleases=True)
            ),
            None,
        )
        if lower_bound is None:
            raise ValueError(
                f"dependency {requirement.name!r} has no installable lower bound"
            )
        constraints.append(f"{requirement.name}=={lower_bound}")
    return sorted(set(constraints), key=str.casefold)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit exact constraints for declared minimum dependencies."
    )
    parser.add_argument("pyproject", nargs="?", type=Path, default=Path("pyproject.toml"))
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Include lower bounds from this optional dependency group; repeatable.",
    )
    args = parser.parse_args(argv)
    for constraint in lower_bound_constraints(args.pyproject, extras=args.extra):
        print(constraint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
