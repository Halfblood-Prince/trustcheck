from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from packaging.markers import default_environment
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import InvalidName, canonicalize_name

    from trustcheck.cli import _clean_requirement_line, _strip_requirement_hashes
    from trustcheck.resolver import _logical_requirement_lines, _requirement_risks


def test_one_input(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    for line in _logical_requirement_lines(text):
        cleaned = _clean_requirement_line(line)
        stripped = _strip_requirement_hashes(cleaned)
        _requirement_risks(stripped)
        if stripped:
            try:
                requirement = Requirement(stripped)
                canonicalize_name(requirement.name, validate=True)
                if requirement.marker is not None:
                    requirement.marker.evaluate(default_environment())
                if requirement.url is not None:
                    _requirement_risks(f"{requirement.name} @ {requirement.url}")
            except (InvalidName, InvalidRequirement):
                pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
