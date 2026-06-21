from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from packaging.requirements import InvalidRequirement, Requirement

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
                Requirement(stripped)
            except InvalidRequirement:
                pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
