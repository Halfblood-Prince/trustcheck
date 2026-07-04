from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from trustcheck.exports import render_payload_export

FORMATS = (
    "sarif",
    "spdx-json",
    "spdx-3-json",
    "cyclonedx-json",
    "cyclonedx-xml",
    "cyclonedx-1.7-json",
    "cyclonedx-1.7-xml",
)


def test_one_input(data: bytes) -> None:
    if not data:
        return
    try:
        payload = json.loads(data[1:])
    except (UnicodeError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    try:
        render_payload_export(FORMATS[data[0] % len(FORMATS)], payload)
    except (TypeError, UnicodeError, ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
