from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from pydantic import ValidationError

    from trustcheck.provenance import SlsaValidationError, analyze_slsa_provenance
    from trustcheck.schemas import ProvenanceEnvelopePayload


def test_one_input(data: bytes) -> None:
    try:
        payload = json.loads(data)
    except (UnicodeError, json.JSONDecodeError):
        return
    try:
        ProvenanceEnvelopePayload.model_validate(payload)
    except ValidationError:
        pass
    try:
        analyze_slsa_provenance(
            payload,
            publisher_kind="github",
            publisher_repository="https://github.com/example/project",
            publisher_workflow=".github/workflows/release.yml",
        )
    except SlsaValidationError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
