from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = frozenset(
    {
        "advisory_id",
        "reason",
        "owner",
        "introduced",
        "expires",
    }
)


class AuditExceptionError(ValueError):
    """Raised when an audit exception file is malformed or expired."""


def load_exception_file(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AuditExceptionError("audit exception file must contain a JSON object")
    return payload


def validate_exceptions(payload: dict[str, Any], *, today: date) -> list[dict[str, str]]:
    raw_exceptions = payload.get("exceptions")
    if not isinstance(raw_exceptions, list):
        raise AuditExceptionError("audit exception file must contain an exceptions list")

    validated: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_exceptions):
        if not isinstance(item, dict):
            raise AuditExceptionError(f"exception {index} must be an object")
        keys = set(item)
        missing = REQUIRED_FIELDS - keys
        unexpected = keys - REQUIRED_FIELDS
        if missing:
            raise AuditExceptionError(
                f"exception {index} is missing required fields: {sorted(missing)}"
            )
        if unexpected:
            raise AuditExceptionError(
                f"exception {index} has unexpected fields: {sorted(unexpected)}"
            )

        normalized: dict[str, str] = {}
        for field in REQUIRED_FIELDS:
            value = item[field]
            if not isinstance(value, str) or not value.strip():
                raise AuditExceptionError(
                    f"exception {index} field {field!r} must be a non-empty string"
                )
            normalized[field] = value.strip()

        advisory_id = normalized["advisory_id"]
        if advisory_id in seen:
            raise AuditExceptionError(f"duplicate audit exception for {advisory_id}")
        seen.add(advisory_id)

        introduced = _parse_date(normalized["introduced"], field="introduced", index=index)
        expires = _parse_date(normalized["expires"], field="expires", index=index)
        if introduced > today:
            raise AuditExceptionError(
                f"exception {index} for {advisory_id} starts in the future"
            )
        if expires < today:
            raise AuditExceptionError(
                f"exception {index} for {advisory_id} expired on {expires.isoformat()}"
            )
        validated.append(normalized)
    return validated


def emit_pip_audit_args(exceptions: list[dict[str, str]]) -> list[str]:
    args: list[str] = []
    for item in exceptions:
        args.extend(["--ignore-vuln", item["advisory_id"]])
    return args


def _parse_date(value: str, *, field: str, index: int) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AuditExceptionError(
            f"exception {index} field {field!r} must use YYYY-MM-DD"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate pip-audit vulnerability exception metadata."
    )
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--emit-pip-audit-args",
        action="store_true",
        help="Print one pip-audit ignore argument per line after validation.",
    )
    args = parser.parse_args(argv)

    try:
        exceptions = validate_exceptions(load_exception_file(args.path), today=date.today())
    except (OSError, json.JSONDecodeError, AuditExceptionError) as exc:
        parser.error(str(exc))

    if args.emit_pip_audit_args:
        for argument in emit_pip_audit_args(exceptions):
            print(argument)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
