from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence


def validate_sarif(path: Path) -> set[tuple[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != "2.1.0":
        raise ValueError("SARIF document must use version 2.1.0")
    schema = payload.get("$schema")
    if not isinstance(schema, str) or "sarif-schema-2.1.0.json" not in schema:
        raise ValueError("SARIF document must declare the 2.1.0 schema")
    runs = payload.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("SARIF document must contain exactly one run")
    run = runs[0]
    if not isinstance(run, dict):
        raise ValueError("SARIF run must be an object")
    driver = _mapping(_mapping(run.get("tool"), "tool").get("driver"), "driver")
    if driver.get("name") != "trustcheck":
        raise ValueError("SARIF driver name must be trustcheck")
    rules = driver.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("SARIF driver must declare at least one rule")
    rule_ids = {
        rule.get("id")
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    }
    results = run.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("SARIF run must contain at least one result")

    identities: set[tuple[str, str]] = set()
    for index, result_value in enumerate(results):
        result = _mapping(result_value, f"results[{index}]")
        rule_id = result.get("ruleId")
        if not isinstance(rule_id, str) or rule_id not in rule_ids:
            raise ValueError(f"results[{index}] references an unknown rule")
        message = _mapping(result.get("message"), f"results[{index}].message")
        if not isinstance(message.get("text"), str) or not message["text"].strip():
            raise ValueError(f"results[{index}] must contain message text")
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            raise ValueError(f"results[{index}] must contain a location")
        fingerprints = _mapping(
            result.get("partialFingerprints"),
            f"results[{index}].partialFingerprints",
        )
        fingerprint = fingerprints.get("trustcheck/v1")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError(f"results[{index}] has no stable trustcheck fingerprint")
        identity = (rule_id, fingerprint)
        if identity in identities:
            raise ValueError(f"duplicate SARIF result fingerprint: {rule_id}/{fingerprint}")
        identities.add(identity)
    return identities


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"SARIF {field} must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Trustcheck SARIF and stable GitHub alert fingerprints."
    )
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args(argv)
    fingerprints = validate_sarif(args.sarif)
    if args.compare is not None:
        comparison = validate_sarif(args.compare)
        if fingerprints != comparison:
            raise ValueError("SARIF fingerprints are not stable across equivalent runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
