from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess  # nosec B404
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping, Sequence

from .exports import render_payload_export
from .lockfiles import is_supported_lockfile

SKIP_DIRECTORIES = {".git", ".tox", ".venv", "build", "dist", "node_modules", "venv"}


def discover_dependency_files(root: Path) -> tuple[Path, ...]:
    resolved = root.resolve()
    discovered: list[Path] = []
    for path in resolved.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in path.relative_to(resolved).parts):
            continue
        if not path.is_file():
            continue
        name = path.name.lower()
        if (
            is_supported_lockfile(path)
            or name == "pyproject.toml"
            or (name.startswith("requirements") and path.suffix.lower() in {".txt", ".in"})
        ):
            discovered.append(path)
    return tuple(sorted(discovered, key=lambda item: item.relative_to(resolved).as_posix()))


def _policy_for(path: Path, root: Path, overrides: Mapping[str, str]) -> str | None:
    relative = path.relative_to(root).as_posix()
    matches = [
        (pattern, policy)
        for pattern, policy in overrides.items()
        if fnmatch.fnmatch(relative, pattern)
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item[0]))[1]


def _issue_fingerprints(payload: Mapping[str, Any]) -> set[str]:
    fingerprints: set[str] = set()
    reports = payload.get("reports", [])
    if not isinstance(reports, list):
        return fingerprints
    for report in reports:
        if not isinstance(report, dict):
            continue
        project = str(report.get("project") or "")
        version = str(report.get("version") or "")
        vulnerabilities = report.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:
                if isinstance(item, dict):
                    fingerprints.add(
                        _stable_issue("vulnerability", project, version, item.get("id"))
                    )
        policy = report.get("policy", {})
        violations = policy.get("violations", []) if isinstance(policy, dict) else []
        if isinstance(violations, list):
            for item in violations:
                if isinstance(item, dict):
                    fingerprints.add(_stable_issue("policy", project, version, item.get("code")))
    return fingerprints


def _stable_issue(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()


def _normalize_sources(payload: dict[str, Any], root: Path) -> None:
    resolved = payload.get("resolved", [])
    if not isinstance(resolved, list):
        return
    for item in resolved:
        if not isinstance(item, dict) or not isinstance(item.get("source_file"), str):
            continue
        source_file = item["source_file"]
        windows_path = PureWindowsPath(source_file)
        if windows_path.is_absolute() and not Path(source_file).is_absolute():
            item["source_file"] = windows_path.name
            continue
        try:
            item["source_file"] = Path(source_file).resolve().relative_to(root).as_posix()
        except ValueError:
            item["source_file"] = Path(source_file).name


def scan_workspace(
    root: Path,
    *,
    policy_overrides: Mapping[str, str] = {},
    offline: bool = False,
) -> tuple[dict[str, Any], int]:
    root = root.resolve()
    aggregate: dict[str, Any] = {
        "schema": "urn:trustcheck:workspace:1.0.0",
        "workspace": root.name,
        "file": ".",
        "dependency_files": [],
        "reports": [],
        "failures": [],
        "resolved": [],
    }
    exit_code = 0
    for path in discover_dependency_files(root):
        relative = path.relative_to(root).as_posix()
        command = [
            sys.executable,
            "-m",
            "trustcheck",
            "scan",
            "--file",
            str(path),
            "--fast",
            "--format",
            "json",
            "--with-osv",
        ]
        policy = _policy_for(path, root, policy_overrides)
        if policy:
            command.extend(["--policy-file", policy])
        if offline:
            command.append("--offline")
        completed = subprocess.run(  # nosec B603
            command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        exit_code = max(exit_code, completed.returncode)
        if not completed.stdout.strip():
            aggregate["failures"].append({"file": relative, "message": completed.stderr.strip()})
            continue
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict):
            raise ValueError(f"scan output for {relative} is not an object")
        _normalize_sources(payload, root)
        aggregate["dependency_files"].append(
            {"path": relative, "policy": policy, "exit_code": completed.returncode}
        )
        for key in ("reports", "failures", "resolved"):
            values = payload.get(key, [])
            if isinstance(values, list):
                aggregate[key].extend(values)
    fingerprints = sorted(_issue_fingerprints(aggregate))
    aggregate["issue_fingerprints"] = fingerprints
    return aggregate, exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate Trustcheck scans across a monorepo.")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument("--output-file")
    parser.add_argument("--baseline")
    parser.add_argument("--policy-overrides", help="JSON mapping of workspace glob to policy file.")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    overrides: dict[str, str] = {}
    if args.policy_overrides:
        raw = json.loads(Path(args.policy_overrides).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in raw.items()
        ):
            parser.error("--policy-overrides must contain a string-to-string JSON object")
        overrides = raw
    payload, exit_code = scan_workspace(
        Path(args.root), policy_overrides=overrides, offline=args.offline
    )
    previous: set[str] = set()
    previous_sarif: set[str] = set()
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        if isinstance(baseline, dict) and isinstance(baseline.get("issue_fingerprints"), list):
            previous = {str(item) for item in baseline["issue_fingerprints"]}
        if isinstance(baseline, dict) and isinstance(baseline.get("runs"), list):
            for run in baseline["runs"]:
                results = run.get("results", []) if isinstance(run, dict) else []
                for result in results if isinstance(results, list) else []:
                    partial = (
                        result.get("partialFingerprints", {})
                        if isinstance(result, dict)
                        else {}
                    )
                    fingerprint = (
                        partial.get("trustcheck/v1")
                        if isinstance(partial, dict)
                        else None
                    )
                    if isinstance(fingerprint, str):
                        previous_sarif.add(fingerprint)
    current = set(payload["issue_fingerprints"])
    payload["baseline"] = {
        "new": sorted(current - previous),
        "unchanged": sorted(current & previous),
        "resolved": sorted(previous - current),
    }
    if args.format == "sarif":
        rendered = render_payload_export("sarif", payload)
        sarif = json.loads(rendered)
        for result in sarif.get("runs", [{}])[0].get("results", []):
            partial = result.get("partialFingerprints", {})
            fingerprint = partial.get("trustcheck/v1")
            result["baselineState"] = (
                "unchanged" if fingerprint in previous_sarif else "new"
            )
        rendered = json.dumps(sarif, indent=2, sort_keys=True) + "\n"
    else:
        rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output_file:
        Path(args.output_file).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
