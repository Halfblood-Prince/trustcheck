from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

START_MARKER = "<!-- trustcheck-benchmark:start -->"
END_MARKER = "<!-- trustcheck-benchmark:end -->"
INSTALLATION_HEADING = "## Installation"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Update the README benchmark table from a benchmark JSON result."
    )
    parser.add_argument("result", help="Path to benchmarks/results/latest.json.")
    parser.add_argument("--readme", default="README.md")
    args = parser.parse_args(argv)

    result_path = Path(args.result)
    readme_path = Path(args.readme)
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("benchmark result must be a JSON object")

    table = _render_table(payload)
    original = readme_path.read_text(encoding="utf-8")
    updated = _replace_block(original, table)
    readme_path.write_text(updated, encoding="utf-8")
    return 0


def _render_table(payload: dict[str, Any]) -> str:
    generated_at = str(payload.get("generated_at") or "unknown")
    environment = payload.get("environment")
    corpus = payload.get("corpus")
    performance = payload.get("performance")
    correctness = payload.get("correctness")
    if not isinstance(environment, dict):
        environment = {}
    if not isinstance(corpus, dict):
        corpus = {}
    if not isinstance(performance, dict):
        raise ValueError("benchmark result is missing performance data")
    if not isinstance(correctness, dict):
        correctness = {}

    trustcheck = _tool_performance(performance, "trustcheck")
    pip_audit = _tool_performance(performance, "pip_audit")
    agreement = correctness.get("alias_aware_agreement")
    matched = correctness.get("matched_advisories")
    packages = correctness.get("packages_compared")
    corpus_version = corpus.get("version") or "unknown"
    corpus_packages = corpus.get("benchmark_package_count") or corpus.get("package_count")

    return "\n".join(
        [
            START_MARKER,
            "## Latest benchmark",
            "",
            (
                f"Generated `{generated_at}` on Python "
                f"`{environment.get('python', 'unknown')}` with "
                f"`{environment.get('pip_audit', 'pip-audit unknown')}`. "
                f"Corpus `{corpus_version}` covered {corpus_packages} comparable "
                "package entries."
            ),
            "",
            "| Tool | Median | p95 | Vulnerable packages |",
            "| --- | ---: | ---: | ---: |",
            (
                f"| trustcheck scan | {_seconds(trustcheck.get('median_seconds'))} | "
                f"{_seconds(trustcheck.get('p95_seconds'))} | "
                f"{correctness.get('trustcheck_vulnerable_packages', 'unknown')} |"
            ),
            (
                f"| pip-audit | {_seconds(pip_audit.get('median_seconds'))} | "
                f"{_seconds(pip_audit.get('p95_seconds'))} | "
                f"{correctness.get('pip_audit_vulnerable_packages', 'unknown')} |"
            ),
            "",
            (
                f"Alias-aware agreement: `{agreement}` across `{packages}` compared "
                f"packages and `{matched}` matched advisories."
            ),
            END_MARKER,
            "",
        ]
    )


def _tool_performance(
    performance: dict[str, Any],
    tool: str,
) -> dict[str, Any]:
    payload = performance.get(tool)
    if not isinstance(payload, dict):
        raise ValueError(f"benchmark result is missing {tool} performance data")
    return payload


def _seconds(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{value:.2f} s"
    return "unknown"


def _replace_block(readme: str, block: str) -> str:
    if START_MARKER in readme or END_MARKER in readme:
        start = readme.find(START_MARKER)
        end = readme.find(END_MARKER)
        if start == -1 or end == -1 or end < start:
            raise ValueError("README benchmark markers are unbalanced")
        end += len(END_MARKER)
        return readme[:start] + block.rstrip() + readme[end:]

    installation = readme.find(INSTALLATION_HEADING)
    if installation == -1:
        raise ValueError(f"README is missing {INSTALLATION_HEADING!r}")
    prefix = readme[:installation].rstrip()
    suffix = readme[installation:].lstrip()
    return f"{prefix}\n\n{block}{suffix}"


if __name__ == "__main__":
    raise SystemExit(main())
