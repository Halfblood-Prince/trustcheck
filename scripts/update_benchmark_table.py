from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

START_MARKER = "<!-- trustcheck-benchmark:start -->"
END_MARKER = "<!-- trustcheck-benchmark:end -->"
INSTALLATION_HEADING = "## Installation"
MIN_PUBLISHED_WARM_SAMPLES = 5
PUBLISHED_PIP_AUDIT_VERSION = "pip-audit 2.10.1"


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

    _validate_publishable(payload)
    table = _render_table(payload)
    original = readme_path.read_text(encoding="utf-8")
    updated = _replace_block(original, table)
    readme_path.write_text(updated, encoding="utf-8")
    return 0


def _validate_publishable(payload: dict[str, Any]) -> None:
    environment = payload.get("environment")
    if (
        not isinstance(environment, dict)
        or environment.get("pip_audit") != PUBLISHED_PIP_AUDIT_VERSION
    ):
        raise ValueError(
            f"published benchmark must use {PUBLISHED_PIP_AUDIT_VERSION}"
        )

    configuration = payload.get("configuration")
    if (
        not isinstance(configuration, dict)
        or configuration.get("iterations", 0) < MIN_PUBLISHED_WARM_SAMPLES
    ):
        raise ValueError("published benchmark requires at least five warm iterations")

    performance = payload.get("performance")
    if not isinstance(performance, dict):
        raise ValueError("benchmark result is missing performance data")
    for tool in ("trustcheck", "pip_audit"):
        summary = performance.get(tool)
        samples = summary.get("samples_seconds") if isinstance(summary, dict) else None
        if not isinstance(samples, list) or len(samples) < MIN_PUBLISHED_WARM_SAMPLES:
            raise ValueError(f"published benchmark requires five warm {tool} samples")

    corpus = payload.get("corpus")
    truth = payload.get("truth_corpus")
    if not isinstance(corpus, dict) or not isinstance(truth, dict):
        raise ValueError("published benchmark requires corpus and truth summaries")
    truth_cases = truth.get("case_count")
    if not isinstance(truth_cases, int) or truth_cases < 1:
        raise ValueError("published benchmark requires a signed truth corpus")
    gates = truth.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("signed truth corpus must declare correctness gates")

    correctness = payload.get("correctness")
    if not isinstance(correctness, dict):
        raise ValueError("published benchmark requires correctness evidence")
    truth_result = correctness.get("truth")
    if (
        not isinstance(truth_result, dict)
        or not isinstance(truth_result.get("case_count"), int)
        or truth_result["case_count"] < 1
    ):
        raise ValueError("published benchmark requires measured truth-corpus recall")
    if correctness.get("regressions"):
        raise ValueError("published benchmark contains truth-corpus regressions")
    if correctness.get("alias_aware_agreement") != 1.0:
        raise ValueError("published benchmark requires complete advisory agreement")
    if correctness.get("trustcheck_only") or correctness.get("pip_audit_only"):
        raise ValueError("published benchmark contains one-sided advisory findings")


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
    recall = correctness.get("advisory_recall")
    recall = recall if isinstance(recall, dict) else {}
    evidence = payload.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    resolution = evidence.get("dependency_resolution")
    resolution = resolution if isinstance(resolution, dict) else {}
    resolver_correctness = resolution.get("resolver_correctness")
    resolver_correctness = (
        resolver_correctness if isinstance(resolver_correctness, dict) else {}
    )
    matched = correctness.get("matched_advisories")
    packages = correctness.get("packages_compared")
    corpus_version = corpus.get("version") or "unknown"
    corpus_total = corpus.get("package_count") or "unknown"
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
                f"Corpus `{corpus_version}` contains {corpus_total} entries; "
                "this fixed-input `--no-deps` comparison covers "
                f"{corpus_packages} comparable package entries."
            ),
            "",
            (
                "This is useful for vulnerability-feed parity and timing on declared "
                "pins, but it is not a full dependency-resolution benchmark."
            ),
            "",
            "| Tool | Cold p50 | Warm p50 | Warm p95 | Peak RSS | Requests p50 | Recall |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            (
                f"| trustcheck scan --fast | "
                f"{_seconds(_cold_value(trustcheck, 'p50_seconds'))} | "
                f"{_seconds(trustcheck.get('p50_seconds') or trustcheck.get('median_seconds'))} | "
                f"{_seconds(trustcheck.get('p95_seconds'))} | "
                f"{_memory(trustcheck.get('peak_memory_bytes'))} | "
                f"{_number(trustcheck.get('request_count_p50'))} | "
                f"{_number(recall.get('trustcheck'))} |"
            ),
            (
                f"| pip-audit | {_seconds(_cold_value(pip_audit, 'p50_seconds'))} | "
                f"{_seconds(pip_audit.get('p50_seconds') or pip_audit.get('median_seconds'))} | "
                f"{_seconds(pip_audit.get('p95_seconds'))} | "
                f"{_memory(pip_audit.get('peak_memory_bytes'))} | "
                f"{_number(pip_audit.get('request_count_p50'))} | "
                f"{_number(recall.get('pip_audit'))} |"
            ),
            "",
            (
                f"Alias-aware agreement: `{agreement}` across `{packages}` compared "
                f"packages and `{matched}` matched advisories."
            ),
            (
                "Resolver exact match: "
                f"`{resolver_correctness.get('exact_match', 'not measured')}` "
                f"(trustcheck `{resolver_correctness.get('trustcheck_package_count', 'unknown')}`, "
                f"pip-audit `{resolver_correctness.get('pip_audit_package_count', 'unknown')}`)."
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


def _cold_value(performance: dict[str, Any], key: str) -> object:
    cold = performance.get("cold")
    return cold.get(key) if isinstance(cold, dict) else None


def _memory(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{value / (1024 * 1024):.1f} MiB"
    return "unknown"


def _number(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{value:.3f}".rstrip("0").rstrip(".")
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
