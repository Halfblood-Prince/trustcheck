# Benchmarks

Trustcheck publishes a reproducible performance and correctness comparison
against `pip-audit`. The benchmark uses the same pinned input and OSV advisory
service for both tools.

Correctness is alias-aware: advisories match when any normalized `CVE`, `GHSA`,
`PYSEC`, or provider ID overlaps. The raw unmatched records remain in the JSON
result so agreement cannot hide feed or normalization differences.

The checked-in result is
[`benchmarks/results/latest.json`](https://github.com/Halfblood-Prince/trustcheck/blob/main/benchmarks/results/latest.json).
The scheduled benchmark workflow also publishes each run as a workflow
artifact.

## Latest measured result

Measured June 14, 2026 on CPython 3.14.5 and Windows 11, comparing the current
Trustcheck development build with `pip-audit 2.10.0`:

| Tool | Median | p95 | Vulnerable packages |
| --- | ---: | ---: | ---: |
| Trustcheck | 15.03 s | 18.02 s | 3 |
| pip-audit | 43.97 s | 44.21 s | 3 |

The alias-aware advisory comparison matched all 12 deduplicated advisories:
agreement `1.0`, with no Trustcheck-only or pip-audit-only findings. The raw
file contains all samples and identifiers. `pip-audit` exits `1` when it finds
vulnerabilities; Trustcheck exits `0` here because the benchmark intentionally
uses its default non-blocking policy.

```bash
python benchmarks/benchmark_against_pip_audit.py
```

Wall-time results include dependency resolution, metadata and advisory
requests, and output generation. Trustcheck performs broader provenance and
supply-chain analysis than `pip-audit`, so the benchmark reports observed
performance rather than claiming feature-equivalent work.
