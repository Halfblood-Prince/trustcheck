# Benchmarks

Trustcheck publishes a reproducible performance and correctness comparison of
`trustcheck scan` against the latest installed `pip-audit`. The benchmark uses
a versioned corpus manifest and the OSV advisory service for both tools. Only
those two command paths contribute timing or correctness samples.
The Trustcheck command explicitly uses `--fast`, limiting it to dependency
resolution and advisory lookup for an apples-to-apples comparison.

The corpus is `benchmarks/corpus/corpus.json`. Version `2026.06` contains 128
package entries: 100 mixed clean and historically vulnerable PyPI pins, marker
and extra cases, private-index inputs, pip-tools and TOML lockfiles, VCS and
editable dependencies, and intentionally malformed requirements. Timing and
correctness runs use only cases marked `compare_with_pip_audit`; the remaining
cases are kept as versioned parser and fail-closed coverage.

Comparable requirements cases audit their declared pins directly. Trustcheck
and pip-audit both use `--no-deps`, and pip-audit also uses `--disable-pip`, so
historical releases do not execute build backends or need to resolve into one
compatible environment.

Correctness is alias-aware: advisories match when any normalized `CVE`, `GHSA`,
`PYSEC`, or provider ID overlaps. The raw unmatched records remain in the JSON
result so agreement cannot hide feed or normalization differences.

The scheduled benchmark workflow publishes each run as a workflow artifact.
Local runs default to `benchmarks/results/latest.json`; commit or publish that
file only when it was regenerated from the current corpus and environment.
`pip-audit` exits `1` when it finds vulnerabilities; `trustcheck scan` exits
`0` here because the benchmark intentionally uses its default non-blocking policy.
Commands that return an accepted exit code but no output are retried twice;
the result records this setting and includes retry time in the timing sample.

```bash
python benchmarks/benchmark_against_pip_audit.py
```

Wall-time results include package metadata and advisory requests plus output
generation. The benchmark reports observed performance rather than claiming
feature-equivalent work.
