# Benchmarks

Trustcheck publishes a reproducible performance and correctness comparison of
`trustcheck scan` against the workflow-pinned `pip-audit 2.10.1`. The benchmark uses
a versioned corpus manifest and the OSV advisory service for both tools. Only
those two command paths contribute timing or correctness samples.
The Trustcheck command explicitly uses `--fast`, limiting it to dependency
resolution and advisory lookup for an apples-to-apples comparison.

The corpus is `benchmarks/corpus/corpus.json`. Version `2026.06` contains 133
package entries: 100 mixed clean and historically vulnerable PyPI pins, marker
and extra cases, private-index inputs, pip-tools and TOML lockfiles, VCS and
editable dependencies, intentionally malformed requirements, and dedicated
resolution/profile evidence cases. Direct timing and correctness use only cases
marked `compare_with_pip_audit`.

Comparable requirements cases audit their declared pins directly. Trustcheck
and pip-audit both use `--no-deps`, and pip-audit also uses `--disable-pip`, so
historical releases do not execute build backends or need to resolve into one
compatible environment.

Correctness is alias-aware: advisories match when any normalized `CVE`, `GHSA`,
`PYSEC`, or provider ID overlaps. The raw unmatched records remain in the JSON
result so agreement cannot hide feed or normalization differences.
Recall is measured against the signed `benchmarks/corpus/truth.json`, which
contains independently curated vulnerable and clean package-version pairs,
aliases, fixed versions, withdrawals, markers, extras, and private-index cases.
`truth.json.sig` is verified with the checked-in public key before a benchmark
runs. The manifest's minimum recall and maximum false-positive gates make the
benchmark exit nonzero on a Trustcheck regression.

Separate evidence suites publish complete dependency resolution and Trustcheck
`standard`/`full` profile results. Every suite records cold-cache and warm-cache
p50/p95, peak RSS, request samples where the tool reports them, and exact
commands. Resolution evidence compares complete package/version sets. Advisory
recall uses the signed curated truth corpus as its reference. Profile evidence
records how many artifacts had provenance,
verification, static inspection, native analysis, and heuristic findings.
Trustcheck request counts come from report diagnostics; `pip-audit` request
counts are `null` because the tool does not expose that measurement.

The scheduled benchmark workflow publishes the raw JSON as a retained workflow
artifact and proposes the generated README evidence table through a pull request.
Publication requires at least five warm samples per tool, a complete signed
truth case for every comparable package entry, no incomplete advisory sets,
and a minimum recall gate of `1.0`.
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
