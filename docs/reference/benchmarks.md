# Benchmarks

Trustcheck publishes a reproducible fixed-input performance and correctness
comparison of `trustcheck scan` against the workflow-pinned `pip-audit 2.10.1`.
The benchmark uses a versioned corpus manifest and the OSV advisory service for
both tools. Only those two command paths contribute timing or correctness
samples. The Trustcheck command explicitly uses `--fast`, limiting it to
advisory lookup and lockfile/requirements parsing for an apples-to-apples
comparison.

The README intentionally carries only a short benchmark pointer. This reference
page and the raw workflow artifact are authoritative for release comparisons.
The fixed-input `--no-deps` numbers do not prove general superiority across
all dependency graphs, policies, indexes, or artifact-inspection modes.

## Latest snapshot

Generated `2026-07-04T12:38:12.871592+00:00` on Python `3.14.6` with
`pip-audit 2.10.1`. Corpus `2026.06` contained 133 entries in that run; this
fixed-input `--no-deps` comparison covered 112 comparable package entries.

| Tool | Cold p50 | Warm p50 | Warm p95 | Peak RSS | Requests p50 | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| trustcheck scan --fast | 16.00 s | 14.20 s | 14.44 s | 78.0 MiB | unknown | 1 |
| pip-audit | 36.69 s | 38.51 s | 39.82 s | 75.6 MiB | unknown | 1 |

Alias-aware agreement was `1.0` across `105` compared packages and `263`
matched advisories. Resolver exact match was `true`: trustcheck and pip-audit
both resolved `22` packages in the dependency-resolution evidence suite.

The corpus is `benchmarks/corpus/corpus.json`. Version `2026.06` contains 135
package entries: 100 mixed clean and historically vulnerable PyPI pins, marker
and extra cases, private-index inputs, pip-tools, PEP 751, uv, Poetry, and PDM
lockfiles, VCS and editable dependencies, intentionally malformed
requirements, and dedicated resolution/profile evidence cases. Direct timing
and correctness use only cases marked `compare_with_pip_audit`.

Comparable requirements cases audit their declared pins directly. Trustcheck
and pip-audit both use `--no-deps`, and pip-audit also uses `--disable-pip`, so
historical releases do not execute build backends or need to resolve into one
compatible environment. The latest snapshot reports direct timing and
correctness for the marked comparable cases.

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

The benchmark workflow runs manually, after the release workflow completes, and
on a weekly schedule. It publishes the raw JSON as a retained workflow artifact
and prints the generated benchmark evidence table into the workflow summary for
maintainer review. Publication requires at least five warm samples per tool, a
signed truth corpus with declared correctness gates, no truth-corpus
regressions, and no one-sided advisory findings.
Release benchmark evidence must record the release tag, release SHA, benchmark
configuration, package version, corpus manifest version, and raw artifact SHA.
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
generation.

## Malicious-package calibration

The `pip-audit` benchmark does not calibrate malicious-package scoring because
it runs `trustcheck scan --fast` and excludes artifact, history, AST, native
binary, and dynamic-analysis heuristics. The seed manifest for that separate
calibration work is `benchmarks/corpus/malicious-calibration.json`.

That manifest is versioned and defines required strata for known malicious PyPI
releases, typo-squats, benign native-extension packages, legitimate packages
that use powerful capabilities, and deliberately weird but harmless academic or
development packages. It is currently marked `seed-unmeasured`; until reviewed
entries and a reproducible runner are published, malicious-package confidence
and false-positive values remain estimated rule priors rather than empirical
measurements.

## Acceptance matrix

The `Acceptance Matrix` workflow is separate from fast pull-request and push
CI. It runs nightly and manually across Linux, macOS, Windows, and every
supported Python version. Each job executes one real `trustcheck scan` case
from `scripts/acceptance_matrix.py` and uploads the rendered report.

The matrix covers selected public packages and corpus fixtures for pip-tools,
uv, Poetry, PDM, PEP 751 `pylock.toml`, extras and markers, private-index
directives, native wheels, and sdists. The private-index fixture accepts the
expected upstream failure for intentionally internal package names but still
requires a rendered report.
