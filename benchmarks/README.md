# trustcheck scan versus pip-audit

The benchmark audits the packages declared in a versioned corpus with
`trustcheck scan` and the latest installed `pip-audit`, using OSV for the
cross-tool advisory comparison. Only those two command paths contribute timing
or correctness samples. Trustcheck always runs with `--fast` so provenance,
artifact, history, and heuristic work is excluded. Comparable requirement cases
run in direct-pin mode
(`--no-deps`, plus pip-audit's `--disable-pip`) so historical pins are measured
independently instead of executing their build backends or requiring them to
form one compatible environment.
The corpus manifest lives at `benchmarks/corpus/corpus.json` and currently
contains 133 package entries across comparable PyPI pins, marker and extra
cases, private-index examples, lockfiles, VCS/editable requirements, hash-pinned
requirements, intentionally malformed inputs, a complete-resolution workload,
and a small provenance/artifact workload.

Only cases marked `compare_with_pip_audit` are included in timing and
correctness samples. Non-comparable cases stay in the corpus so parser,
lockfile, private-index, and fail-closed behavior remain visible and versioned.
Advisories are compared by their full alias sets so a `PYSEC`, `GHSA`, or `CVE`
primary-ID difference is not counted as disagreement.
Correctness uses the detached-signature-verified
`benchmarks/corpus/truth.json`, not the union of tool findings. The truth corpus
versions vulnerable and clean pairs, fixes, withdrawn advisories, markers,
extras, and private-index cases. Its recall and false-positive thresholds are
CI gates.

The raw JSON also publishes separate evidence suites:

- cold-cache and warm-cache p50/p95 wall time
- peak resident memory and tool-reported request samples
- alias-aware advisory recall against the signed curated truth corpus
- complete dependency-resolution package/version set equality
- `standard` provenance and `full` target-artifact inspection work counters

These suites remain separate because provenance and archive inspection have no
equivalent `pip-audit` operation.
Trustcheck request counts come from report diagnostics. `pip-audit` does not
expose an equivalent count, so its request fields are explicitly `null`.

Run:

```bash
python benchmarks/benchmark_against_pip_audit.py \
  --warmups 1 \
  --iterations 3 \
  --output benchmarks/results/latest.json
```

Results include exact commands, tool and platform versions, corpus digest,
selected case metadata, individual cold/warm samples, p50/p95, peak memory,
requests, resolver differences, profile work counters, and unmatched
advisories. Commands that return an accepted exit code but
no output are retried twice by default; retry time remains part of the timing
sample. Network, resolver behavior, and advisory databases change, so compare
results only when the corpus digest, services, and environment are equivalent.

The latest raw result is committed at `benchmarks/results/latest.json` with a
detached `latest.json.sig` verified by `benchmark-public-key.pem`. It records
exact tool versions, OS, Python, cold/warm cache phases, timings, peak RSS,
corpus hashes, and every advisory disagreement. Published tables report the
measurements without making a blanket performance claim.
