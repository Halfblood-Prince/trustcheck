# trustcheck scan versus pip-audit

The benchmark audits the packages declared in a versioned corpus with
`trustcheck scan` and the latest installed `pip-audit`, using OSV for the
cross-tool advisory comparison. Only those two command paths contribute timing
or correctness samples. Trustcheck always runs with `--fast` so provenance,
artifact, history, and heuristic work is excluded. Comparable requirement cases run in direct-pin mode
(`--no-deps`, plus pip-audit's `--disable-pip`) so historical pins are measured
independently instead of executing their build backends or requiring them to
form one compatible environment.
The corpus manifest lives at `benchmarks/corpus/corpus.json` and currently
contains 128 package entries across comparable PyPI pins, marker and extra
cases, private-index examples, lockfiles, VCS/editable requirements, hash-pinned
requirements, and intentionally malformed inputs.

Only cases marked `compare_with_pip_audit` are included in timing and
correctness samples. Non-comparable cases stay in the corpus so parser,
lockfile, private-index, and fail-closed behavior remain visible and versioned.
Advisories are compared by their full alias sets so a `PYSEC`, `GHSA`, or `CVE`
primary-ID difference is not counted as disagreement.

Run:

```bash
python benchmarks/benchmark_against_pip_audit.py \
  --warmups 1 \
  --iterations 3 \
  --output benchmarks/results/latest.json
```

Results include exact commands, tool and platform versions, corpus digest,
selected case metadata, individual timing samples, median and p95 wall time,
and all unmatched advisories. Commands that return an accepted exit code but
no output are retried twice by default; retry time remains part of the timing
sample. Network, resolver behavior, and advisory databases change, so compare
results only when the corpus digest, services, and environment are equivalent.
