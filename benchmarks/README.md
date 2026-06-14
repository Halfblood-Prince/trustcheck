# trustcheck versus pip-audit

The benchmark resolves and audits the same pinned requirements with Trustcheck
and `pip-audit`, using OSV for the cross-tool advisory comparison. It records
warm-cache wall time and compares advisories by their full alias sets so a
`PYSEC`, `GHSA`, or `CVE` primary-ID difference is not counted as disagreement.

Run:

```bash
python benchmarks/benchmark_against_pip_audit.py \
  --warmups 1 \
  --iterations 3 \
  --output benchmarks/results/latest.json
```

Results include exact commands, tool and platform versions, corpus digest,
individual timing samples, median and p95 wall time, and all unmatched
advisories. Network and advisory databases change, so compare results only
when the corpus digest, services, and environment are equivalent.
