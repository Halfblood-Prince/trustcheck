# Exit codes

`trustcheck` is designed to fit into automation as well as interactive review.

- `0`: success
- `1`: upstream PyPI or network failure
- `2`: command usage error
- `3`: invalid or unexpected response, or internal processing failure
- `4`: policy failure triggered by `--strict` or another enforced policy configuration

## Automation guidance

Treat exit code `4` as a policy gate outcome rather than a crash. In CI, this usually means the tool ran correctly and intentionally blocked promotion.
