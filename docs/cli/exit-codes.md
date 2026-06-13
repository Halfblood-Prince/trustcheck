# Exit codes

`trustcheck` is designed to fit into automation as well as interactive review.

- `0`: success
- `1`: upstream PyPI or network failure
- `2`: command usage error
- `3`: invalid or unexpected response, or internal processing failure
- `4`: policy failure triggered by `--strict` or another enforced policy configuration
- `5`: remediation was blocked, could not prove minimality, or failed validation

## Automation guidance

Treat exit code `4` as a policy gate outcome rather than a crash. In CI, this usually means the tool ran correctly and intentionally blocked promotion.

Exit code `5` means no dependency bytes were accepted. Common causes include
an excluded secure release, an immutable VCS or local dependency, a missing
native locker, search-limit exhaustion, a stale input digest, or a generated
lockfile that failed the final rescan.

This also applies to `trustcheck inspect --cve`: the command can print only vulnerability records while still returning `4` when policy settings such as `--fail-on-vulnerability any` block the release.
