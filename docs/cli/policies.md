# Policies

`trustcheck` separates evidence collection from policy enforcement.

That means a report can collect package evidence first, then apply either a built-in or custom policy to decide whether the result should block automation.

## Built-in policies

### `default`

The default profile is advisory. It does not enforce verification or vulnerability blocking by itself.

### `strict`

The strict profile is conservative and is what `--strict` enables.

It sets:

- `require_verified_provenance = "all"`
- `allow_metadata_only = false`
- `vulnerability_mode = "any"`
- `fail_on_severity = "high"`

### `internal-metadata`

This profile is suitable when you intentionally accept metadata-only outcomes and want an informational posture.

## Policy file format

A policy file is a top-level JSON object.

Example:

```json
{
  "profile": "release-gate",
  "require_verified_provenance": "all",
  "allow_metadata_only": false,
  "require_expected_repository_match": true,
  "vulnerability_mode": "kev",
  "fail_on_severity": "medium",
  "suppressions": [
    {
      "id": "CVE-2026-1234",
      "owner": "security@example.com",
      "justification": "Upgrade is scheduled in release 2.4.1.",
      "expires": "2026-06-30"
    }
  ]
}
```

## Supported policy settings

- `profile`: free-form name for reporting
- `require_verified_provenance`: `none` or `all`
- `allow_metadata_only`: `true` or `false`
- `require_expected_repository_match`: `true` or `false`
- `vulnerability_mode`: `ignore`, `any`, `critical`, `kev`, or `fixable`
- `fail_on_severity`: `none`, `medium`, or `high`
- `suppressions`: advisory-ID or alias exceptions with required `owner`,
  `justification`, and ISO `expires`

Vulnerability modes have these meanings:

- `ignore`: collect and report vulnerabilities without blocking
- `any`: block every active, unsuppressed vulnerability
- `critical`: block severity `CRITICAL` or CVSS score `>= 9.0`
- `kev`: block vulnerabilities present in the CISA KEV catalog
- `fixable`: block vulnerabilities with at least one known fixed version

Withdrawn records never block. An active suppression prevents policy blocking
but does not remove the finding from JSON, SARIF, SBOM, VEX, Markdown, or text
output. Date-only expirations remain active through the named UTC date. Expired
suppressions are reported and stop exempting the vulnerability automatically.
The informational `known_vulnerabilities` risk flag remains in the evidence,
but vulnerability modes exclusively control whether vulnerability findings
block policy evaluation.

## CLI overrides

CLI flags can override both built-in policy profiles and policy-file settings.

Example:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --policy-file ./policy.json \
  --fail-on-risk-severity high
```
