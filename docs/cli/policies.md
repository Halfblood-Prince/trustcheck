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
  "vulnerability_mode": "any",
  "fail_on_severity": "medium"
}
```

## Supported policy settings

- `profile`: free-form name for reporting
- `require_verified_provenance`: `none` or `all`
- `allow_metadata_only`: `true` or `false`
- `require_expected_repository_match`: `true` or `false`
- `vulnerability_mode`: `ignore` or `any`
- `fail_on_severity`: `none`, `medium`, or `high`

## CLI overrides

CLI flags can override both built-in policy profiles and policy-file settings.

Example:

```bash
trustcheck inspect sampleproject \
  --version 4.0.0 \
  --policy-file ./policy.json \
  --fail-on-risk-severity high
```
