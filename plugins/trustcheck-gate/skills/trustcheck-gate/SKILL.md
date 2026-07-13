---
name: trustcheck-gate
description: Read-only Trustcheck security gate for AI coding agents including Codex, Claude Code, and Cursor. Use when an agent is about to add, update, install, compare, or recommend Python dependencies; inspect requirements or lock files; verify PyPI release provenance and repository matching; produce Trustcheck JSON, Markdown, SARIF, or SBOM reports; explain Trustcheck findings; or plan dependency remediation without modifying files. The skill routes agents through a strict adapter instead of arbitrary trustcheck shell commands and does not expose package installation, Trustcheck third-party plugin loading, dynamic package execution, unrestricted output paths, or automatic remediation.
---

# Trustcheck Gate

## Overview

Use Trustcheck as the source of truth for Python package security, provenance, malicious-package heuristics, and policy decisions. Interpret the structured results for the user, but do not replace Trustcheck's decision with model judgment.

Always use `scripts/trustcheck_agent_adapter.py` for Trustcheck execution. Do not ask the model to construct raw commands such as `trustcheck <anything>`.

This skill is packaged for Codex (`.codex-plugin/plugin.json`), Claude Code (`.claude-plugin/plugin.json`), and Cursor (`.cursor-plugin/plugin.json`). Keep behavior and safety language agent-neutral.

## Pre-Install Gate

When the user asks to add or update a package:

1. Determine the proposed package name and version from the user's request or the project tooling.
2. Run `check_package` through the adapter before installing anything.
3. Review `classification`, `policy_permits_install`, `findings.blocking_reasons`, vulnerabilities, provenance, risk flags, and malicious-package findings.
4. If `policy_permits_install` is false, do not install. Explain the blocking evidence and recommend safer alternatives or manual review.
5. If `policy_permits_install` is true, still get explicit user approval before modifying dependency files or installing packages.

Example adapter request:

```json
{
  "operation": "check_package",
  "package": "sampleproject",
  "version": "4.0.0",
  "policy": "default",
  "analysis_depth": "standard",
  "with_osv": true
}
```

Use `analysis_depth: "full"` only when the user explicitly opts into advanced artifact analysis; include `advanced_analysis: true`.

## Supported Operations

Use these adapter operations instead of raw CLI flags:

- `scan_project`: Audit supported dependency files in the current workspace.
- `check_package`: Evaluate one package and optional version before installation.
- `check_requirements`: Inspect a requirements or lock file.
- `explain_findings`: Translate a Trustcheck JSON payload into concise actionable findings.
- `plan_remediation`: Produce upgrade recommendations without modifying files.
- `verify_release`: Check provenance, repository matching, release tag evidence, and artifacts.
- `compare_versions`: Compare risk between current and proposed versions.
- `generate_report`: Produce JSON, Markdown, SARIF, CycloneDX, SPDX, or OpenVEX output.

Read `references/operation-schema.md` when constructing non-trivial adapter requests or when a field is unclear.

## Safety Rules

Default to read-only behavior. Scans, package checks, report generation, remediation planning, and provenance verification are allowed.

Require explicit user confirmation before editing requirements, updating lockfiles, installing dependencies, opening pull requests, or applying remediation.

Do not expose or request:

- Arbitrary shell commands or arbitrary Trustcheck CLI flags
- Trustcheck third-party plugin loading
- Custom package index URLs by default
- Shell interpolation
- Unrestricted output paths
- Automatic remediation
- Dynamic package execution

Treat `classification: "scan_failed"` differently from `classification: "security_findings"`. A scan failure means Trustcheck could not complete the assessment; it is not the same thing as a clean package.

## Output Handling

Trustcheck findings should be summarized in plain language, preserving uncertainty for heuristic malicious-package signals. If the adapter reports `policy_permits_install: false`, state that the package or change was not installed and list the strongest evidence from `findings.blocking_reasons`.
