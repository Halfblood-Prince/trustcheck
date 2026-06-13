# Malicious-package detection

Trustcheck produces a bounded, explainable heuristic assessment for each
package. It does not declare that a package is malware.

## Metadata and index signals

These checks run during normal inspection:

- Damerau-Levenshtein name similarity against a built-in reference set
- repeatable `--trusted-project NAME` organization-specific references
- public/private and multi-private-index dependency-confusion collisions
- maintainer and author identity changes
- ownership metadata changes
- non-overlapping declared repository changes
- release bursts, cadence acceleration, and releases after long dormancy

Dependency-confusion evidence comes from resolver and Simple Repository checks;
Trustcheck does not guess index collisions from package names alone.

## Python AST analysis

`--inspect-artifacts` parses bounded `.py` members with the standard-library
`ast` module. It detects capabilities including:

- custom setup command registration and install/build hook context
- sensitive environment, credential-file, and keyring access
- HTTP, socket, subprocess, and shell execution calls
- Python and operating-system startup persistence locations
- dynamic execution, decoding, decompression, and deserialization

Individual capabilities are usually low or medium weight. Combinations such as
credential access plus networking, or install-time downloading plus process
execution, receive higher scores. Source is parsed only; it is never imported
or executed.

## Native binary analysis

PE, ELF, and Mach-O members are structurally parsed for:

- target architecture
- imported DLLs, shared objects, and dylibs
- PE certificate-table or Mach-O code-signature load-command presence
- Shannon byte entropy
- embedded PE, ELF, Mach-O, ZIP, and gzip signatures

Signature presence is not signature verification. Trustcheck does not
disassemble, emulate, sandbox, or execute native code.

## Scoring

Findings have their own severity, confidence, and score. Confidence-weighted
scores are combined with diminishing weight and capped at 100:

| Score | Level |
| --- | --- |
| 0 | `none` |
| 1-24 | `low` |
| 25-49 | `elevated` |
| 50-74 | `high` |
| 75-100 | `critical` |

Scores of 25 or higher create the normal
`malicious_package_heuristics` risk flag. Existing policy severity controls can
therefore require review or block high-scoring results.

## Interpretation

These signals deliberately favor explainability over a binary verdict.
Legitimate packages may use networking, subprocesses, encoded resources,
unsigned extension modules, or rapid release automation. Treat findings as
prioritized review evidence and confirm publisher identity, source history,
provenance, and behavior independently.

Every native JSON and industry export preserves the statement:

> These findings are heuristic indicators for review, not proof that the
> package is malicious.
