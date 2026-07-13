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

## Resource isolation

Artifact responses are streamed with a 128 MiB per-response cap and a 512 MiB
aggregate retained-download cap per scan. Before any archive member is read,
inspection rejects archives with more than 10,000 members, more than 256 MiB of
declared expansion, or a compression ratio above 200 for expansions of at
least 10 MiB.

Built-in deep inspection runs in a spawned process with a 20-second wall-clock
deadline. On POSIX, that worker also receives a 15-second CPU limit, a 512 MiB
address-space limit, and drops root privileges to `nobody`. Other platforms
still receive process and wall-clock isolation plus the format and byte caps.

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

## Bounded install analysis

!!! warning "Experimental"

    Bounded install analysis executes untrusted build and install hooks in a
    constrained container. Treat it as behavior evidence from an installation
    probe, not as proof that a package is safe.

`--dynamic-analysis` is deliberately separate from the static archive, AST, and
native-binary checks. It runs a sandboxed installation probe for downloaded
artifacts in a disposable Docker container, so it is never enabled by default.

The container is started with:

- `--network none`
- a non-root `65534:65534` user
- dropped Linux capabilities and `no-new-privileges`
- a read-only root filesystem plus a temporary `/tmp`
- one CPU, a 10-second CPU ulimit, 512 MiB RAM, a 128-process limit, and a
  30-second wall-clock timeout

The runner records separate phases for archive validation, metadata
preparation, wheel build, wheel installation, and skipped optional import or
entry-point probes. Failures are classified as backend unavailable, metadata
invalid, build failed, install hook failed, policy blocked, timed out,
unsupported, inconclusive, or suspicious behavior when evidence supports it.

Analyzer images are digest-pinned. Trustcheck-controlled image definitions live
in `packaging/dynamic-analyzers/` and prebuild common backend wheels so analysis
can run with `--no-index`. `--dynamic-python` selects Python 3.11, 3.12, 3.13,
or 3.14; profiles without a configured digest-pinned image fail as unsupported
instead of silently reusing another Python version. `--dynamic-image` can supply
an explicit digest-pinned image.

Behavioral evidence is best-effort. The Python audit hook records child
processes, executable paths, subprocess arguments, writes, attempted network
connections, credential-path access, persistence-like paths, and environment
changes where supported. It is evidence collection, not an unbypassable security
boundary. Inconclusive analysis never counts as a clean pass.

## Scoring

Findings have their own severity, estimated confidence, rule version, estimated
false-positive prior, and score. These values are rule metadata and estimates,
not statistically validated measurements. The native JSON field is still named
`false_positive_rate` for schema compatibility, but it is presented as an
estimate until a measured calibration benchmark is published.
Confidence-weighted scores are combined with diminishing weight and capped at 100:

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

Custom policy files can tune `malicious_package_thresholds` for aggregate
`low`, `elevated`, `high`, and `critical` bands, and
`malicious_rule_thresholds` for per-rule score contribution thresholds. For
example, setting `"malicious_rule_thresholds": {"native_signature_absent": 100}`
keeps unsigned native binaries in the report while preventing that weak signal
from contributing to the aggregate score.

## Evaluation status

Trustcheck does not yet publish the reviewed artifacts or benchmark results
needed to call these rates measured. The seed manifest at
`benchmarks/corpus/malicious-calibration.json` defines the required versioned
corpus strata and metric contract, and is deliberately marked
`seed-unmeasured`.

The next security milestone is to populate that corpus with:

- known malicious PyPI releases
- typo-squats and dependency-confusion cases
- benign packages with native extensions
- legitimate packages that use subprocesses, networking, obfuscation or
  generated code, plugins, keyrings, custom installers, or build hooks
- deliberately weird but harmless academic and development packages

Once populated, the published benchmark must report per-rule precision, recall,
false-positive rate, 95% confidence intervals, and score-band performance.
Until then, Trustcheck treats every confidence value and false-positive number
as an estimated rule prior, not an empirical measurement.

## Interpretation

These signals deliberately favor explainability over a binary verdict.
Legitimate packages may use networking, subprocesses, encoded resources,
unsigned extension modules, or rapid release automation. Treat findings as
prioritized review evidence and confirm publisher identity, source history,
provenance, and behavior independently.

Every native JSON and industry export preserves the statement:

> These findings are heuristic indicators for review, not proof that the
> package is malicious.
