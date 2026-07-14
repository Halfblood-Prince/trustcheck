# Limitations and Data Flows

Trustcheck is designed to collect evidence and enforce policy. It does not
prove that a package is safe.

## Result Meanings

- Clean or verified means the configured checks completed and no configured
  policy violation was found.
- Blocked means Trustcheck completed enough work to make a policy decision and
  intentionally refused promotion, installation, or merge.
- Failed means Trustcheck could not complete a required check, parse required
  data, contact a required source, validate a required schema, or render the
  requested output.
- Inconclusive means a bounded or optional analysis could not produce enough
  evidence. Inconclusive analysis must not be treated as a clean result.

## General Limitations

- Network-dependent checks may be unavailable because PyPI, OSV, Ecosyste.ms,
  Sigstore, TUF, or a private index is unreachable.
- Advisory sources may be incomplete, late, withdrawn, duplicated, or disagree
  on aliases and fixed versions.
- Provenance absence is not automatically proof of maliciousness. It is
  evidence quality loss that policy may choose to block.
- Static analysis cannot guarantee safety. Archive, AST, and native-binary
  inspection can find suspicious structures, but cannot prove that code is
  harmless.
- Bounded install analysis is experimental. It runs in a constrained container,
  may be inconclusive, and may miss behavior that requires different inputs,
  platforms, network access, credentials, or runtime paths.
- Third-party Trustcheck plugins remain opt-in and experimental until final
  release validation keeps the IPC and installed-code binding regressions green.

## Command Data Flows

### `trustcheck inspect`

- Local files read: configuration files, optional policy files, optional plugin
  configuration, cache entries, and Sigstore/TUF state.
- External services contacted: PyPI Simple/JSON/project pages, PyPI
  provenance, Sigstore/TUF roots, OSV or other advisory sources when enabled,
  and configured package indexes.
- Artifacts downloaded: release files selected for provenance, hash, static
  inspection, dynamic analysis, or dependency evidence.
- Data retained: optional HTTP/advisory cache entries, report files requested
  by `--output-file`, and optional advisory snapshots.
- Reports generated: text, JSON, SARIF, CycloneDX, SPDX, OpenVEX, or Markdown.

### `trustcheck scan`

- Local files read: requirements files, constraints, `pyproject.toml`,
  supported lockfiles, policy/config files, resume state, and optional advisory
  snapshots.
- External services contacted: package indexes for resolver metadata, PyPI and
  advisory services for package evidence, and Sigstore/TUF roots when
  provenance is inspected.
- Artifacts downloaded: only when provenance, artifact inspection, dynamic
  analysis, or policy requires artifact evidence.
- Data retained: optional cache entries, resume state, advisory snapshots,
  remediation artifacts, and requested reports.
- Reports generated: per-package reports, aggregate scan reports, remediation
  plans, SARIF, SBOMs, and policy summaries.

### `trustcheck install`

- Local files read: requirements or package specifiers, policy/config files,
  constraints, and optional lock inputs.
- External services contacted: configured package indexes, PyPI/provenance
  endpoints, advisory sources, and Sigstore/TUF roots required by policy.
- Artifacts downloaded: candidate wheels and source artifacts needed to prove
  and perform the install.
- Data retained: a temporary verified wheelhouse during execution, optional
  lock/report/attestation evidence, and cache entries.
- Reports generated: verification reports and install evidence. Pip is invoked
  with `--no-index --find-links` against the verified local wheelhouse.

### `trustcheck diff`

- Local files read: base/head dependency files, Git refs or checkout files,
  optional trust manifests, policy/config files, and optional previous reports.
- External services contacted: package indexes, PyPI/provenance endpoints,
  advisory sources, and GitHub only when PR commenting is explicitly enabled.
- Artifacts downloaded: evidence for packages whose resolved version, source,
  or index origin changed.
- Data retained: requested reports, optional PR comments, and cache entries.
- Reports generated: changed-package trust diffs, Markdown review comments,
  JSON, SARIF, and manifest violation summaries.

### `trustcheck manifest`

- Local files read: dependency files, manifest JSON, policy/config files, and
  optional lock or source manifests.
- External services contacted: the same package, provenance, index, and
  advisory sources needed to refresh or verify approved evidence.
- Artifacts downloaded: artifacts required by the selected manifest policy.
- Data retained: manifest updates only when `update` is requested; verification
  does not mutate the manifest.
- Reports generated: manifest verification/update summaries and machine-
  readable issue lists.

### `trustcheck environment`

- Local files read: installed distribution metadata from the active interpreter
  or supplied `site-packages` paths, policy/config files, and optional cache.
- External services contacted: PyPI, provenance, and advisory services needed
  to evaluate installed package versions.
- Artifacts downloaded: only when artifact or provenance checks require them.
- Data retained: requested reports and cache entries.
- Reports generated: installed-environment trust reports.

### `trustcheck impact`

- Local files read: dependency files or reports, source tree files selected for
  static import analysis, policy/config files, and optional cache.
- External services contacted: advisory and package evidence sources needed to
  build vulnerable package reports.
- Artifacts downloaded: package artifacts only when selected scan options need
  artifact evidence.
- Data retained: requested reports and cache entries.
- Reports generated: impact triage reports that distinguish direct,
  transitive, test-only, development-only, unobserved, and unknown usage.

### `trustcheck doctor`

- Local files read: cache paths, Python environment metadata, Sigstore/TUF state
  directories, and optional configuration.
- External services contacted: none.
- Artifacts downloaded: none.
- Data retained: none beyond an explicitly requested output file.
- Reports generated: local prerequisite diagnostics.

### TrustCheck Package Scanner Action

- Local files read: checkout files matching the selected `target`, policy
  files, optional plugin configuration, and the action's locked dependency set.
- External services contacted: the same services as the invoked CLI command.
- Artifacts downloaded: the CLI report artifact and optional remediation patch
  bundle are uploaded to GitHub Actions artifacts.
- Data retained: GitHub stores uploaded artifacts and step outputs according to
  workflow retention settings. Trustcheck does not run a hosted service.
- Reports generated: one requested report artifact. The action asks the CLI for
  JSON internally, then renders the selected artifact format.
