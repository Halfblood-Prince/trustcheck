# Industry output formats

Trustcheck can render the same collected evidence into multiple standard
documents:

| CLI format | Standard |
| --- | --- |
| `sarif` | SARIF 2.1.0 |
| `cyclonedx-json` | CycloneDX 1.6 JSON |
| `cyclonedx-xml` | CycloneDX 1.6 XML |
| `spdx-json` | SPDX 2.3 JSON |
| `openvex` | OpenVEX 0.2.0 JSON |
| `markdown` | Human-readable Markdown |

Use `--output-file` with `inspect`, `scan`, or `environment`:

```bash
trustcheck scan -f requirements.txt \
  --format sarif \
  --output-file reports/trustcheck.sarif
```

When `--output-file` is present, the report is written as UTF-8 and stdout is
left empty. Parent directories are created automatically. Policy exit codes
are unchanged.

## SARIF

SARIF includes results for:

- known vulnerabilities
- trustcheck risk flags
- policy violations
- artifact verification diagnostics
- artifacts without fully verified provenance
- package scan failures
- malicious-package heuristic findings with confidence, score, evidence, and
  artifact-internal source locations

Every result has a SHA-256 `trustcheck/v1` partial fingerprint derived from
the finding category, package purl, stable finding identity, manifest name,
and declaration line. Messages and timestamps are excluded, so wording and
run-time changes do not churn code-scanning identities.

For dependency files, `physicalLocation` points to the manifest and includes a
best-effort `startLine` for direct declarations. Transitive packages retain
the manifest URI without inventing a declaration line. Package-only
inspection uses the package release URL.

## CycloneDX

CycloneDX JSON and XML use canonical `pkg:pypi` purls as component and
dependency references. Components include trustcheck properties for:

- recommendation and policy status
- policy profile and violations
- provenance status and verified/total artifact counts
- interpreted SLSA signer, source repository and commit, builder, build type,
  workflow reference, materials, action references, and provenance issues
- vulnerabilities and fixed versions
- normalized CVSS ratings and CWE identifiers
- withdrawn status, CISA KEV, FIRST EPSS, and suppression evidence
- every retained lockfile or observed artifact hash
- malicious-package score, level, disclaimer, and individual heuristic
  findings

The vulnerability section links each advisory to affected component refs.
Document serial numbers are deterministic for the exported evidence; metadata
timestamps record generation time.

## SPDX

SPDX output uses version 2.3 JSON. Root reports and inspected dependencies are
packages connected with `DESCRIBES` and `DEPENDS_ON` relationships. Canonical
purls are package-manager external references.

SPDX 2.3 does not define CycloneDX-style arbitrary properties, so trustcheck
evidence is represented through package comments and document annotations.
Those records include vulnerabilities, provenance coverage, interpreted SLSA
source and build evidence, artifact checksums, recommendations, policy
violations, CVSS, CWE, withdrawal, KEV, EPSS, suppression state, and
malicious-package heuristic evidence.

## OpenVEX

Each vulnerability observed for a package produces an OpenVEX statement with
status `affected`. The product uses its canonical purl and available artifact
hashes. When fixed versions are known, the action statement recommends those
versions; otherwise it directs the consumer to vendor mitigation guidance.
Status notes retain KEV, EPSS, and suppression context.

Trustcheck does not infer `not_affected` from the absence of an advisory.
OpenVEX 0.2.0 requires at least one statement, so requesting `openvex` when
no configured source reported a vulnerability returns a data error instead
of emitting a non-conforming or misleading document.

OpenVEX remains vulnerability-focused and does not translate heuristic
malicious-package indicators into vulnerability status statements. Native JSON,
SARIF, CycloneDX, SPDX, and Markdown preserve that evidence.

## Heuristic labeling

Every exported malicious-package indicator is labeled as heuristic and carries
the disclaimer that it is not proof of malware. SARIF emits dedicated
`TC-HEURISTIC-*` rules and stable fingerprints. Artifact source findings use
locations such as `package.whl!/module.py` with a best-effort line number.

## Stability

- SARIF fingerprints are stable across runs and checkout directories.
- The scheduled `SARIF integration` workflow generates a deliberately
  vulnerable fixture twice, validates identical fingerprints, and performs a
  real upload to GitHub code scanning under a dedicated category.
- CycloneDX serial numbers, SPDX namespaces, OpenVEX document IDs, package
  purls, and statement IDs are deterministic for equivalent evidence.
- Generation timestamps are intentionally current and are not identity inputs.
- The native trustcheck JSON envelope remains the lossless interface; standard
  formats expose the fields representable by each specification.
