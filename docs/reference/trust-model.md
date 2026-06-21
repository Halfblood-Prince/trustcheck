# Trust model and repository matching

`trustcheck` does not treat project metadata alone as proof of origin.

The strongest result comes from verified provenance bound to the exact artifact digest that was downloaded. Repository URLs and publisher identity hints are useful context, but they are not equivalent to a cryptographically verified attestation.

## What the report means

That distinction is reflected in the report:

- metadata can support an explanation
- verified provenance can support a trust decision
- missing or unverifiable provenance drives risk flags and strict-policy failures

In particular, a complete absence of published provenance is treated as a weaker trust posture that typically warrants review, while invalid provenance or stronger inconsistencies remain higher-severity concerns.

Recommendation tiers are documented in more detail in [Recommendation model](recommendations.md), but the core outcomes are:

- `verified`: every discovered release artifact verified successfully
- `metadata-only`: no cryptographically verified artifact set, but no higher-severity risk flags were raised
- `review-required`: medium-severity issues require manual review
- `high-risk`: high-severity issues were detected

## SLSA provenance interpretation

For `https://slsa.dev/provenance/v1` statements, successful envelope and
artifact verification is only the first step. Trustcheck also interprets and
validates:

- `buildDefinition.buildType`
- untrusted `externalParameters`, including workflow repository, path, and ref
- `resolvedDependencies`, selecting the source repository material and
  requiring its full git commit digest
- `runDetails.builder.id` and invocation metadata
- agreement between source material, workflow, Trusted Publisher repository,
  and Trusted Publisher workflow

For the GitHub Actions workflow build type, the publisher and builder must be
consistent with GitHub. A source repository, workflow path, or immutable
workflow commit contradiction invalidates verification.

Mutable workflow references, missing workflow revisions, weak auxiliary
material digests, and action references not pinned to full commits remain
explicit review findings. They indicate a weaker or less reproducible build,
not proof that the artifact is malicious.

Trustcheck applies the same rule to itself: external workflow Actions are
pinned to full commits, and the reusable Action installs a hash-locked runtime
and build dependency set. Release builds validate wheel and sdist metadata
against the stable release tag before publication.

Verified sdists and wheels are compared on repository, workflow, builder,
source commit, and build type. Release history separately records changes in
signer, repository, workflow, builder, source commit, and build type. A source
commit normally changes between releases, so commit drift is retained as
evidence without automatically creating a risk flag.

Policies can restrict verified publishers to organization-owned repositories:

```bash
trustcheck inspect sampleproject \
  --trusted-publisher-organization github:pypa
```

Entries may be unscoped (`pypa`) or provider-scoped (`github:pypa`,
`gitlab:group/subgroup`). Every verified publisher identity must match the
configured allowlist.

## Repository matching rules

Repository matching is intentionally strict.

`trustcheck` currently normalizes and matches canonical repository roots for supported forges:

- GitHub
- GitLab

It accepts canonical repository URLs and equivalent git-style remotes, and rejects non-repository pages such as profile, organization, documentation, or archive URLs.

Invalid `--expected-repo` values are reported explicitly as a risk condition rather than being matched loosely.

## Diagnostics and upstream instability

`trustcheck` distinguishes package risk from upstream instability. The machine-readable `diagnostics` block is included so automation can tell whether a failure came from policy, verification, or PyPI and network behavior.

Diagnostics include:

- request failures with deterministic `code` and `subcode`
- retry counts and total request counts
- cache hit counts
- artifact-level provenance or verification failures
- effective network settings such as timeout, retry count, backoff, offline mode, and cache directory

Common upstream subcodes include:

- `http_not_found`
- `http_transient`
- `network_timeout`
- `network_dns_temporary`
- `network_dns_failure`
- `network_tls`
- `network_connection_refused`
- `json_malformed`
- `project_shape_invalid`
- `provenance_shape_invalid`
- `offline_cache_miss`

For configuration details, see [Config and offline mode](../cli/configuration.md).

## Dependency inspection

When `--with-deps`, `--with-transitive-deps`, `include_dependencies=True`, or `include_transitive_dependencies=True` is used, `trustcheck` extends the trust model from a single release to the package's declared runtime dependency set.

Dependency inspection currently works by:

- reading `requires_dist` metadata from the selected release
- evaluating environment markers before inspection
- using exact versions supplied by a supported lockfile or `locked_versions` mapping when available
- otherwise resolving a complete compatible dependency set through pip
- inspecting either direct dependencies only or the full transitive tree, depending on the selected mode
- summarizing the highest-risk dependency outcome in the top-level report

The dependency view is flattened in the report for operator readability and automation. The `depth`, `parent_project`, and `parent_version` fields preserve traversal context.

`trustcheck scan` ingests exact versions from hashed requirements files,
PEP 751 `pylock.toml`, `Pipfile.lock`, pip-tools output, `uv.lock`,
`poetry.lock`, and `pdm.lock`. When dependency traversal is enabled, those
locked versions are retained for direct and transitive packages. Recorded
artifact hashes are verified before provenance evaluation.

When multiple indexes are configured, every resolved normalized project name
is queried separately on each index. A name present on both a private and
public index is treated as a dependency-confusion risk and blocks the scan
unless the operator explicitly allows it. Allowing the collision does not
remove it from combined JSON.

## Artifact content inspection

`--inspect-artifacts` adds static inspection of downloaded wheel and sdist
archives. The inspector does not extract archives to disk, import modules, call
entry points, or execute package code.

Wheel checks include:

- secure hash and size validation for every file listed in `RECORD`
- detection of files missing from `RECORD` or listed but absent from the wheel
- console-script listing and suspicious target detection
- native extension detection
- AST analysis of every bounded Python source file
- suspicious credential, network, subprocess, persistence, install-hook, and
  obfuscation capability detection
- PE, ELF, and Mach-O import, architecture, embedded-signature-presence,
  entropy, and embedded-payload inspection
- unexpected top-level file reporting
- `METADATA` Name, Version, and Requires-Dist comparison

Sdist checks include:

- suspicious install or executable script indicators
- AST analysis with elevated weighting for install and build-hook contexts
- oversized, unusual, nested-archive, and special-member reporting
- `PKG-INFO` metadata comparison with the selected release and wheel metadata

An invalid wheel `RECORD` or metadata mismatch is high-risk. Native code and
suspicious executable entry points are medium-severity findings that require
review rather than being treated as automatically high-risk.

Normal package inspection also scores project-name similarity against a
built-in trusted-name set, configured `--trusted-project` names, cross-index
dependency-confusion collisions, maintainer and ownership changes, repository
changes, release bursts, cadence acceleration, and releases after dormancy.

All of these findings are heuristics. A score raises review priority and can
feed normal risk policy, but it is not a malware classification and must not be
presented as proof that a publisher or package is malicious.

## Limitations

- PyPI metadata quality varies by project
- some projects do not publish provenance at all
- repository matching currently supports canonical GitHub and GitLab URLs only
- lockfile scans consume the recorded resolution; requirements and project
  inputs run pip's complete resolver. The default `--sandbox auto` mode uses an
  enforced sandbox or falls back to strict wheel-only resolution. `warn` is an
  explicit compatibility mode that can execute build-backend metadata hooks
- resolver containers and Bubblewrap namespaces retain network access to
  configured package indexes. They expose staged resolver inputs and necessary
  local dependency directories, not the project workspace; they constrain host
  filesystem, environment, identity, capability, and process access rather
  than providing an offline execution boundary
- versionless source trees cannot be represented as package-release audits and
  are reported as unsupported
- private Simple Repository indexes do not necessarily publish Warehouse
  provenance or vulnerability metadata, so those evidence fields may remain
  unavailable even when source and hash checks succeed
- artifact inspection is static and cannot prove that arbitrary source code is safe
- native binaries are structurally parsed but are not disassembled, emulated,
  dynamically executed, or guaranteed to have valid signatures merely because
  an embedded signature record is present
- provenance verification may depend on local environment support required by underlying tooling
- text output is intentionally concise and may omit low-level detail unless `--verbose` is used
