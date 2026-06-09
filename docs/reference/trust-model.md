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
- otherwise resolving a compatible dependency release from the versions visible on PyPI
- inspecting either direct dependencies only or the full transitive tree, depending on the selected mode
- summarizing the highest-risk dependency outcome in the top-level report

The dependency view is flattened in the report for operator readability and automation. The `depth`, `parent_project`, and `parent_version` fields preserve traversal context.

`trustcheck scan` ingests exact versions from hashed requirements files,
`uv.lock`, `poetry.lock`, and `pdm.lock`. When dependency traversal is enabled,
those locked versions are retained for direct and transitive packages.

## Artifact content inspection

`--inspect-artifacts` adds static inspection of downloaded wheel and sdist
archives. The inspector does not extract archives to disk, import modules, call
entry points, or execute package code.

Wheel checks include:

- secure hash and size validation for every file listed in `RECORD`
- detection of files missing from `RECORD` or listed but absent from the wheel
- console-script listing and suspicious target detection
- native extension detection
- unexpected top-level file reporting
- `METADATA` Name, Version, and Requires-Dist comparison

Sdist checks include:

- suspicious install or executable script indicators
- oversized, unusual, nested-archive, and special-member reporting
- `PKG-INFO` metadata comparison with the selected release and wheel metadata

An invalid wheel `RECORD` or metadata mismatch is high-risk. Native code and
suspicious executable entry points are medium-severity findings that require
review rather than being treated as automatically high-risk.

## Limitations

- PyPI metadata quality varies by project
- some projects do not publish provenance at all
- repository matching currently supports canonical GitHub and GitLab URLs only
- lockfile scanning consumes existing resolutions but does not run a dependency solver
- local, editable, path, and VCS-only lockfile entries are skipped because they cannot be inspected as PyPI releases
- dependency inspection without a lockfile or `locked_versions` mapping resolves compatible releases from current PyPI metadata
- artifact inspection is static and cannot prove that arbitrary source code is safe
- native binaries are detected but are not disassembled or dynamically analyzed
- provenance verification may depend on local environment support required by underlying tooling
- text output is intentionally concise and may omit low-level detail unless `--verbose` is used
