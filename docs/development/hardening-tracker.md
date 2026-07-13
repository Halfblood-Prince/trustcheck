# Hardening Tracker

This tracker is the project-local issue record for the hardening roadmap. Mirror
the IDs into GitHub issues or a project board when triaging the release, and use
the labels in `.github/labels.yml` for consistency.

## Issue Labels

| Label | Purpose |
| --- | --- |
| `release-blocker` | Work that blocks a package tag, marketplace upload, or stable promotion |
| `security` | Trust boundary, sandbox, verification, or fail-closed behavior |
| `ai-plugin` | Claude, Codex, Cursor, or shared AI adapter work |
| `plugin-system` | Trustcheck third-party plugin protocol, manifests, IPC, and identity |
| `dynamic-analysis` | Installation or runtime analysis of package artifacts |
| `ci-cd` | GitHub Actions, release workflows, permissions, and artifact binding |
| `packaging` | Wheels, sdists, standalone binaries, Snap, Homebrew, or marketplace archives |
| `testing` | Unit, integration, coverage, fuzzing, mutation, and artifact smoke tests |
| `documentation` | User docs, reviewer docs, changelog, privacy, terms, and marketing accuracy |
| `maintainability` | Refactors, lint expansion, architecture docs, and contributor ergonomics |

## Feature Maturity

| Feature | Status | Release note |
| --- | --- | --- |
| Vulnerability scanning | Stable | Core scanner behavior remains release-ready. |
| Static artifact inspection | Stable | Static archive, AST, and native-binary checks remain enabled through explicit scan profiles. |
| Provenance verification | Stable | PyPI provenance and attestation verification remain core functionality. |
| Resolver isolation | Stable | Existing resolver sandbox modes remain part of the stable scanner. |
| Automated remediation | Advanced | Safe planning and transactional application are available, but release PRs must keep remediation tests green. |
| Dynamic installation analysis | Experimental | It executes untrusted package code in a constrained container and may be inconclusive. |
| Third-party Trustcheck plugins | Experimental | Safe IPC and installed-code identity binding are implemented; keep opt-in status until release validation completes. |
| AI installation gate | Experimental | Promotion is blocked until fail-closed validation, hardening, coverage, packaging, and final validation complete. |

## Milestone Issues

| ID | Milestone | Labels | Release blocking | Status |
| --- | --- | --- | --- | --- |
| `TRUSTCHECK-HARDENING-00` | Establish baseline and implementation tracker | `release-blocker`, `testing`, `documentation` | Blocks all release branches until present | Complete in this change |
| `TRUSTCHECK-HARDENING-01` | Make the AI adapter work as a standalone installed plugin | `release-blocker`, `security`, `ai-plugin`, `packaging`, `testing` | Blocks AI plugin release | Complete in this change |
| `TRUSTCHECK-HARDENING-02` | Make the AI security gate fail closed | `release-blocker`, `security`, `ai-plugin`, `testing` | Blocks AI plugin release | Complete in this change |
| `TRUSTCHECK-HARDENING-03` | Harden AI adapter execution and input handling | `release-blocker`, `security`, `ai-plugin` | Blocks AI plugin release | Complete in this change |
| `TRUSTCHECK-HARDENING-04` | Add AI adapter tests and restore coverage above 98% | `release-blocker`, `ai-plugin`, `testing` | Blocks AI plugin and main package release | Open |
| `TRUSTCHECK-HARDENING-05` | Replace unsafe plugin IPC | `release-blocker`, `security`, `plugin-system` | Blocks third-party plugin promotion | Complete in this change |
| `TRUSTCHECK-HARDENING-06` | Bind plugin trust to installed code and identity | `release-blocker`, `security`, `plugin-system` | Blocks third-party plugin promotion | Complete in this change |
| `TRUSTCHECK-HARDENING-07` | Redesign dynamic analysis | `security`, `dynamic-analysis`, `testing`, `documentation` | Blocks stable dynamic-analysis promotion | Complete in this change |
| `TRUSTCHECK-HARDENING-08` | Harden CI and release workflow correctness | `release-blocker`, `security`, `ci-cd` | Blocks main package release | Open |
| `TRUSTCHECK-HARDENING-09` | Improve packaging and source-distribution hygiene | `release-blocker`, `packaging`, `testing` | Blocks main package release | Open |
| `TRUSTCHECK-HARDENING-10` | Replace private pip APIs and strengthen resolver compatibility | `security`, `maintainability`, `testing` | Required before resolver compatibility promotion | Open |
| `TRUSTCHECK-HARDENING-11` | Prepare marketplace-ready Claude, Codex, and Cursor packages | `release-blocker`, `ai-plugin`, `packaging`, `documentation` | Blocks AI plugin release | Open |
| `TRUSTCHECK-HARDENING-12` | Improve maintainability, linting, mutation testing, and architecture | `maintainability`, `testing`, `documentation` | Release hardening follow-up | Open |
| `TRUSTCHECK-HARDENING-13` | Improve documentation, compatibility, and marketing accuracy | `release-blocker`, `documentation`, `ci-cd` | Blocks final release validation | Open |
| `TRUSTCHECK-HARDENING-14` | Final security review and staged release | `release-blocker`, `security`, `testing`, `packaging` | Blocks final release | Open |

## Release-Blocking Summary

Before tagging the next main package release, close milestones 4, 8, 9, 13, and
14. Before publishing the AI plugin, close milestones 4, 11, 13, and 14.
Before promoting Trustcheck's third-party plugin system as hardened, keep the
milestone 5 IPC regressions and milestone 6 trust-binding regressions green
through final release validation.
