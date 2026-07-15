from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

ActionValueKind = Literal["string", "bool", "multi", "int", "float"]


@dataclass(frozen=True, slots=True)
class ActionInputSpec:
    name: str
    field: str | None
    description: str
    default: str = ""
    required: bool = False
    kind: ActionValueKind = "string"
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    allow_minus_one: bool = False
    env_var: str | None = None
    env_aliases: tuple[str, ...] = ()
    runtime: bool = True

    @property
    def action_default(self) -> str | None:
        return None if self.required and self.default == "" else self.default

    @property
    def environment_name(self) -> str:
        if self.env_var is not None:
            return self.env_var
        normalized = self.name.upper().replace("-", "_")
        return f"TRUSTCHECK_ACTION_{normalized}"


ACTION_OUTPUT_FORMATS = (
    "text",
    "json",
    "sarif",
    "cyclonedx-json",
    "cyclonedx-xml",
    "cyclonedx-1.7-json",
    "cyclonedx-1.7-xml",
    "spdx-json",
    "spdx-3-json",
    "openvex",
    "markdown",
)
KEYRING_PROVIDERS = ("auto", "disabled", "import", "subprocess")
REMEDIATION_MODES = ("none", "plan", "fix")
SANDBOX_INPUT_MODES = ("off", "warn", "auto", "container", "bubblewrap", "strict")

ACTION_INPUTS: tuple[ActionInputSpec, ...] = (
    ActionInputSpec(
        "target",
        "target",
        (
            "Package name or path to requirements.txt, pyproject.toml, pylock.toml, "
            "Pipfile.lock, uv.lock, poetry.lock, or pdm.lock."
        ),
        required=True,
    ),
    ActionInputSpec(
        "policy",
        "policy",
        "Built-in policy bundle or path to a custom JSON policy file.",
        default="default",
    ),
    ActionInputSpec(
        "expected-repo",
        "expected_repo",
        "Expected source repository URL for a package target.",
    ),
    ActionInputSpec(
        "trusted-publisher-organizations",
        "trusted_publisher_organizations",
        "Whitespace- or newline-separated [provider:]organization publisher allowlist entries.",
        kind="multi",
    ),
    ActionInputSpec(
        "with-osv",
        "with_osv",
        "Query OSV for additional vulnerability records.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "osv-urls",
        "osv_urls",
        "Whitespace- or newline-separated custom OSV-compatible API base URLs.",
        kind="multi",
    ),
    ActionInputSpec(
        "with-ecosystems",
        "with_ecosystems",
        "Query the Ecosyste.ms OSV-compatible advisory service.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "with-kev",
        "with_kev",
        "Enrich CVEs with the CISA Known Exploited Vulnerabilities catalog.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "with-epss",
        "with_epss",
        "Enrich CVEs with FIRST EPSS scores and percentiles.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "with-deps",
        "with_deps",
        "Inspect direct runtime dependencies.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "with-transitive-deps",
        "with_transitive_deps",
        "Inspect direct and transitive runtime dependencies.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "inspect-artifacts",
        "inspect_artifacts",
        "Statically inspect downloaded wheel and sdist contents.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "index-url",
        "index_url",
        "Primary PEP 503/691 Simple Repository index URL.",
    ),
    ActionInputSpec(
        "extra-index-urls",
        "extra_index_urls",
        "Whitespace- or newline-separated additional Simple Repository index URLs.",
        kind="multi",
    ),
    ActionInputSpec(
        "keyring-provider",
        "keyring_provider",
        "Keyring authentication mode (auto, disabled, import, or subprocess).",
        default="auto",
        choices=KEYRING_PROVIDERS,
    ),
    ActionInputSpec(
        "allow-dependency-confusion",
        "allow_dependency_confusion",
        "Continue after reporting a project-name collision across configured indexes.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "allow-insecure-index",
        "allow_insecure_index",
        "Allow HTTP Simple Repository indexes and artifact URLs from those indexes.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "trusted-projects",
        "trusted_projects",
        "Whitespace- or newline-separated project names added to the typosquatting reference set.",
        kind="multi",
    ),
    ActionInputSpec(
        "workers",
        "max_workers",
        "Concurrent scan, advisory, and network workers (1-64, or -1 for all CPUs).",
        default="8",
        kind="int",
        minimum=1,
        maximum=64,
        allow_minus_one=True,
        env_var="TRUSTCHECK_ACTION_WORKERS",
        env_aliases=("TRUSTCHECK_ACTION_MAX_WORKERS",),
    ),
    ActionInputSpec(
        "sandbox",
        "sandbox",
        "Resolver isolation mode (off, warn, auto, container, bubblewrap, or strict).",
        default="strict",
        choices=SANDBOX_INPUT_MODES,
    ),
    ActionInputSpec(
        "sandbox-image",
        "sandbox_image",
        "Digest-pinned OCI image used by the container resolver sandbox.",
    ),
    ActionInputSpec(
        "advisory-snapshots",
        "advisory_snapshots",
        "Whitespace- or newline-separated advisory snapshot paths.",
        kind="multi",
    ),
    ActionInputSpec(
        "write-advisory-snapshot",
        "write_advisory_snapshot",
        "Path for a merged reusable advisory snapshot.",
    ),
    ActionInputSpec(
        "max-advisory-age",
        "max_advisory_age",
        "Maximum accepted advisory snapshot age in hours.",
        default="168",
        kind="float",
        minimum=0,
    ),
    ActionInputSpec(
        "advisory-snapshot-identity",
        "advisory_snapshot_identity",
        "Trusted Sigstore certificate identity for advisory snapshots.",
    ),
    ActionInputSpec(
        "advisory-snapshot-issuer",
        "advisory_snapshot_issuer",
        "Expected OIDC issuer for the advisory snapshot signer.",
    ),
    ActionInputSpec(
        "sign-advisory-snapshot",
        "sign_advisory_snapshot",
        "Sign written advisory snapshots using ambient Sigstore identity.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "allow-unsigned-advisory-snapshot",
        "allow_unsigned_advisory_snapshot",
        "Explicitly allow unsigned advisory snapshot compatibility mode.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "resume-state",
        "resume_state",
        "Checkpoint path used to resume matching dependency-file scans.",
    ),
    ActionInputSpec(
        "enable-plugins",
        "enable_plugins",
        "Enable installed trustcheck entry-point plugins.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "plugins",
        "plugins",
        "Whitespace- or newline-separated [kind:]name plugin allowlist.",
        kind="multi",
    ),
    ActionInputSpec(
        "plugin-config",
        "plugin_config",
        "JSON configuration path keyed by plugin name.",
    ),
    ActionInputSpec(
        "remediation",
        "remediation",
        "Remediation mode for dependency files (none, plan, or fix).",
        default="none",
        choices=REMEDIATION_MODES,
    ),
    ActionInputSpec(
        "dry-run",
        "dry_run",
        "Regenerate and validate the exact fix patch without modifying files.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "allow-constraint-changes",
        "allow_constraint_changes",
        "Permit minimal declared-range changes when secure versions are excluded.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "source-manifest",
        "source_manifest",
        "Source requirements or pyproject.toml used to regenerate a lockfile.",
    ),
    ActionInputSpec(
        "remediation-path",
        "remediation_path",
        "Path for the machine-readable remediation patch bundle.",
        default="trustcheck-remediation.json",
    ),
    ActionInputSpec(
        "max-fix-attempts",
        "max_fix_attempts",
        "Maximum candidate resolutions used to prove a minimal secure fix.",
        default="256",
        kind="int",
        minimum=1,
    ),
    ActionInputSpec(
        "create-pr",
        "create_pr",
        "Create a pull request for a validated fix using git and gh.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec("pr-base", "pr_base", "Optional pull request base branch."),
    ActionInputSpec("pr-branch", "pr_branch", "Optional pull request head branch."),
    ActionInputSpec("pr-title", "pr_title", "Optional pull request title."),
    ActionInputSpec(
        "pr-ready",
        "pr_ready",
        "Create a ready-for-review pull request instead of a draft.",
        default="false",
        kind="bool",
    ),
    ActionInputSpec(
        "format",
        "output_format",
        (
            "Report format (text, json, sarif, cyclonedx-json, cyclonedx-xml, "
            "cyclonedx-1.7-json, cyclonedx-1.7-xml, spdx-json, spdx-3-json, "
            "openvex, or markdown)."
        ),
        default="text",
        choices=ACTION_OUTPUT_FORMATS,
    ),
    ActionInputSpec(
        "report-path",
        "report_path",
        (
            "Report path relative to the caller workspace; defaults to an "
            "extension appropriate for the selected format."
        ),
    ),
    ActionInputSpec(
        "artifact-name",
        None,
        "Name of the uploaded workflow artifact.",
        default="trustcheck-report",
        runtime=False,
    ),
    ActionInputSpec(
        "python-version",
        None,
        "Python version used to run trustcheck.",
        default="3.12",
        runtime=False,
    ),
)

ACTION_INPUTS_BY_NAME: Mapping[str, ActionInputSpec] = {
    spec.name: spec for spec in ACTION_INPUTS
}
ACTION_INPUTS_BY_FIELD: Mapping[str, ActionInputSpec] = {
    spec.field: spec for spec in ACTION_INPUTS if spec.field is not None
}
RUNTIME_ACTION_INPUTS = tuple(spec for spec in ACTION_INPUTS if spec.runtime)
