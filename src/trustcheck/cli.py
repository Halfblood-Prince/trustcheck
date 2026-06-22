from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import tomllib
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Callable, Sequence
from urllib import parse

import urllib3
from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from . import __version__
from .advisories import (
    CISA_KEV_URL,
    ECOSYSTEMS_OSV_BASE_URL,
    EPSS_BASE_URL,
    OSV_BASE_URL,
    CisaKevClient,
    EpssClient,
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
)
from .contract import JSON_SCHEMA_VERSION
from .exports import (
    OUTPUT_FORMATS,
    ExportPackage,
    SourceLocation,
    render_export,
)
from .indexes import (
    DEFAULT_INDEX_URL,
    IndexConfiguration,
    SimpleRepositoryClient,
    normalize_index_url,
    redact_url_credentials,
)
from .lockfiles import (
    LockedPackage,
    LockfileResolution,
    is_supported_lockfile,
    load_lockfile,
    load_pip_tools_lock,
)
from .models import RemediationSummary, TrustReport
from .plugins import PluginError, PluginManager, RepositoryClient
from .policy import BUILTIN_POLICIES, PolicySettings, evaluate_policy, resolve_policy
from .pypi import IndexBackedPackageClient, PypiClient, PypiClientError
from .remediation import (
    PreparedRemediation,
    RemediationError,
    RemediationPlan,
    apply_prepared_remediation,
    create_pull_request,
    dependency_graph_from_resolution,
    plan_remediation,
    post_fix_result,
    prepare_remediation,
    render_remediation_text,
    validate_candidate,
)
from .resolver import (
    SANDBOX_MODES,
    ArtifactReference,
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
    discover_installed_distributions,
)
from .resume import ScanState, ScanStateError, scan_fingerprint, target_key
from .service import (
    ArtifactDigestCache,
    DependencyProgressCallback,
    ProgressCallback,
    inspect_package,
)
from .snapshots import (
    DEFAULT_MAX_ADVISORY_AGE_HOURS,
    AdvisorySnapshotError,
    AdvisorySnapshotStore,
)

EXIT_OK = 0
EXIT_UPSTREAM_FAILURE = 1
EXIT_USAGE = 2
EXIT_DATA_ERROR = 3
EXIT_POLICY_FAILURE = 4
EXIT_REMEDIATION_FAILURE = 5


@dataclass(slots=True)
class ScanTarget:
    requirement: str
    project: str
    version: str | None = None
    failure_message: str | None = None
    failure_exit_code: int = EXIT_OK
    locked_versions: dict[str, str] = field(default_factory=dict)
    complete_locked_versions: bool = False
    source_url: str | None = None
    requested: bool = True
    editable: bool = False
    vcs: str | None = None
    vcs_commit: str | None = None
    artifacts: tuple[ArtifactReference, ...] = ()
    index_url: str | None = None
    requires_dist: tuple[str, ...] = ()
    dependency_confusion: tuple[str, ...] = ()
    source_file: str | None = None
    source_line: int | None = None
    source_type: str = "index"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustcheck",
        description=(
            "Inspect PyPI package trust metadata or scan packages for vulnerabilities."
        ),
        epilog=f"Machine-readable report schema: {JSON_SCHEMA_VERSION}.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=(f"%(prog)s {__version__} (report schema {JSON_SCHEMA_VERSION})"),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show tracebacks for operational failures.",
    )
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default="text",
        help="Structured debug log format when --debug is enabled.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect package trust and provenance without vulnerability checks.",
    )
    inspect_parser.add_argument("project", nargs="?", help="Project name on PyPI.")
    inspect_parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        help=(
            "Inspect packages from requirements.txt, pyproject.toml, "
            "pylock.toml, Pipfile.lock, uv.lock, poetry.lock, or pdm.lock."
        ),
    )
    inspect_parser.add_argument("--version", help="Specific version to inspect.")
    inspect_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    inspect_parser.add_argument(
        "--expected-repo",
        help="Repository URL you expect the package to come from.",
    )
    inspect_parser.add_argument(
        "--format",
        default="text",
        help="Output format.",
    )
    inspect_parser.add_argument(
        "--output-file",
        help="Write the rendered report to this file instead of standard output.",
    )
    inspect_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed per-file verification evidence.",
    )
    inspect_parser.add_argument(
        "--inspect-artifacts",
        action="store_true",
        help="Statically inspect wheel and sdist contents without executing package code.",
    )
    dependency_group = inspect_parser.add_mutually_exclusive_group()
    dependency_group.add_argument(
        "--with-deps",
        action="store_true",
        help=("Inspect direct runtime dependencies and summarize the worst-risk dependency."),
    )
    dependency_group.add_argument(
        "--with-transitive-deps",
        action="store_true",
        help=(
            "Inspect direct and transitive runtime dependencies and "
            "summarize the worst-risk dependency."
        ),
    )
    inspect_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply the built-in strict policy.",
    )
    inspect_parser.add_argument(
        "--policy",
        choices=tuple(BUILTIN_POLICIES),
        default="default",
        help="Built-in policy profile to evaluate after evidence collection.",
    )
    inspect_parser.add_argument(
        "--policy-file",
        help="Path to a JSON file containing policy settings.",
    )
    inspect_parser.add_argument(
        "--require-verified-provenance",
        choices=("none", "all"),
        help="Override whether policy requires verified provenance for every artifact.",
    )
    inspect_parser.add_argument(
        "--allow-metadata-only",
        action="store_true",
        default=None,
        help="Allow metadata-only outcomes under the selected policy.",
    )
    inspect_parser.add_argument(
        "--disallow-metadata-only",
        action="store_false",
        dest="allow_metadata_only",
        default=None,
        help="Fail policy evaluation when the result is metadata-only.",
    )
    inspect_parser.add_argument(
        "--require-expected-repo-match",
        action="store_true",
        default=None,
        help="Require a provided expected repository to match the collected evidence.",
    )
    inspect_parser.add_argument(
        "--trusted-publisher-organization",
        action="append",
        default=[],
        metavar="[PROVIDER:]ORGANIZATION",
        help=(
            "Allow only verified publishers owned by this organization; "
            "repeat for multiple organizations."
        ),
    )
    inspect_parser.add_argument(
        "--fail-on-risk-severity",
        choices=("none", "medium", "high"),
        help="Fail policy evaluation when risk flags meet or exceed this severity.",
    )
    inspect_parser.add_argument(
        "--timeout",
        type=float,
        help="Network timeout in seconds.",
    )
    inspect_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    inspect_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    inspect_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    inspect_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_file_resolution_arguments(inspect_parser)
    _add_target_environment_arguments(inspect_parser)
    _add_index_arguments(inspect_parser)
    _add_malicious_arguments(inspect_parser)
    _add_runtime_arguments(inspect_parser)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a PyPI package or dependency file for vulnerabilities.",
    )
    scan_parser.add_argument(
        "project",
        nargs="?",
        help="Project name on PyPI.",
    )
    scan_parser.add_argument("--version", help="Specific version to scan.")
    scan_parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        help=(
            "Scan requirements.txt, pyproject.toml, pylock.toml, "
            "Pipfile.lock, uv.lock, poetry.lock, or pdm.lock."
        ),
    )
    scan_parser.add_argument(
        "--no-deps",
        action="store_true",
        help=(
            "Scan only packages declared in the dependency file without "
            "resolving transitive dependencies."
        ),
    )
    scan_profile = scan_parser.add_mutually_exclusive_group()
    scan_profile.add_argument(
        "--fast",
        action="store_const",
        const="fast",
        dest="scan_profile",
        help="Resolve dependencies and query advisories only (default).",
    )
    scan_profile.add_argument(
        "--standard",
        action="store_const",
        const="standard",
        dest="scan_profile",
        help="Add provenance checks for artifacts in the selected scope.",
    )
    scan_profile.add_argument(
        "--full",
        action="store_const",
        const="full",
        dest="scan_profile",
        help=(
            "Add static archives, native binaries, release history, and "
            "heuristic analysis for artifacts in the selected scope."
        ),
    )
    scan_parser.set_defaults(scan_profile="fast")
    scan_parser.add_argument(
        "--artifact-scope",
        choices=("target", "sdist", "all"),
        default="target",
        help=(
            "Choose target-compatible install artifact (default), source "
            "distributions, or every release artifact."
        ),
    )
    remediation_mode = scan_parser.add_mutually_exclusive_group()
    remediation_mode.add_argument(
        "--plan-fixes",
        action="store_true",
        help=(
            "Compute and validate the smallest secure upgrade set without "
            "running lockfile writers."
        ),
    )
    remediation_mode.add_argument(
        "--fix",
        action="store_true",
        help="Prepare, validate, and transactionally apply secure dependency fixes.",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "With --fix, run writers and validation in an isolated copy and "
            "emit the exact patch without modifying the project."
        ),
    )
    scan_parser.add_argument(
        "--allow-constraint-changes",
        action="store_true",
        help=(
            "Permit minimal declared-range changes when every known secure "
            "release is otherwise excluded."
        ),
    )
    scan_parser.add_argument(
        "--source-manifest",
        help="Explicit source requirements or pyproject.toml for a generated lockfile.",
    )
    scan_parser.add_argument(
        "--remediation-output",
        help="Write the versioned machine-readable remediation bundle to this path.",
    )
    scan_parser.add_argument(
        "--max-fix-attempts",
        type=int,
        default=256,
        help="Maximum candidate resolutions used to prove a minimal secure fix.",
    )
    scan_parser.add_argument(
        "--create-pr",
        action="store_true",
        help="Publish the validated fix from an isolated Git worktree using gh.",
    )
    scan_parser.add_argument("--pr-base", help="Pull request base branch.")
    scan_parser.add_argument("--pr-branch", help="Pull request head branch.")
    scan_parser.add_argument("--pr-title", help="Pull request title.")
    scan_parser.add_argument(
        "--pr-ready",
        action="store_true",
        help="Create a ready-for-review pull request instead of a draft.",
    )
    scan_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    scan_parser.add_argument(
        "--format",
        default="text",
        help="Output format.",
    )
    scan_parser.add_argument(
        "--output-file",
        help="Write the rendered report to this file instead of standard output.",
    )
    scan_parser.add_argument(
        "--with-osv",
        action="store_true",
        help="Query OSV for each resolved package version.",
    )
    _add_advisory_arguments(scan_parser)
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply the built-in strict policy.",
    )
    scan_parser.add_argument(
        "--policy",
        choices=tuple(BUILTIN_POLICIES),
        default="default",
        help="Built-in policy profile to evaluate after evidence collection.",
    )
    scan_parser.add_argument(
        "--policy-file",
        help="Path to a JSON file containing policy settings.",
    )
    scan_parser.add_argument(
        "--fail-on-vulnerability",
        choices=("ignore", "any", "critical", "kev", "fixable"),
        help="Override vulnerability handling for policy evaluation.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        help="Network timeout in seconds.",
    )
    scan_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    scan_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    scan_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_file_resolution_arguments(scan_parser)
    _add_target_environment_arguments(scan_parser)
    _add_index_arguments(scan_parser)
    _add_runtime_arguments(scan_parser, resumable=True)

    environment_parser = subparsers.add_parser(
        "environment",
        help="Inspect installed distributions in the active environment or site-packages paths.",
    )
    environment_parser.add_argument(
        "--path",
        action="append",
        default=[],
        metavar="SITE_PACKAGES",
        help="Discover distributions from this site-packages path; repeatable.",
    )
    environment_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    environment_parser.add_argument(
        "--format",
        default="text",
        help="Output format.",
    )
    environment_parser.add_argument(
        "--output-file",
        help="Write the rendered report to this file instead of standard output.",
    )
    environment_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed per-file verification evidence.",
    )
    environment_parser.add_argument(
        "--inspect-artifacts",
        action="store_true",
        help="Statically inspect wheel and sdist contents without executing package code.",
    )
    environment_parser.add_argument(
        "--with-osv",
        action="store_true",
        help="Query OSV for each installed distribution.",
    )
    _add_advisory_arguments(environment_parser)
    environment_dependency_group = environment_parser.add_mutually_exclusive_group()
    environment_dependency_group.add_argument(
        "--with-deps",
        action="store_true",
        help="Inspect immediate dependencies using installed versions.",
    )
    environment_dependency_group.add_argument(
        "--with-transitive-deps",
        action="store_true",
        help="Inspect transitive dependencies using installed versions.",
    )
    environment_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply the built-in strict policy.",
    )
    environment_parser.add_argument(
        "--policy",
        choices=tuple(BUILTIN_POLICIES),
        default="default",
        help="Built-in policy profile to evaluate after evidence collection.",
    )
    environment_parser.add_argument(
        "--policy-file",
        help="Path to a JSON file containing policy settings.",
    )
    environment_parser.add_argument(
        "--require-verified-provenance",
        choices=("none", "all"),
        help="Override whether policy requires verified provenance for every artifact.",
    )
    environment_parser.add_argument(
        "--trusted-publisher-organization",
        action="append",
        default=[],
        metavar="[PROVIDER:]ORGANIZATION",
        help=(
            "Allow only verified publishers owned by this organization; "
            "repeat for multiple organizations."
        ),
    )
    environment_parser.add_argument(
        "--allow-metadata-only",
        action="store_true",
        default=None,
        help="Allow metadata-only outcomes under the selected policy.",
    )
    environment_parser.add_argument(
        "--disallow-metadata-only",
        action="store_false",
        dest="allow_metadata_only",
        default=None,
        help="Fail policy evaluation when the result is metadata-only.",
    )
    environment_parser.add_argument(
        "--fail-on-vulnerability",
        choices=("ignore", "any", "critical", "kev", "fixable"),
        help="Override vulnerability handling for policy evaluation.",
    )
    environment_parser.add_argument(
        "--fail-on-risk-severity",
        choices=("none", "medium", "high"),
        help="Fail policy evaluation when risk flags meet or exceed this severity.",
    )
    environment_parser.add_argument("--timeout", type=float, help="Network timeout in seconds.")
    environment_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    environment_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    environment_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    environment_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_index_arguments(environment_parser)
    _add_malicious_arguments(environment_parser)
    _add_runtime_arguments(environment_parser, resumable=True)
    return parser


def _add_target_environment_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--python-version",
        help="Resolve dependencies for this target Python version.",
    )
    parser.add_argument(
        "--platform",
        action="append",
        default=[],
        help="Resolve wheels for this target platform; repeatable.",
    )
    parser.add_argument(
        "--implementation",
        help="Resolve wheels for this Python implementation tag, such as cp or pp.",
    )
    parser.add_argument(
        "--abi",
        action="append",
        default=[],
        help="Resolve wheels for this target ABI; repeatable.",
    )


def _add_index_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--index-url",
        default=DEFAULT_INDEX_URL,
        metavar="URL",
        help="Primary PEP 503/691 package index.",
    )
    parser.add_argument(
        "--extra-index-url",
        action="append",
        default=[],
        metavar="URL",
        help="Additional PEP 503/691 package index; repeatable.",
    )
    parser.add_argument(
        "--keyring-provider",
        choices=("auto", "disabled", "import", "subprocess"),
        default="auto",
        help="Credential provider used by pip and private-index requests.",
    )
    parser.add_argument(
        "--allow-dependency-confusion",
        action="store_true",
        help=(
            "Continue when a project name exists on more than one configured "
            "index; unsafe unless the source has been independently verified."
        ),
    )


def _add_advisory_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--osv-url",
        action="append",
        default=[],
        metavar="URL",
        help="Additional OSV-compatible API base URL; repeatable.",
    )
    parser.add_argument(
        "--with-ecosystems",
        action="store_true",
        help="Query the Ecosyste.ms OSV-compatible advisory service.",
    )
    parser.add_argument(
        "--with-kev",
        action="store_true",
        help="Enrich CVE aliases with the CISA Known Exploited Vulnerabilities catalog.",
    )
    parser.add_argument(
        "--with-epss",
        action="store_true",
        help="Enrich CVE aliases with FIRST EPSS probability and percentile scores.",
    )


def _add_file_resolution_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sandbox",
        choices=SANDBOX_MODES,
        default="auto",
        help=(
            "Resolver isolation: compatibility modes off/warn, automatic secure "
            "selection, Docker/Podman, bubblewrap, or strict wheel-only."
        ),
    )
    parser.add_argument(
        "--sandbox-image",
        default=None,
        metavar="IMAGE@SHA256:DIGEST",
        help=(
            "Digest-pinned OCI image used by the container resolver sandbox."
        ),
    )
    parser.add_argument(
        "--constraint",
        action="append",
        default=[],
        metavar="FILE",
        help="Apply a pip constraints file during dependency resolution; repeatable.",
    )
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        metavar="NAME",
        help="Select an optional-dependency extra from pyproject.toml; repeatable.",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        metavar="NAME",
        help="Select a standard or Poetry dependency group; repeatable.",
    )


def _add_malicious_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trusted-project",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Add a project name to the typosquatting comparison set; repeatable. "
            "Trustcheck also uses a built-in reference set."
        ),
    )


def _add_runtime_arguments(
    parser: argparse.ArgumentParser,
    *,
    resumable: bool = False,
) -> None:
    parser.add_argument(
        "--max-workers",
        type=int,
        help="Bound concurrent network and target work; defaults to 8.",
    )
    parser.add_argument(
        "--advisory-snapshot",
        action="append",
        default=[],
        metavar="PATH",
        help="Read a versioned offline advisory snapshot; repeatable.",
    )
    parser.add_argument(
        "--write-advisory-snapshot",
        metavar="PATH",
        help="Write merged advisory results as a reusable offline snapshot.",
    )
    parser.add_argument(
        "--max-advisory-age",
        type=float,
        default=DEFAULT_MAX_ADVISORY_AGE_HOURS,
        metavar="HOURS",
        help="Reject advisory snapshots older than this many hours; defaults to 168.",
    )
    parser.add_argument(
        "--advisory-snapshot-identity",
        metavar="IDENTITY",
        help="Trusted Sigstore certificate identity for advisory snapshots.",
    )
    parser.add_argument(
        "--advisory-snapshot-issuer",
        metavar="URL",
        help="Expected OIDC issuer for the advisory snapshot signer.",
    )
    parser.add_argument(
        "--sign-advisory-snapshot",
        action="store_true",
        help="Sign written advisory snapshots with Sigstore ambient identity.",
    )
    parser.add_argument(
        "--allow-unsigned-advisory-snapshot",
        action="store_true",
        help="Allow unsigned snapshot input or output for compatibility.",
    )
    parser.add_argument(
        "--enable-plugins",
        action="store_true",
        help="Enable installed trustcheck entry-point plugins.",
    )
    parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="[KIND:]NAME",
        help="Enable only this installed plugin; repeatable.",
    )
    parser.add_argument(
        "--plugin-config",
        metavar="PATH",
        help="JSON configuration keyed by plugin name.",
    )
    if resumable:
        parser.add_argument(
            "--resume-state",
            metavar="PATH",
            help="Persist completed targets and resume a matching interrupted scan.",
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(raw_argv)
    args._explicit_config_fields = _explicit_config_fields(raw_argv)
    try:
        config_payload = _load_config_file(args.config_file)
        _apply_project_config(args, config_payload)
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        return _handle_error(
            f"error: invalid configuration: {exc}",
            EXIT_DATA_ERROR,
            debug=args.debug,
        )
    if args.max_workers is not None and args.max_workers < 1:
        parser.error("--max-workers must be at least 1")
    if args.command == "scan":
        if args.dry_run and not args.fix:
            parser.error("--dry-run requires --fix")
        if args.create_pr and not args.fix:
            parser.error("--create-pr requires --fix")
        if args.create_pr and args.dry_run:
            parser.error("--create-pr cannot be combined with --dry-run")
        if args.max_fix_attempts < 1:
            parser.error("--max-fix-attempts must be at least 1")
        if args.no_deps and not args.filename:
            parser.error("--no-deps requires -f/--file")
        if args.no_deps and (args.plan_fixes or args.fix):
            parser.error("--no-deps cannot be combined with remediation")
        if args.no_deps and args.constraint:
            parser.error("--no-deps cannot be combined with --constraint")

    try:
        plugin_manager = PluginManager.from_options(
            enabled=args.enable_plugins,
            selected=args.plugin,
            config_path=args.plugin_config,
        )
        supported_formats = set(OUTPUT_FORMATS) | set(
            plugin_manager.output_formats()
        )
        if args.format not in supported_formats:
            parser.error(
                "--format must be one of: "
                + ", ".join(sorted(supported_formats))
        )
        if args.command == "inspect":
            args.max_workers = _resolve_max_workers(args, config_payload)
            progress_callback = None
            dependency_progress_callback = None
            if args.format == "text":
                progress_callback = _build_progress_callback()
                dependency_progress_callback = _build_dependency_progress_callback()
            client = _build_client(
                args,
                config_payload=config_payload,
                request_hook=_build_debug_request_hook(
                    enabled=args.debug,
                    log_format=args.log_format,
                ),
            )
            if args.filename and args.project:
                parser.error("inspect accepts either PROJECT or -f/--file, not both")
            if not args.filename and not args.project:
                parser.error("inspect requires PROJECT or -f/--file")
            if args.filename and (args.version or args.expected_repo):
                parser.error("--version and --expected-repo apply to package inspection")
            resolver = _resolver_from_args(args, plugin_manager=plugin_manager)
            policy_name = "strict" if args.strict else args.policy
            policy = resolve_policy(
                builtin_name=policy_name,
                config_path=args.policy_file,
                cli_overrides={
                    "require_verified_provenance": args.require_verified_provenance,
                    "allow_metadata_only": args.allow_metadata_only,
                    "require_expected_repository_match": args.require_expected_repo_match,
                    "allowed_publisher_organizations": (
                        args.trusted_publisher_organization or None
                    ),
                    "fail_on_severity": args.fail_on_risk_severity,
                },
            )
            if args.filename:
                targets = _load_scan_targets(
                    args.filename,
                    client,
                    resolver=resolver,
                    constraints=args.constraint,
                    extras=args.extra,
                    groups=args.group,
                    target_environment=_target_environment_from_args(args),
                    offline=client.offline,
                )
                return _run_scan_targets(
                    args.filename,
                    targets,
                    args=args,
                    client=client,
                    vulnerability_client=None,
                    policy=policy,
                    include_vulnerabilities=False,
                    vulnerability_only=False,
                    progress_callback=progress_callback,
                    dependency_progress_callback=dependency_progress_callback,
                    resolver=resolver,
                    plugin_manager=plugin_manager,
                )

            inspection_client: PypiClient | IndexBackedPackageClient = client
            expected_artifacts: tuple[ArtifactReference, ...] = ()
            dependency_confusion_indexes: tuple[str, ...] = ()
            selected_version = args.version
            if _uses_nondefault_indexes(args):
                root_requirement = (
                    f"{args.project}=={args.version}"
                    if args.version
                    else args.project
                )
                resolution = resolver.resolve_requirements(
                    [root_requirement],
                    target=_target_environment_from_args(args),
                    offline=client.offline,
                )
                root = next(
                    (
                        item
                        for item in resolution.distributions
                        if canonicalize_name(item.name)
                        == canonicalize_name(args.project)
                    ),
                    None,
                )
                if root is None:
                    raise ResolutionError(
                        f"resolver did not return root package {args.project!r}"
                    )
                selected_version = root.version
                expected_artifacts = root.artifacts
                dependency_confusion_indexes = next(
                    (
                        finding.indexes
                        for finding in resolution.dependency_confusion
                        if canonicalize_name(finding.project)
                        == canonicalize_name(args.project)
                    ),
                    (),
                )
                inspection_client = _client_for_target(
                    client,
                    ScanTarget(
                        requirement=f"{root.name}=={root.version}",
                        project=root.name,
                        version=root.version,
                        artifacts=root.artifacts,
                        index_url=root.index_url,
                        requires_dist=root.requires_dist,
                    ),
                    keyring_provider=args.keyring_provider,
                    plugin_manager=plugin_manager,
                )
            report = inspect_package(
                args.project,
                version=selected_version,
                expected_repository=args.expected_repo,
                client=inspection_client,
                progress_callback=progress_callback,
                dependency_progress_callback=dependency_progress_callback,
                include_dependencies=args.with_deps,
                include_transitive_dependencies=args.with_transitive_deps,
                include_vulnerabilities=False,
                include_osv=False,
                inspect_artifacts=args.inspect_artifacts,
                vulnerability_client=None,
                resolver=resolver,
                target_environment=_target_environment_from_args(args),
                expected_artifacts=expected_artifacts,
                dependency_confusion_indexes=dependency_confusion_indexes,
                trusted_projects=args.trusted_project,
                plugin_manager=plugin_manager,
                max_workers=args.max_workers,
            )
            evaluation = evaluate_policy(
                report,
                policy,
                plugin_manager=plugin_manager,
            )
            if args.format == "json":
                rendered = json.dumps(
                    report.to_dict(),
                    indent=2,
                    sort_keys=True,
                )
            elif args.format == "text":
                rendered = _render_text_report(
                    report,
                    verbose=args.verbose,
                )
            else:
                rendered = render_export(
                    args.format,
                    [
                        ExportPackage(
                            report=report,
                            source=SourceLocation(report.package_url),
                            artifacts=expected_artifacts,
                        )
                    ],
                    source_name=f"{report.project} {report.version}",
                    plugin_manager=plugin_manager,
                )
            _emit_output(rendered, args.output_file)
            if not evaluation.passed:
                return EXIT_POLICY_FAILURE
            return EXIT_OK
        if args.command == "scan":
            if args.filename and args.project:
                parser.error("scan accepts either PROJECT or -f/--file, not both")
            if not args.filename and not args.project:
                parser.error("scan requires PROJECT or -f/--file")
            if not args.filename and (args.plan_fixes or args.fix):
                parser.error("remediation requires -f/--file")
            args.max_workers = _resolve_max_workers(args, config_payload)
            progress_callback = None
            dependency_progress_callback = None
            client = _build_client(
                args,
                config_payload=config_payload,
                request_hook=_build_debug_request_hook(
                    enabled=args.debug,
                    log_format=args.log_format,
                ),
            )
            vulnerability_client = _build_vulnerability_client(
                args,
                client,
                config_payload=config_payload,
                plugin_manager=plugin_manager,
            )
            policy_name = "strict" if args.strict else args.policy
            policy = resolve_policy(
                builtin_name=policy_name,
                config_path=args.policy_file,
                cli_overrides={
                    "require_verified_provenance": "none",
                    "allow_metadata_only": True,
                    "allowed_publisher_organizations": [],
                    "vulnerability_mode": args.fail_on_vulnerability,
                    "fail_on_severity": "none",
                },
            )
            resolver = _resolver_from_args(args, plugin_manager=plugin_manager)
            if not args.filename:
                report = _scan_project_vulnerabilities(
                    args.project,
                    version=args.version,
                    args=args,
                    client=client,
                    vulnerability_client=vulnerability_client,
                    policy=policy,
                    resolver=resolver,
                    plugin_manager=plugin_manager,
                )
                evaluation = evaluate_policy(
                    report,
                    policy,
                    plugin_manager=plugin_manager,
                )
                vulnerability_only = args.scan_profile == "fast"
                if args.format == "json" and vulnerability_only:
                    rendered = json.dumps(
                        _render_cve_json(report),
                        indent=2,
                        sort_keys=True,
                    )
                elif args.format == "json":
                    rendered = json.dumps(
                        report.to_dict(),
                        indent=2,
                        sort_keys=True,
                    )
                elif args.format == "text" and vulnerability_only:
                    rendered = _render_cve_report(report)
                elif args.format == "text":
                    rendered = _render_text_report(report, verbose=True)
                else:
                    rendered = render_export(
                        args.format,
                        [
                            ExportPackage(
                                report=report,
                                source=SourceLocation(report.package_url),
                                artifacts=(),
                            )
                        ],
                        source_name=f"{report.project} {report.version}",
                        plugin_manager=plugin_manager,
                    )
                if vulnerability_client is not None:
                    vulnerability_client.flush_snapshots()
                _emit_output(rendered, args.output_file)
                return EXIT_OK if evaluation.passed else EXIT_POLICY_FAILURE

            targets = _load_scan_targets(
                args.filename,
                client,
                resolver=None if args.no_deps else resolver,
                constraints=args.constraint,
                extras=args.extra,
                groups=args.group,
                target_environment=_target_environment_from_args(args),
                offline=client.offline,
            )
            return _run_scan_targets(
                args.filename,
                targets,
                args=args,
                client=client,
                vulnerability_client=vulnerability_client,
                policy=policy,
                include_vulnerabilities=True,
                vulnerability_only=args.scan_profile == "fast",
                progress_callback=progress_callback,
                dependency_progress_callback=dependency_progress_callback,
                resolver=resolver,
                plugin_manager=plugin_manager,
            )
        if args.command == "environment":
            args.max_workers = _resolve_max_workers(args, config_payload)
            progress_callback = None
            dependency_progress_callback = None
            if args.format == "text":
                progress_callback = _build_progress_callback()
                dependency_progress_callback = _build_dependency_progress_callback()
            client = _build_client(
                args,
                config_payload=config_payload,
                request_hook=_build_debug_request_hook(
                    enabled=args.debug,
                    log_format=args.log_format,
                ),
            )
            vulnerability_client = _build_vulnerability_client(
                args,
                client,
                config_payload=config_payload,
                plugin_manager=plugin_manager,
            )
            policy_name = "strict" if args.strict else args.policy
            policy = resolve_policy(
                builtin_name=policy_name,
                config_path=args.policy_file,
                cli_overrides={
                    "require_verified_provenance": args.require_verified_provenance,
                    "allow_metadata_only": args.allow_metadata_only,
                    "allowed_publisher_organizations": (
                        args.trusted_publisher_organization or None
                    ),
                    "vulnerability_mode": args.fail_on_vulnerability,
                    "fail_on_severity": args.fail_on_risk_severity,
                },
            )
            resolution = discover_installed_distributions(args.path)
            if _uses_nondefault_indexes(args):
                resolution = _resolver_from_args(
                    args,
                    plugin_manager=plugin_manager,
                ).annotate_indexes(resolution)
            targets = _scan_targets_from_resolution(resolution)
            source_label = (
                ", ".join(str(Path(path).resolve()) for path in args.path)
                if args.path
                else "active Python environment"
            )
            return _run_scan_targets(
                source_label,
                targets,
                args=args,
                client=client,
                vulnerability_client=vulnerability_client,
                policy=policy,
                include_vulnerabilities=True,
                vulnerability_only=False,
                progress_callback=progress_callback,
                dependency_progress_callback=dependency_progress_callback,
                resolver=None,
                plugin_manager=plugin_manager,
            )

        parser.error("unknown command")
        return EXIT_USAGE
    except PypiClientError as exc:
        return _handle_error(
            _format_upstream_error(exc),
            EXIT_UPSTREAM_FAILURE,
            debug=args.debug,
        )
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        ResolutionError,
        RemediationError,
        PluginError,
        ScanStateError,
        AdvisorySnapshotError,
    ) as exc:
        return _handle_error(
            f"error: received an invalid response while inspecting the package: {exc}",
            EXIT_DATA_ERROR,
            debug=args.debug,
        )
    except Exception as exc:
        return _handle_error(
            f"error: unexpected failure while inspecting the package: {exc}",
            EXIT_DATA_ERROR,
            debug=args.debug,
        )


def _run_scan_targets(
    source_label: str,
    targets: list[ScanTarget],
    *,
    args: argparse.Namespace,
    client: PypiClient,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    policy: PolicySettings,
    include_vulnerabilities: bool,
    vulnerability_only: bool,
    progress_callback: ProgressCallback | None,
    dependency_progress_callback: DependencyProgressCallback | None,
    resolver: PipResolver | None,
    plugin_manager: PluginManager,
) -> int:
    reports_by_index: dict[int, TrustReport] = {}
    failures_by_index: dict[int, dict[str, str]] = {}
    overall_exit_code = EXIT_OK
    keys = [target_key(target) for target in targets]
    state = _build_scan_state(
        source_label,
        targets,
        keys=keys,
        args=args,
        policy=policy,
        plugin_manager=plugin_manager,
    )
    callback_lock = threading.Lock()
    safe_progress = _synchronized_progress_callback(
        progress_callback,
        callback_lock,
    )
    safe_dependency_progress = _synchronized_dependency_progress_callback(
        dependency_progress_callback,
        callback_lock,
    )

    if vulnerability_client is not None:
        vulnerability_client.prefetch(
            [
                (target.project, target.version)
                for target in targets
                if target.failure_message is None and target.version is not None
            ]
        )

    pending: list[tuple[int, ScanTarget]] = []
    for index, target in enumerate(targets):
        if target.failure_message is not None:
            failure = {
                "requirement": target.requirement,
                "message": target.failure_message,
            }
            failures_by_index[index] = failure
            if state is not None:
                state.record_failure(
                    keys[index],
                    requirement=target.requirement,
                    message=target.failure_message,
                )
            overall_exit_code = _merge_exit_codes(
                overall_exit_code,
                target.failure_exit_code,
            )
            continue
        resumed = state.report(keys[index]) if state is not None else None
        if resumed is not None:
            reports_by_index[index] = resumed
            evaluation = evaluate_policy(
                resumed,
                policy,
                plugin_manager=plugin_manager,
            )
            if not evaluation.passed and overall_exit_code == EXIT_OK:
                overall_exit_code = EXIT_POLICY_FAILURE
            continue
        pending.append((index, target))

    def scan_target(
        index: int,
        target: ScanTarget,
    ) -> tuple[int, TrustReport | None, dict[str, str] | None, int]:
        try:
            isolated_client = _clone_pypi_client(client)
            target_client = _client_for_target(
                isolated_client,
                target,
                keyring_provider=args.keyring_provider,
                plugin_manager=plugin_manager,
            )
            report = inspect_package(
                target.project,
                version=target.version,
                client=target_client,
                progress_callback=safe_progress,
                dependency_progress_callback=safe_dependency_progress,
                include_dependencies=getattr(args, "with_deps", False),
                include_transitive_dependencies=getattr(
                    args,
                    "with_transitive_deps",
                    False,
                ),
                include_vulnerabilities=include_vulnerabilities,
                include_osv=vulnerability_client is not None,
                vulnerability_only=vulnerability_only,
                inspect_artifacts=getattr(args, "inspect_artifacts", False),
                vulnerability_client=vulnerability_client,
                locked_versions=target.locked_versions,
                complete_locked_versions=target.complete_locked_versions,
                expected_artifacts=target.artifacts,
                dependency_confusion_indexes=target.dependency_confusion,
                trusted_projects=getattr(args, "trusted_project", ()),
                plugin_manager=plugin_manager,
                scan_profile=getattr(args, "scan_profile", None),
                artifact_scope=getattr(args, "artifact_scope", None),
                max_workers=args.max_workers,
                artifact_cache=artifact_cache,
                artifact_executor=artifact_executor,
                target_environment=_target_environment_from_args(args),
            )
            evaluation = evaluate_policy(
                report,
                policy,
                plugin_manager=plugin_manager,
            )
            return (
                index,
                report,
                None,
                EXIT_OK if evaluation.passed else EXIT_POLICY_FAILURE,
            )
        except PypiClientError as exc:
            return (
                index,
                None,
                {
                    "requirement": target.requirement,
                    "message": _format_upstream_error(exc),
                },
                EXIT_UPSTREAM_FAILURE,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return (
                index,
                None,
                {
                    "requirement": target.requirement,
                    "message": (
                        "error: received an invalid response while "
                        f"inspecting the package: {exc}"
                    ),
                },
                EXIT_DATA_ERROR,
            )

    artifact_cache = ArtifactDigestCache()
    artifact_executor = ThreadPoolExecutor(
        max_workers=max(1, args.max_workers),
        thread_name_prefix="trustcheck-artifact",
    )
    workers = min(max(1, args.max_workers), max(1, len(pending)))
    try:
        if pending:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(scan_target, index, target): (index, target)
                    for index, target in pending
                }
                for future in as_completed(futures):
                    index, target = futures[future]
                    result_index, report, result_failure, exit_code = future.result()
                    if result_index != index:
                        raise RuntimeError("scan worker returned an invalid target index")
                    overall_exit_code = _merge_exit_codes(
                        overall_exit_code,
                        exit_code,
                    )
                    if report is not None:
                        reports_by_index[index] = report
                        if state is not None:
                            state.record_report(keys[index], report)
                    elif result_failure is not None:
                        failures_by_index[index] = result_failure
                        if state is not None:
                            state.record_failure(
                                keys[index],
                                requirement=target.requirement,
                                message=result_failure["message"],
                            )
    finally:
        artifact_executor.shutdown(wait=True)

    report_indexes = sorted(reports_by_index)
    reports = [reports_by_index[index] for index in report_indexes]
    report_targets = [targets[index] for index in report_indexes]
    failures = [
        failures_by_index[index] for index in sorted(failures_by_index)
    ]
    if vulnerability_client is not None:
        vulnerability_client.flush_snapshots()
    if state is not None:
        state.complete()
    remediation: RemediationPlan | None = None
    if (
        args.command == "scan"
        and (args.plan_fixes or args.fix)
        and resolver is not None
        and not failures
    ):
        try:
            remediation = _run_remediation(
                source_label,
                targets=report_targets,
                reports=reports,
                args=args,
                client=client,
                vulnerability_client=vulnerability_client,
                policy=policy,
                resolver=resolver,
                progress_callback=progress_callback,
                dependency_progress_callback=dependency_progress_callback,
                plugin_manager=plugin_manager,
            )
        except RemediationError as exc:
            remediation = RemediationPlan(
                source=str(Path(source_label).resolve()),
                status="failed",
                max_attempts=args.max_fix_attempts,
                message=str(exc),
            )
        _attach_remediation_summary(reports, remediation)
        if args.remediation_output:
            remediation.write_json(args.remediation_output)
        if remediation.status in {"blocked", "failed"}:
            overall_exit_code = _merge_exit_codes(
                overall_exit_code,
                EXIT_REMEDIATION_FAILURE,
            )
        elif args.fix and not remediation.validation.policy_passed:
            overall_exit_code = _merge_exit_codes(
                overall_exit_code,
                EXIT_POLICY_FAILURE,
            )
    if args.format == "json":
        payload = _render_scan_json(
            source_label,
            reports,
            failures=failures,
            vulnerability_only=vulnerability_only,
            targets=targets,
        )
        if remediation is not None:
            payload["remediation"] = remediation.to_dict()
        rendered = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
    elif args.format == "text":
        rendered = _render_scan_text(
            source_label,
            reports,
            failures=failures,
            verbose=getattr(args, "verbose", False),
            vulnerability_only=vulnerability_only,
        )
        if remediation is not None:
            rendered += "\n\n" + render_remediation_text(remediation)
    else:
        rendered = render_export(
            args.format,
            [
                ExportPackage(
                    report=report,
                    source=SourceLocation(
                        target.source_file or source_label,
                        target.source_line,
                    ),
                    artifacts=target.artifacts,
                )
                for report, target in zip(
                    reports,
                    report_targets,
                    strict=True,
                )
            ],
            source_name=source_label,
            failures=failures,
            plugin_manager=plugin_manager,
        )
    _emit_output(rendered, args.output_file)
    return overall_exit_code


def _scan_project_vulnerabilities(
    project: str,
    *,
    version: str | None,
    args: argparse.Namespace,
    client: PypiClient,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    policy: PolicySettings,
    resolver: PipResolver,
    plugin_manager: PluginManager,
) -> TrustReport:
    selected_version = version
    scan_client: PypiClient | IndexBackedPackageClient = client
    expected_artifacts: tuple[ArtifactReference, ...] = ()
    dependency_confusion_indexes: tuple[str, ...] = ()
    if _uses_nondefault_indexes(args):
        root_requirement = f"{project}=={version}" if version else project
        resolution = resolver.resolve_requirements(
            [root_requirement],
            target=_target_environment_from_args(args),
            offline=client.offline,
        )
        root = next(
            (
                item
                for item in resolution.distributions
                if canonicalize_name(item.name) == canonicalize_name(project)
            ),
            None,
        )
        if root is None:
            raise ResolutionError(
                f"resolver did not return root package {project!r}"
            )
        selected_version = root.version
        expected_artifacts = root.artifacts
        dependency_confusion_indexes = next(
            (
                finding.indexes
                for finding in resolution.dependency_confusion
                if canonicalize_name(finding.project) == canonicalize_name(project)
            ),
            (),
        )
        scan_client = _client_for_target(
            client,
            ScanTarget(
                requirement=f"{root.name}=={root.version}",
                project=root.name,
                version=root.version,
                artifacts=root.artifacts,
                index_url=root.index_url,
                requires_dist=root.requires_dist,
            ),
            keyring_provider=args.keyring_provider,
            plugin_manager=plugin_manager,
        )
    report = inspect_package(
        project,
        version=selected_version,
        client=scan_client,
        include_vulnerabilities=True,
        include_osv=vulnerability_client is not None,
        vulnerability_only=args.scan_profile == "fast",
        vulnerability_client=vulnerability_client,
        resolver=resolver,
        target_environment=_target_environment_from_args(args),
        expected_artifacts=expected_artifacts,
        dependency_confusion_indexes=dependency_confusion_indexes,
        plugin_manager=plugin_manager,
        scan_profile=args.scan_profile,
        artifact_scope=args.artifact_scope,
        max_workers=args.max_workers,
    )
    evaluate_policy(report, policy, plugin_manager=plugin_manager)
    return report


def _run_remediation(
    source_label: str,
    *,
    targets: Sequence[ScanTarget],
    reports: Sequence[TrustReport],
    args: argparse.Namespace,
    client: PypiClient,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    policy: PolicySettings,
    resolver: PipResolver,
    progress_callback: ProgressCallback | None,
    dependency_progress_callback: DependencyProgressCallback | None,
    plugin_manager: PluginManager | None = None,
) -> RemediationPlan:
    plugin_manager = plugin_manager or PluginManager()
    source_path = Path(source_label).resolve()
    baseline = _resolution_from_scan_targets(targets)
    report_map = {
        str(canonicalize_name(report.project)): report for report in reports
    }
    root_requirements = _remediation_root_requirements(
        source_path,
        source_manifest=args.source_manifest,
        extras=args.extra,
        groups=args.group,
        target_environment=_target_environment_from_args(args),
    )
    for constraint in args.constraint:
        root_requirements.extend(
            _read_remediation_requirements(Path(constraint).resolve())
        )
    source_types = {
        str(canonicalize_name(target.project)): target.source_type
        for target in targets
    }
    available_versions = _remediation_available_versions(
        targets,
        reports,
        client=client,
        keyring_provider=args.keyring_provider,
    )
    target_environment = _target_environment_from_args(args)

    def resolve_candidate(requirements: Sequence[str]) -> Resolution:
        return resolver.resolve_requirements(
            requirements,
            target=target_environment,
            cwd=source_path.parent,
            offline=client.offline,
        )

    def scan_candidate(resolution: Resolution) -> dict[str, TrustReport]:
        return _scan_resolution_for_remediation(
            resolution,
            args=args,
            client=client,
            vulnerability_client=vulnerability_client,
            policy=policy,
            progress_callback=progress_callback,
            dependency_progress_callback=dependency_progress_callback,
            plugin_manager=plugin_manager,
        )

    plan = plan_remediation(
        source=source_path,
        baseline=baseline,
        reports=report_map,
        root_requirements=root_requirements,
        resolve=resolve_candidate,
        scan=scan_candidate,
        source_types=source_types,
        available_versions=available_versions,
        allow_constraint_changes=args.allow_constraint_changes,
        max_attempts=args.max_fix_attempts,
    )
    if not args.fix or plan.status != "validated":
        return plan

    prepared = prepare_remediation(
        source_path,
        plan,
        source_manifest=args.source_manifest,
        constraint_files=args.constraint,
        allow_constraint_changes=args.allow_constraint_changes,
    )
    try:
        generated = _resolution_from_prepared(
            prepared,
            source_path=source_path,
            args=args,
            resolver=resolver,
            offline=client.offline,
        )
        expected_versions = (
            plan.candidate_resolution.versions
            if plan.candidate_resolution is not None
            else {}
        )
        if generated.versions != expected_versions:
            raise RemediationError(
                "the generated dependency files do not reproduce the proven "
                "minimal resolution"
            )
        generated_reports = scan_candidate(generated)
        targeted = {
            str(canonicalize_name(upgrade.project)): upgrade.advisory_ids
            for upgrade in plan.upgrades
        }
        plan.validation = validate_candidate(
            baseline=baseline,
            baseline_reports=report_map,
            candidate=generated,
            candidate_reports=generated_reports,
            targeted=targeted,
        )
        plan.after_graph = dependency_graph_from_resolution(generated)
        plan.post_fix_result = post_fix_result(
            command=_post_fix_reproduction_command(source_path, args),
            resolution=generated,
            reports=generated_reports,
            validation=plan.validation,
            expected_versions=expected_versions,
        )
        if not plan.validation.accepted:
            raise RemediationError(
                "the generated patch failed post-write resolution or security validation"
            )
        if args.dry_run:
            plan.message = (
                "the exact patch was regenerated and validated in an isolated "
                "workspace; no project files were modified"
            )
            return plan
        if args.create_pr:
            result = create_pull_request(
                prepared,
                base=args.pr_base,
                branch=args.pr_branch,
                title=args.pr_title,
                ready=args.pr_ready,
            )
            if not result.created:
                plan.status = "failed"
            return plan
        apply_prepared_remediation(prepared)
        return plan
    finally:
        prepared.close()


def _post_fix_reproduction_command(
    source_path: Path,
    args: argparse.Namespace,
) -> tuple[str, ...]:
    command = ["trustcheck", "scan", "-f", str(source_path), "--format", "json"]
    if getattr(args, "with_osv", False):
        command.append("--with-osv")
    for url in getattr(args, "osv_url", ()):
        command.extend(["--osv-url", url])
    if getattr(args, "with_ecosystems", False):
        command.append("--with-ecosystems")
    if getattr(args, "with_kev", False):
        command.append("--with-kev")
    if getattr(args, "with_epss", False):
        command.append("--with-epss")
    for extra in getattr(args, "extra", ()):
        command.extend(["--extra", extra])
    for group in getattr(args, "group", ()):
        command.extend(["--group", group])
    for constraint in getattr(args, "constraint", ()):
        command.extend(["--constraint", str(Path(constraint).resolve())])
    if getattr(args, "strict", False):
        command.append("--strict")
    policy_name = getattr(args, "policy", "default")
    if policy_name != "default":
        command.extend(["--policy", policy_name])
    if getattr(args, "policy_file", None):
        command.extend(["--policy-file", str(Path(args.policy_file).resolve())])
    if getattr(args, "fail_on_vulnerability", None):
        command.extend(["--fail-on-vulnerability", args.fail_on_vulnerability])
    index_url = getattr(args, "index_url", DEFAULT_INDEX_URL)
    if index_url != DEFAULT_INDEX_URL:
        command.extend(["--index-url", index_url])
    for index_url in getattr(args, "extra_index_url", ()):
        command.extend(["--extra-index-url", index_url])
    if getattr(args, "allow_dependency_confusion", False):
        command.append("--allow-dependency-confusion")
    if getattr(args, "python_version", None):
        command.extend(["--python-version", args.python_version])
    for platform in getattr(args, "platform", ()):
        command.extend(["--platform", platform])
    if getattr(args, "implementation", None):
        command.extend(["--implementation", args.implementation])
    for abi in getattr(args, "abi", ()):
        command.extend(["--abi", abi])
    if getattr(args, "offline", False):
        command.append("--offline")
    for snapshot in getattr(args, "advisory_snapshot", ()):
        command.extend(["--advisory-snapshot", str(Path(snapshot).resolve())])
    if getattr(args, "max_advisory_age", None) is not None:
        command.extend(["--max-advisory-age", str(args.max_advisory_age)])
    if getattr(args, "advisory_snapshot_identity", None):
        command.extend(
            ["--advisory-snapshot-identity", args.advisory_snapshot_identity]
        )
    if getattr(args, "advisory_snapshot_issuer", None):
        command.extend(
            ["--advisory-snapshot-issuer", args.advisory_snapshot_issuer]
        )
    if getattr(args, "allow_unsigned_advisory_snapshot", False):
        command.append("--allow-unsigned-advisory-snapshot")
    return tuple(command)


def _remediation_available_versions(
    targets: Sequence[ScanTarget],
    reports: Sequence[TrustReport],
    *,
    client: PypiClient,
    keyring_provider: str,
) -> dict[str, tuple[str, ...]]:
    reports_by_name = {
        str(canonicalize_name(report.project)): report
        for report in reports
    }
    versions: dict[str, tuple[str, ...]] = {}
    for target in targets:
        name = str(canonicalize_name(target.project))
        report = reports_by_name.get(name)
        if report is None or not any(
            vulnerability.fixed_in
            and not vulnerability.withdrawn
            and not (
                vulnerability.suppression is not None
                and vulnerability.suppression.status == "active"
            )
            for vulnerability in report.vulnerabilities
        ):
            continue
        target_client = _client_for_target(
            client,
            target,
            keyring_provider=keyring_provider,
        )
        try:
            payload = target_client.get_project(target.project)
        except PypiClientError:
            continue
        releases = payload.get("releases")
        if isinstance(releases, dict):
            versions[name] = tuple(
                raw_version
                for raw_version in releases
                if isinstance(raw_version, str)
            )
    return versions


def _resolution_from_scan_targets(
    targets: Sequence[ScanTarget],
) -> Resolution:
    distributions = [
        ResolvedDistribution(
            name=target.project,
            version=target.version,
            requested=target.requested,
            source_url=target.source_url,
            is_direct=target.source_type == "direct",
            editable=target.editable,
            vcs=target.vcs,
            vcs_commit=target.vcs_commit,
            requires_dist=target.requires_dist,
            artifacts=target.artifacts,
            index_url=target.index_url,
        )
        for target in targets
        if target.version is not None and target.failure_message is None
    ]
    return Resolution(distributions=distributions)


def _remediation_root_requirements(
    source_path: Path,
    *,
    source_manifest: str | None,
    extras: Sequence[str],
    groups: Sequence[str],
    target_environment: TargetEnvironment,
) -> list[str]:
    manifest = (
        Path(source_manifest).resolve()
        if source_manifest is not None
        else _discover_remediation_manifest(source_path)
    )
    input_path = manifest or source_path
    if is_supported_lockfile(source_path) and manifest is None:
        raise RemediationError(
            f"{source_path.name} does not identify its root requirements; "
            "provide --source-manifest"
        )
    if input_path.suffix.lower() == ".toml":
        try:
            with input_path.open("rb") as stream:
                payload = tomllib.load(stream)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise RemediationError(
                f"invalid remediation source manifest {input_path}: {exc}"
            ) from exc
        return _extract_scan_requirements_from_toml(
            payload,
            extras=extras,
            groups=groups,
            base_path=input_path.parent,
        )
    requirements = _read_remediation_requirements(input_path)
    if not requirements:
        raise RemediationError(
            f"no root requirements were found in remediation source {input_path}"
        )
    del target_environment
    return requirements


def _read_remediation_requirements(
    path: Path,
    *,
    seen: set[Path] | None = None,
) -> list[str]:
    resolved = path.resolve()
    visited = seen if seen is not None else set()
    if resolved in visited:
        raise RemediationError(
            f"cyclic requirements include involving {resolved}"
        )
    if not resolved.is_file():
        raise RemediationError(f"requirements source does not exist: {resolved}")
    visited.add(resolved)
    requirements: list[str] = []
    pending = ""
    for raw_line in resolved.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.rstrip()
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment.strip()}".strip()
        if continued:
            continue
        cleaned = _clean_requirement_line(pending)
        pending = ""
        include_match = re.match(
            r"^(?:-r|--requirement|-c|--constraint)\s*(?:=|\s)\s*(\S+)",
            cleaned,
        )
        if include_match is not None:
            requirements.extend(
                _read_remediation_requirements(
                    resolved.parent / include_match.group(1),
                    seen=visited,
                )
            )
            continue
        requirement = _strip_requirement_hashes(cleaned)
        if requirement and not requirement.startswith(("-", "--")):
            requirements.append(requirement)
    visited.remove(resolved)
    return requirements


def _discover_remediation_manifest(source_path: Path) -> Path | None:
    if source_path.name == "pyproject.toml":
        return source_path
    pyproject = source_path.parent / "pyproject.toml"
    if pyproject.is_file():
        return pyproject
    if source_path.name.lower() == "requirements.txt":
        requirements_in = source_path.with_suffix(".in")
        if requirements_in.is_file():
            return requirements_in
        return source_path
    if source_path.suffix.lower() in {".txt", ".in"}:
        return source_path
    return None


def _scan_resolution_for_remediation(
    resolution: Resolution,
    *,
    args: argparse.Namespace,
    client: PypiClient,
    vulnerability_client: VulnerabilityIntelligenceClient | None,
    policy: PolicySettings,
    progress_callback: ProgressCallback | None,
    dependency_progress_callback: DependencyProgressCallback | None,
    plugin_manager: PluginManager | None = None,
) -> dict[str, TrustReport]:
    plugin_manager = plugin_manager or PluginManager()
    reports: dict[str, TrustReport] = {}
    versions = resolution.versions
    for distribution in resolution.distributions:
        target = _scan_target_from_resolved_distribution(
            distribution,
            versions,
        )
        target_client = _client_for_target(
            client,
            target,
            keyring_provider=args.keyring_provider,
            plugin_manager=plugin_manager,
        )
        report = inspect_package(
            target.project,
            version=target.version,
            client=target_client,
            progress_callback=progress_callback,
            dependency_progress_callback=dependency_progress_callback,
            include_dependencies=args.with_deps,
            include_transitive_dependencies=args.with_transitive_deps,
            include_osv=vulnerability_client is not None,
            inspect_artifacts=args.inspect_artifacts,
            vulnerability_client=vulnerability_client,
            locked_versions=versions,
            complete_locked_versions=True,
            expected_artifacts=target.artifacts,
            dependency_confusion_indexes=target.dependency_confusion,
            trusted_projects=args.trusted_project,
            plugin_manager=plugin_manager,
        )
        evaluate_policy(
            report,
            policy,
            plugin_manager=plugin_manager,
        )
        reports[str(canonicalize_name(report.project))] = report
    return reports


def _resolution_from_prepared(
    prepared: PreparedRemediation,
    *,
    source_path: Path,
    args: argparse.Namespace,
    resolver: PipResolver,
    offline: bool,
) -> Resolution:
    relative_target = _relative_to_resolved_root(
        source_path,
        prepared.source_root,
    )
    staged_target = prepared.root / relative_target
    target_environment = _target_environment_from_args(args)
    if is_supported_lockfile(staged_target):
        locked = load_lockfile(
            staged_target,
            extras=args.extra,
            groups=args.group,
            environment=_target_marker_environment(target_environment),
        )
        return Resolution(
            distributions=[
                ResolvedDistribution(
                    name=package.name,
                    version=package.version,
                    source_url=next(
                        (
                            artifact.url
                            for artifact in package.artifacts
                            if artifact.url is not None
                        ),
                        None,
                    ),
                    requires_dist=package.requires_dist,
                    artifacts=package.artifacts,
                    index_url=package.index_url,
                )
                for package in locked.packages
            ]
        )
    if staged_target.suffix.lower() == ".toml":
        try:
            with staged_target.open("rb") as stream:
                payload = tomllib.load(stream)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise RemediationError(
                f"generated TOML is invalid: {exc}"
            ) from exc
        requirements = _extract_scan_requirements_from_toml(
            payload,
            extras=args.extra,
            groups=args.group,
            base_path=staged_target.parent,
        )
        return resolver.resolve_requirements(
            requirements,
            target=target_environment,
            cwd=staged_target.parent,
            offline=offline,
        )
    staged_constraints = [
        prepared.root
        / _relative_to_resolved_root(
            Path(path),
            prepared.source_root,
        )
        for path in args.constraint
    ]
    resolution = resolver.resolve_requirements_file(
        staged_target,
        constraints=staged_constraints,
        target=target_environment,
        offline=offline,
    )
    pip_tools = load_pip_tools_lock(staged_target)
    if pip_tools is None:
        return resolution
    locked_packages = {
        str(canonicalize_name(package.name)): package
        for package in pip_tools.packages
    }
    resolution.distributions = [
        ResolvedDistribution(
            name=item.name,
            version=item.version,
            requested=item.requested,
            requested_extras=item.requested_extras,
            source_url=item.source_url,
            is_direct=item.is_direct,
            is_yanked=item.is_yanked,
            editable=item.editable,
            vcs=item.vcs,
            vcs_commit=item.vcs_commit,
            requires_dist=item.requires_dist,
            artifacts=(
                locked_packages[str(canonicalize_name(item.name))].artifacts
                if str(canonicalize_name(item.name)) in locked_packages
                else item.artifacts
            ),
            index_url=item.index_url,
        )
        for item in resolution.distributions
    ]
    return resolution


def _relative_to_resolved_root(path: Path, root: Path) -> Path:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    try:
        return resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise RemediationError(
            f"remediation path is outside the project root: {resolved_path}"
        ) from exc


def _attach_remediation_summary(
    reports: Sequence[TrustReport],
    plan: RemediationPlan,
) -> None:
    pull_request_url = (
        plan.pull_request.url
        if plan.pull_request is not None
        else None
    )
    summary = RemediationSummary(
        status=plan.status,
        minimal=plan.minimal,
        attempts=plan.attempts,
        upgrades_planned=len(plan.upgrades),
        blocked_fixes=len(plan.blocked),
        patch_files=[patch.path for patch in plan.patches],
        pull_request_url=pull_request_url,
        confidence=(
            min(
                (item.compatibility_confidence for item in plan.upgrades),
                key=lambda value: {"low": 0, "medium": 1, "high": 2}[value],
            )
            if plan.upgrades
            else None
        ),
        breaking_change_warnings=[
            item.breaking_change_warning
            for item in plan.upgrades
            if item.breaking_change_warning is not None
        ],
        minimal_secure_upgrade_proven=(
            plan.minimal_secure_upgrade_proof.get("proven") is True
        ),
    )
    for report in reports:
        report.remediation = summary


def _emit_output(rendered: str, output_file: str | None) -> None:
    if output_file is None:
        print(rendered)
        return
    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        rendered + ("" if rendered.endswith("\n") else "\n"),
        encoding="utf-8",
    )


def _build_scan_state(
    source_label: str,
    targets: Sequence[ScanTarget],
    *,
    keys: Sequence[str],
    args: argparse.Namespace,
    policy: PolicySettings,
    plugin_manager: PluginManager,
) -> ScanState | None:
    state_path = getattr(args, "resume_state", None)
    if not state_path:
        return None
    source_path = Path(source_label)
    source_digest: str | None = None
    if source_path.is_file():
        source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    fingerprint = scan_fingerprint(
        {
            "source": str(source_path.resolve()) if source_path.exists() else source_label,
            "source_sha256": source_digest,
            "targets": list(keys),
            "policy": asdict(policy),
            "options": {
                "scan_profile": getattr(args, "scan_profile", None),
                "artifact_scope": getattr(args, "artifact_scope", None),
                "sandbox": getattr(args, "sandbox", "auto"),
                "sandbox_image": getattr(args, "sandbox_image", None),
                "with_deps": getattr(args, "with_deps", False),
                "with_transitive_deps": getattr(args, "with_transitive_deps", False),
                "inspect_artifacts": getattr(args, "inspect_artifacts", False),
                "with_osv": getattr(args, "with_osv", False),
                "osv_urls": list(getattr(args, "osv_url", ())),
                "with_ecosystems": getattr(args, "with_ecosystems", False),
                "with_kev": getattr(args, "with_kev", False),
                "with_epss": getattr(args, "with_epss", False),
                "offline": getattr(args, "offline", False),
                "trusted_projects": list(getattr(args, "trusted_project", ())),
                "index": _index_configuration_from_args(args).redacted(),
                "plugins": [
                    {
                        "name": item.name,
                        "kind": item.kind,
                        "value": item.value,
                        "distribution": item.distribution,
                    }
                    for item in plugin_manager.descriptors()
                ],
            },
            "target_count": len(targets),
        }
    )
    return ScanState(
        state_path,
        fingerprint=fingerprint,
        target_keys=keys,
    )


def _clone_pypi_client(client: PypiClient) -> PypiClient:
    if type(client) is not PypiClient:
        return client
    return PypiClient(
        base_url=client.base_url,
        timeout=client.timeout,
        user_agent=client.user_agent,
        max_retries=client.max_retries,
        backoff_factor=client.backoff_factor,
        enable_cache=client.enable_cache,
        cache_dir=client.cache_dir,
        offline=client.offline,
        request_hook=client.request_hook,
        sleep=client.sleep,
        http_pool=client.http_pool,
    )


def _synchronized_progress_callback(
    callback: ProgressCallback | None,
    lock: threading.Lock,
) -> ProgressCallback | None:
    if callback is None:
        return None

    def emit(filename: str, current: int, total: int) -> None:
        with lock:
            callback(filename, current, total)

    return emit


def _synchronized_dependency_progress_callback(
    callback: DependencyProgressCallback | None,
    lock: threading.Lock,
) -> DependencyProgressCallback | None:
    if callback is None:
        return None

    def emit(project: str, depth: int, percent: int, done: bool) -> None:
        with lock:
            callback(project, depth, percent, done)

    return emit


def _handle_error(message: str, exit_code: int, *, debug: bool) -> int:
    print(message, file=sys.stderr)
    if debug:
        traceback.print_exc(file=sys.stderr)
    return exit_code


def _build_progress_callback() -> ProgressCallback:
    def emit(filename: str, current: int, total: int) -> None:
        print(
            f"[progress] verifying artifact {current}/{total}: {filename}",
            file=sys.stderr,
            flush=True,
        )

    return emit


def _build_dependency_progress_callback() -> DependencyProgressCallback:
    previous_length = 0

    def emit(project: str, depth: int, percent: int, done: bool) -> None:
        nonlocal previous_length
        message = f"[progress] inspecting dependency depth={depth}: {project} ({percent}%)"
        padded_message = message.ljust(previous_length)
        end = "\n" if done else ""
        sys.stderr.write("\r" + padded_message + end)
        sys.stderr.flush()
        previous_length = 0 if done else len(message)

    return emit


def _target_environment_from_args(args: argparse.Namespace) -> TargetEnvironment:
    return TargetEnvironment(
        python_version=getattr(args, "python_version", None),
        platforms=tuple(getattr(args, "platform", ()) or ()),
        implementation=getattr(args, "implementation", None),
        abis=tuple(getattr(args, "abi", ()) or ()),
    )


def _target_marker_environment(
    target: TargetEnvironment | None,
) -> dict[str, str]:
    environment = {
        key: str(value) for key, value in default_environment().items()
    }
    if target is None:
        return environment
    if target.python_version:
        parts = target.python_version.split(".")
        environment["python_version"] = ".".join(parts[:2])
        environment["python_full_version"] = target.python_version
    if target.implementation:
        implementation = target.implementation.lower()
        implementation_names = {
            "cp": "cpython",
            "pp": "pypy",
            "py": "python",
        }
        environment["implementation_name"] = implementation_names.get(
            implementation,
            implementation,
        )
    if target.platforms:
        platform = target.platforms[0].lower()
        if "win" in platform:
            environment["sys_platform"] = "win32"
        elif "macosx" in platform:
            environment["sys_platform"] = "darwin"
        elif "linux" in platform or "manylinux" in platform or "musllinux" in platform:
            environment["sys_platform"] = "linux"
    return environment


def _index_configuration_from_args(
    args: argparse.Namespace,
) -> IndexConfiguration:
    return IndexConfiguration(
        index_url=args.index_url,
        extra_index_urls=tuple(args.extra_index_url),
        keyring_provider=args.keyring_provider,
    )


def _resolver_from_args(
    args: argparse.Namespace,
    *,
    plugin_manager: PluginManager | None = None,
) -> PipResolver:
    indexes = _index_configuration_from_args(args)
    index_client: RepositoryClient = SimpleRepositoryClient(
        keyring_provider=indexes.keyring_provider,
    )
    if plugin_manager is not None:
        index_client = plugin_manager.repository_client(index_client)
    return PipResolver(
        indexes=indexes,
        index_client=index_client,
        allow_dependency_confusion=args.allow_dependency_confusion,
        sandbox_mode=getattr(args, "sandbox", "auto"),
        container_image=getattr(args, "sandbox_image", None),
        warning_handler=lambda message: print(
            f"warning: {message}",
            file=sys.stderr,
        ),
    )


def _uses_nondefault_indexes(args: argparse.Namespace) -> bool:
    configuration = _index_configuration_from_args(args)
    return (
        redact_url_credentials(normalize_index_url(configuration.index_url))
        != normalize_index_url(DEFAULT_INDEX_URL)
        or bool(configuration.extra_index_urls)
    )


def _client_for_target(
    client: PypiClient,
    target: ScanTarget,
    *,
    keyring_provider: str,
    plugin_manager: PluginManager | None = None,
) -> PypiClient | IndexBackedPackageClient:
    if target.version is None:
        return client
    index_url = target.index_url
    artifact_urls = [
        artifact.url for artifact in target.artifacts if artifact.url
    ]
    if index_url and (
        redact_url_credentials(normalize_index_url(index_url))
        == normalize_index_url(DEFAULT_INDEX_URL)
    ):
        return client
    if not index_url and all(
        _is_pypi_artifact_url(url) for url in artifact_urls
    ):
        return client
    if not index_url and not artifact_urls:
        return client
    if index_url is None:
        parsed = parse.urlsplit(artifact_urls[0])
        index_url = f"{parsed.scheme}://{parsed.netloc}/"
    repository_client: RepositoryClient = SimpleRepositoryClient(
        timeout=client.timeout,
        keyring_provider=keyring_provider,
    )
    if plugin_manager is not None:
        repository_client = plugin_manager.repository_client(repository_client)
    return IndexBackedPackageClient(
        base_client=client,
        project=target.project,
        version=target.version,
        index_url=index_url,
        artifacts=target.artifacts,
        requires_dist=target.requires_dist,
        repository_client=repository_client,
    )


def _is_pypi_artifact_url(url: str) -> bool:
    hostname = (parse.urlsplit(url).hostname or "").lower()
    return hostname in {"files.pythonhosted.org", "pypi.org"}


def _build_client(
    args: argparse.Namespace,
    *,
    config_payload: dict[str, object],
    request_hook: Callable[[str, dict[str, object]], None] | None,
) -> PypiClient:
    network_config = config_payload.get("network")
    if network_config is not None and not isinstance(network_config, dict):
        raise ValueError("config file field 'network' must be an object")
    network_config = network_config or {}
    max_workers = int(getattr(args, "max_workers", None) or 8)
    return PypiClient(
        timeout=_resolve_float(
            args.timeout,
            env_name="TRUSTCHECK_TIMEOUT",
            config_value=network_config.get("timeout"),
            default=10.0,
        ),
        max_retries=_resolve_int(
            args.retries,
            env_name="TRUSTCHECK_RETRIES",
            config_value=network_config.get("retries"),
            default=2,
        ),
        backoff_factor=_resolve_float(
            args.backoff,
            env_name="TRUSTCHECK_BACKOFF",
            config_value=network_config.get("backoff_factor"),
            default=0.25,
        ),
        cache_dir=_resolve_str(
            args.cache_dir,
            env_name="TRUSTCHECK_CACHE_DIR",
            config_value=network_config.get("cache_dir"),
        ),
        offline=_resolve_bool(
            args.offline,
            env_name="TRUSTCHECK_OFFLINE",
            config_value=network_config.get("offline"),
            default=False,
        ),
        request_hook=request_hook,
        http_pool=urllib3.PoolManager(
            num_pools=max_workers,
            maxsize=max_workers,
            block=True,
            retries=False,
        ),
    )


def _build_osv_client(
    client: PypiClient,
    *,
    base_url: str = OSV_BASE_URL,
    max_workers: int = 8,
) -> OsvClient:
    return OsvClient(
        base_url=base_url.rstrip("/"),
        timeout=client.timeout,
        max_retries=client.max_retries,
        backoff_factor=client.backoff_factor,
        offline=client.offline,
        max_workers=max_workers,
        request_hook=client.request_hook,
    )


def _build_vulnerability_client(
    args: argparse.Namespace,
    client: PypiClient,
    *,
    config_payload: dict[str, object],
    plugin_manager: PluginManager | None = None,
) -> VulnerabilityIntelligenceClient | None:
    raw_config = config_payload.get("advisories")
    if raw_config is not None and not isinstance(raw_config, dict):
        raise ValueError("config file field 'advisories' must be an object")
    advisory_config = raw_config or {}
    allowed = {
        "osv",
        "osv_urls",
        "ecosystems",
        "kev",
        "kev_url",
        "epss",
        "epss_url",
    }
    unknown = sorted(set(advisory_config) - allowed)
    if unknown:
        raise ValueError(
            "unknown advisories config setting(s): " + ", ".join(unknown)
        )

    max_workers = _resolve_max_workers(args, config_payload)
    providers: list[OsvProvider] = []
    seen_urls: set[str] = set()
    source_urls: list[str] = []

    def add_provider(name: str, base_url: str) -> None:
        normalized = base_url.strip().rstrip("/")
        if not normalized or normalized in seen_urls:
            return
        seen_urls.add(normalized)
        source_urls.append(normalized)
        provider_client = _build_osv_client(
            client,
            base_url=normalized,
            max_workers=max_workers,
        )
        provider_client.request_hook = None
        providers.append(
            OsvProvider(
                name=name,
                client=provider_client,
            )
        )

    if args.with_osv or _config_bool(advisory_config, "osv"):
        add_provider("OSV", OSV_BASE_URL)

    custom_urls = [
        *getattr(args, "osv_url", []),
        *_config_string_list(advisory_config, "osv_urls"),
    ]
    for base_url in custom_urls:
        hostname = parse.urlsplit(base_url).hostname or base_url
        add_provider(f"OSV:{hostname}", base_url)

    if args.with_ecosystems or _config_bool(advisory_config, "ecosystems"):
        add_provider("Ecosyste.ms", ECOSYSTEMS_OSV_BASE_URL)

    kev_enabled = args.with_kev or _config_bool(advisory_config, "kev")
    epss_enabled = args.with_epss or _config_bool(advisory_config, "epss")
    advisory_sources = (
        plugin_manager.advisory_sources()
        if plugin_manager is not None
        else ()
    )
    kev_url = _config_string(
        advisory_config,
        "kev_url",
        default=CISA_KEV_URL,
    )
    epss_url = _config_string(
        advisory_config,
        "epss_url",
        default=EPSS_BASE_URL,
    )
    if kev_enabled:
        source_urls.append(kev_url)
    if epss_enabled:
        source_urls.append(epss_url)
    snapshot_store = AdvisorySnapshotStore(
        inputs=getattr(args, "advisory_snapshot", ()),
        output=getattr(args, "write_advisory_snapshot", None),
        source_urls=source_urls,
        max_age=timedelta(
            hours=getattr(
                args,
                "max_advisory_age",
                DEFAULT_MAX_ADVISORY_AGE_HOURS,
            )
        ),
        sigstore_identity=getattr(args, "advisory_snapshot_identity", None),
        sigstore_issuer=getattr(args, "advisory_snapshot_issuer", None),
        allow_unsigned=getattr(args, "allow_unsigned_advisory_snapshot", False),
        sign_output=getattr(args, "sign_advisory_snapshot", False),
        offline=client.offline,
    )
    if (
        not providers
        and not kev_enabled
        and not epss_enabled
        and not advisory_sources
        and not snapshot_store.sources
        and snapshot_store.output is None
    ):
        return None

    return VulnerabilityIntelligenceClient(
        providers=tuple(providers),
        advisory_sources=advisory_sources,
        kev_client=(
            CisaKevClient(
                url=kev_url,
                timeout=client.timeout,
                max_retries=client.max_retries,
                backoff_factor=client.backoff_factor,
                offline=client.offline,
            )
            if kev_enabled
            else None
        ),
        epss_client=(
            EpssClient(
                base_url=epss_url,
                timeout=client.timeout,
                max_retries=client.max_retries,
                backoff_factor=client.backoff_factor,
                offline=client.offline,
            )
            if epss_enabled
            else None
        ),
        snapshot_store=snapshot_store,
        max_workers=max_workers,
        request_hook=client.request_hook,
    )


def _resolve_max_workers(
    args: argparse.Namespace,
    config_payload: dict[str, object],
) -> int:
    raw_config = config_payload.get("performance")
    if raw_config is not None and not isinstance(raw_config, dict):
        raise ValueError("config file field 'performance' must be an object")
    performance_config = raw_config or {}
    unknown = sorted(set(performance_config) - {"max_workers"})
    if unknown:
        raise ValueError(
            "unknown performance config setting(s): " + ", ".join(unknown)
        )
    workers = _resolve_int(
        getattr(args, "max_workers", None),
        env_name="TRUSTCHECK_MAX_WORKERS",
        config_value=performance_config.get("max_workers"),
        default=8,
    )
    if workers < 1 or workers > 64:
        raise ValueError("max_workers must be between 1 and 64")
    return workers


def _config_bool(config: dict[str, object], name: str) -> bool:
    value = config.get(name, False)
    if not isinstance(value, bool):
        raise ValueError(f"advisories.{name} must be a boolean")
    return value


def _config_string_list(
    config: dict[str, object],
    name: str,
) -> list[str]:
    value = config.get(name, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip()
        for item in value
    ):
        raise ValueError(f"advisories.{name} must be a list of URLs")
    return [item.strip() for item in value]


def _config_string(
    config: dict[str, object],
    name: str,
    *,
    default: str,
) -> str:
    value = config.get(name, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"advisories.{name} must be a URL")
    return value.strip()


def _load_config_file(path: str | None) -> dict[str, object]:
    if path:
        return _load_config_path(Path(path), explicit=True)
    standalone = Path.cwd() / ".trustcheck.toml"
    if standalone.is_file():
        return _load_config_path(standalone, explicit=False)
    pyproject = Path.cwd() / "pyproject.toml"
    if pyproject.is_file():
        return _load_config_path(pyproject, explicit=False)
    return {}


def _load_config_path(path: Path, *, explicit: bool) -> dict[str, object]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    elif suffix == ".toml":
        with path.open("rb") as config_file:
            payload = tomllib.load(config_file)
        if path.name == "pyproject.toml":
            tool = payload.get("tool")
            trustcheck = tool.get("trustcheck") if isinstance(tool, dict) else None
            if trustcheck is None:
                if explicit:
                    raise ValueError("pyproject.toml does not contain [tool.trustcheck]")
                return {}
            payload = trustcheck
        elif "tool" in payload and len(payload) == 1:
            tool = payload.get("tool")
            trustcheck = tool.get("trustcheck") if isinstance(tool, dict) else None
            if isinstance(trustcheck, dict):
                payload = trustcheck
    else:
        raise ValueError("config file must use a .json or .toml extension")
    if not isinstance(payload, dict):
        if suffix == ".json":
            raise ValueError("config file must contain a top-level JSON object")
        raise ValueError("config file must contain a configuration table")
    return payload


def _apply_project_config(
    args: argparse.Namespace,
    config: dict[str, object],
) -> None:
    explicit = set(getattr(args, "_explicit_config_fields", ()))
    allowed = {
        "policy",
        "with_osv",
        "with_kev",
        "scan_profile",
        "artifact_scope",
        "network",
        "advisories",
        "performance",
    }
    unknown = sorted(set(config) - allowed)
    if unknown:
        raise ValueError("unknown project config setting(s): " + ", ".join(unknown))

    args.policy = _resolve_choice(
        getattr(args, "policy", None) if "policy" in explicit else None,
        env_name="TRUSTCHECK_POLICY",
        config_value=config.get("policy"),
        default="default",
        choices=set(BUILTIN_POLICIES),
    )
    if hasattr(args, "with_osv"):
        args.with_osv = _resolve_bool(
            args.with_osv if "with_osv" in explicit else False,
            env_name="TRUSTCHECK_WITH_OSV",
            config_value=config.get("with_osv"),
            default=False,
        )
    if hasattr(args, "with_kev"):
        args.with_kev = _resolve_bool(
            args.with_kev if "with_kev" in explicit else False,
            env_name="TRUSTCHECK_WITH_KEV",
            config_value=config.get("with_kev"),
            default=False,
        )
    if hasattr(args, "scan_profile"):
        args.scan_profile = _resolve_choice(
            args.scan_profile if "scan_profile" in explicit else None,
            env_name="TRUSTCHECK_SCAN_PROFILE",
            config_value=config.get("scan_profile"),
            default="fast",
            choices={"fast", "standard", "full"},
        )
    if hasattr(args, "artifact_scope"):
        args.artifact_scope = _resolve_choice(
            args.artifact_scope if "artifact_scope" in explicit else None,
            env_name="TRUSTCHECK_ARTIFACT_SCOPE",
            config_value=config.get("artifact_scope"),
            default="target",
            choices={"target", "sdist", "all"},
        )


def _explicit_config_fields(argv: Sequence[str]) -> set[str]:
    flags = {
        "--policy": "policy",
        "--with-osv": "with_osv",
        "--with-kev": "with_kev",
        "--fast": "scan_profile",
        "--standard": "scan_profile",
        "--full": "scan_profile",
        "--artifact-scope": "artifact_scope",
    }
    explicit: set[str] = set()
    for token in argv:
        flag = token.split("=", 1)[0]
        destination = flags.get(flag)
        if destination is not None:
            explicit.add(destination)
    return explicit


def _resolve_choice(
    cli_value: str | None,
    *,
    env_name: str,
    config_value: object,
    default: str,
    choices: set[str],
) -> str:
    value: object = cli_value
    if value is None:
        value = os.getenv(env_name)
    if value is None:
        value = config_value
    if value is None:
        value = default
    if not isinstance(value, str) or value not in choices:
        raise ValueError(
            f"{env_name} or project config must be one of: "
            + ", ".join(sorted(choices))
        )
    return value


def _resolve_float(
    cli_value: float | None,
    *,
    env_name: str,
    config_value: object,
    default: float,
) -> float:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return float(env_value)
    if config_value is not None and isinstance(config_value, (str, int, float)):
        return float(config_value)
    return default


def _resolve_int(
    cli_value: int | None,
    *,
    env_name: str,
    config_value: object,
    default: int,
) -> int:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return int(env_value)
    if config_value is not None and isinstance(config_value, (str, int, float)):
        return int(config_value)
    return default


def _resolve_str(
    cli_value: str | None,
    *,
    env_name: str,
    config_value: object,
) -> str | None:
    if cli_value is not None:
        return cli_value
    env_value = os.getenv(env_name)
    if env_value is not None:
        return env_value
    if config_value is not None:
        return str(config_value)
    return None


def _resolve_bool(
    cli_value: bool,
    *,
    env_name: str,
    config_value: object,
    default: bool,
) -> bool:
    if cli_value:
        return True
    env_value = os.getenv(env_name)
    if env_value is not None:
        return _parse_bool(env_value, field=env_name)
    if config_value is not None:
        if isinstance(config_value, bool):
            return config_value
        if isinstance(config_value, str):
            return _parse_bool(config_value, field=f"{env_name} project config value")
        raise ValueError(f"{env_name} project config value must be a boolean")
    return default


def _parse_bool(value: str, *, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"{field} must be one of: 0, 1, false, true, no, yes, off, on"
    )


def _build_debug_request_hook(
    *,
    enabled: bool,
    log_format: str,
) -> Callable[[str, dict[str, object]], None] | None:
    if not enabled:
        return None

    def emit(event: str, payload: dict[str, object]) -> None:
        record = {"event": event, **payload}
        if log_format == "json":
            print(json.dumps(record, sort_keys=True), file=sys.stderr, flush=True)
        else:
            parts = [f"event={event}"] + [
                f"{key}={value}" for key, value in sorted(payload.items())
            ]
            print("[debug] " + " ".join(parts), file=sys.stderr, flush=True)

    return emit


def _format_upstream_error(exc: PypiClientError) -> str:
    if exc.code == "advisory":
        source = "advisory service"
    elif exc.code == "dependency":
        source = "dependency resolver"
    else:
        source = "PyPI"
    return (
        f"error: unable to inspect package from {source}: "
        f"{exc} [code={exc.code} subcode={exc.subcode}]"
    )


def _merge_exit_codes(current: int, new: int) -> int:
    if current == EXIT_REMEDIATION_FAILURE or new == EXIT_REMEDIATION_FAILURE:
        return EXIT_REMEDIATION_FAILURE
    if current == EXIT_DATA_ERROR or new == EXIT_DATA_ERROR:
        return EXIT_DATA_ERROR
    if current == EXIT_UPSTREAM_FAILURE or new == EXIT_UPSTREAM_FAILURE:
        return EXIT_UPSTREAM_FAILURE
    if current == EXIT_POLICY_FAILURE or new == EXIT_POLICY_FAILURE:
        return EXIT_POLICY_FAILURE
    return max(current, new)


def _load_scan_targets(
    path: str,
    client: PypiClient,
    *,
    resolver: PipResolver | None = None,
    constraints: Sequence[str | Path] = (),
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    target_environment: TargetEnvironment | None = None,
    offline: bool = False,
) -> list[ScanTarget]:
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError(f"scan file not found: {path}")

    if is_supported_lockfile(file_path):
        lockfile_resolution = load_lockfile(
            file_path,
            extras=extras,
            groups=groups,
            environment=_target_marker_environment(target_environment),
        )
        return _attach_source_locations(
            _scan_targets_from_lockfile(
                lockfile_resolution,
                resolver=resolver,
            ),
            file_path,
        )

    if file_path.suffix.lower() == ".toml":
        return _attach_source_locations(
            _load_scan_targets_from_toml(
                file_path,
                client,
                resolver=resolver,
                constraints=constraints,
                extras=extras,
                groups=groups,
                target_environment=target_environment,
                offline=offline,
            ),
            file_path,
        )

    if resolver is not None:
        pip_resolution = resolver.resolve_requirements_file(
            file_path,
            constraints=constraints,
            target=target_environment,
            offline=offline,
        )
        pip_tools_resolution = load_pip_tools_lock(file_path)
        return _attach_source_locations(
            _scan_targets_from_resolution(
                pip_resolution,
                lockfile_resolution=pip_tools_resolution,
            ),
            file_path,
        )

    requirement_lines = _read_requirements_file(file_path)
    locked_versions = _locked_versions_from_requirements(
        requirement_lines,
        source_path=file_path,
    )
    return _attach_source_locations(
        _build_scan_targets(
            requirement_lines,
            client,
            source_path=file_path,
            locked_versions=locked_versions,
        ),
        file_path,
    )


def _attach_source_locations(
    targets: list[ScanTarget],
    source_path: Path,
) -> list[ScanTarget]:
    resolved_path = source_path.resolve()
    lines = resolved_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()
    for target in targets:
        target.source_file = str(resolved_path)
        target.source_line = _source_line_for_project(lines, target.project)
    return targets


def _source_line_for_project(
    lines: Sequence[str],
    project: str,
) -> int | None:
    normalized = canonicalize_name(project)
    project_pattern = re.escape(normalized).replace(r"\-", "[-_.]+")
    pattern = re.compile(
        rf"(?<![A-Za-z0-9]){project_pattern}"
        r"(?![A-Za-z0-9])",
        re.IGNORECASE,
    )
    for line_number, line in enumerate(lines, 1):
        if pattern.search(line):
            return line_number
    return None


def _load_scan_targets_from_toml(
    file_path: Path,
    client: PypiClient,
    *,
    resolver: PipResolver | None = None,
    constraints: Sequence[str | Path] = (),
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    target_environment: TargetEnvironment | None = None,
    offline: bool = False,
) -> list[ScanTarget]:
    try:
        with file_path.open("rb") as toml_file:
            payload = tomllib.load(toml_file)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid TOML in {file_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"TOML file must contain a top-level table: {file_path}")

    requirement_lines = _extract_scan_requirements_from_toml(
        payload,
        extras=extras,
        groups=groups,
        base_path=file_path.parent,
    )
    if not requirement_lines:
        raise ValueError(f"no supported package requirements found in {file_path}")

    if resolver is not None:
        resolution = resolver.resolve_requirements(
            requirement_lines,
            constraints=constraints,
            target=target_environment,
            cwd=file_path.parent,
            offline=offline,
        )
        return _scan_targets_from_resolution(resolution)

    return _build_scan_targets(
        requirement_lines,
        client,
        source_path=file_path,
        entry_label="entry",
    )


def _build_scan_targets(
    requirement_lines: list[str],
    client: PypiClient,
    *,
    source_path: Path,
    locked_versions: dict[str, str] | None = None,
    complete_locked_versions: bool = False,
    entry_label: str = "line",
) -> list[ScanTarget]:
    environment = {key: str(value) for key, value in default_environment().items()}
    environment.setdefault("extra", "")
    resolved_versions = locked_versions or {}
    targets: list[ScanTarget] = []
    for line_number, line in enumerate(requirement_lines, 1):
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise ValueError(
                f"invalid requirement in {source_path} at {entry_label} {line_number}: {exc}"
            ) from exc
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        version, failure_message, failure_exit_code = _resolve_scan_target_version_for_scan(
            requirement,
            client,
        )
        targets.append(
            ScanTarget(
                requirement=line,
                project=requirement.name,
                version=version,
                failure_message=failure_message,
                failure_exit_code=failure_exit_code,
                locked_versions=resolved_versions,
                complete_locked_versions=complete_locked_versions,
            )
        )
    if not targets:
        raise ValueError(f"no supported package requirements found in {source_path}")
    return targets


def _scan_targets_from_resolution(
    resolution: Resolution,
    *,
    lockfile_resolution: LockfileResolution | None = None,
) -> list[ScanTarget]:
    if not resolution.distributions:
        raise ResolutionError("dependency resolution produced no distributions")
    versions = resolution.versions
    locked_packages = (
        {
            canonicalize_name(package.name): package
            for package in lockfile_resolution.packages
        }
        if lockfile_resolution is not None
        else {}
    )
    confusion = {
        canonicalize_name(finding.project): finding.indexes
        for finding in resolution.dependency_confusion
    }
    return [
        _scan_target_from_resolved_distribution(
            item,
            versions,
            locked_package=locked_packages.get(canonicalize_name(item.name)),
            dependency_confusion=confusion.get(
                canonicalize_name(item.name),
                (),
            ),
        )
        for item in resolution.distributions
    ]


def _scan_target_from_resolved_distribution(
    item: ResolvedDistribution,
    versions: dict[str, str],
    *,
    locked_package: LockedPackage | None = None,
    dependency_confusion: tuple[str, ...] = (),
) -> ScanTarget:
    artifacts = (
        locked_package.artifacts
        if locked_package is not None and locked_package.artifacts
        else item.artifacts
    )
    return ScanTarget(
        requirement=f"{item.name}=={item.version}",
        project=item.name,
        version=item.version,
        locked_versions=versions,
        complete_locked_versions=True,
        source_url=item.source_url,
        requested=item.requested,
        editable=item.editable,
        vcs=item.vcs,
        vcs_commit=item.vcs_commit,
        artifacts=artifacts,
        index_url=(
            locked_package.index_url
            if locked_package is not None and locked_package.index_url
            else item.index_url
        ),
        requires_dist=(
            locked_package.requires_dist
            if locked_package is not None and locked_package.requires_dist
            else item.requires_dist
        ),
        dependency_confusion=dependency_confusion,
        source_type=(
            "vcs"
            if item.vcs is not None
            else "directory"
            if item.editable
            else "direct"
            if item.is_direct
            else (
                locked_package.source_type
                if locked_package is not None
                else "index"
            )
        ),
    )


def _scan_targets_from_lockfile(
    resolution: LockfileResolution,
    *,
    resolver: PipResolver | None = None,
) -> list[ScanTarget]:
    findings: dict[str, tuple[str, ...]] = {}
    if resolver is not None:
        detected = resolver.check_dependency_confusion(
            [package.name for package in resolution.packages],
            additional_indexes=[
                package.index_url
                for package in resolution.packages
                if package.index_url is not None
            ],
        )
        findings = {
            canonicalize_name(finding.project): finding.indexes
            for finding in detected
        }
    targets = [
        ScanTarget(
            requirement=package.requirement,
            project=package.name,
            version=package.version,
            locked_versions=resolution.versions,
            complete_locked_versions=True,
            source_url=next(
                (
                    artifact.url
                    for artifact in package.artifacts
                    if artifact.url is not None
                ),
                None,
            ),
            artifacts=package.artifacts,
            index_url=package.index_url,
            requires_dist=package.requires_dist,
            dependency_confusion=findings.get(
                canonicalize_name(package.name),
                (),
            ),
            source_type=package.source_type,
        )
        for package in resolution.packages
    ]
    targets.extend(
        ScanTarget(
            requirement=warning,
            project=warning.split(":", 1)[0],
            failure_message=warning,
            failure_exit_code=EXIT_DATA_ERROR,
            locked_versions=resolution.versions,
            complete_locked_versions=True,
        )
        for warning in resolution.warnings
    )
    return targets


def _read_requirements_file(file_path: Path) -> list[str]:
    requirements: list[str] = []
    pending = ""
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.rstrip()
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment.strip()}".strip()
        if continued:
            continue

        line = _strip_requirement_hashes(_clean_requirement_line(pending))
        pending = ""
        if line and not line.startswith(("-", "--")):
            requirements.append(line)

    if pending:
        line = _strip_requirement_hashes(_clean_requirement_line(pending))
        if line and not line.startswith(("-", "--")):
            requirements.append(line)
    return requirements


def _strip_requirement_hashes(line: str) -> str:
    if not line:
        return line
    return re.split(r"\s+--hash(?:=|\s+)", line, maxsplit=1)[0].rstrip()


def _locked_versions_from_requirements(
    requirement_lines: list[str],
    *,
    source_path: Path,
) -> dict[str, str]:
    environment = {key: str(value) for key, value in default_environment().items()}
    environment.setdefault("extra", "")
    versions: dict[str, str] = {}
    for line_number, line in enumerate(requirement_lines, 1):
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        if requirement.marker is not None and not requirement.marker.evaluate(environment):
            continue
        version = _exact_scan_target_version(requirement)
        if version is None:
            continue
        key = canonicalize_name(requirement.name)
        existing_version = versions.get(key)
        if existing_version is not None and existing_version != version:
            raise ValueError(
                f"multiple active locked versions for {requirement.name!r} in "
                f"{source_path}: {existing_version} and {version}"
            )
        versions[key] = version
    return versions


def _extract_scan_requirements_from_toml(
    payload: dict[str, object],
    *,
    extras: Sequence[str] = (),
    groups: Sequence[str] = (),
    base_path: Path | None = None,
) -> list[str]:
    requirements: list[str] = []
    available_extras: dict[str, tuple[str, object]] = {}
    available_groups: dict[str, tuple[str, object, str]] = {}

    project = payload.get("project")
    if isinstance(project, dict):
        requirements.extend(_collect_requirement_strings(project.get("dependencies")))
        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for name, extra_requirements in optional_dependencies.items():
                key = canonicalize_name(str(name))
                if key in available_extras:
                    raise ValueError(f"duplicate optional dependency extra: {name}")
                available_extras[key] = (str(name), extra_requirements)

    standard_groups = payload.get("dependency-groups")
    if isinstance(standard_groups, dict):
        for name, group_payload in standard_groups.items():
            key = canonicalize_name(str(name))
            if key in available_groups:
                raise ValueError(f"duplicate dependency group: {name}")
            available_groups[key] = (str(name), group_payload, "standard")

    selected_extras = (
        [canonicalize_name(name) for name in extras]
        if extras
        else list(available_extras)
    )
    for extra_key in selected_extras:
        extra_entry = available_extras.get(extra_key)
        if extra_entry is None:
            raise ValueError(f"unknown optional dependency extra: {extra_key}")
        requirements.extend(_collect_requirement_strings(extra_entry[1]))

    tool = payload.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            requirements.extend(
                _extract_poetry_dependency_requirements(
                    poetry.get("dependencies"),
                    base_path=base_path,
                )
            )
            poetry_groups = poetry.get("group")
            if isinstance(poetry_groups, dict):
                for name, group_payload in poetry_groups.items():
                    if not isinstance(group_payload, dict):
                        continue
                    key = canonicalize_name(str(name))
                    if key in available_groups:
                        raise ValueError(
                            f"dependency group {name!r} is defined more than once"
                        )
                    available_groups[key] = (
                        str(name),
                        group_payload.get("dependencies"),
                        "poetry",
                    )
        pdm = tool.get("pdm")
        if isinstance(pdm, dict):
            pdm_groups = pdm.get("dev-dependencies")
            if isinstance(pdm_groups, dict):
                for name, group_payload in pdm_groups.items():
                    key = canonicalize_name(str(name))
                    if key in available_groups:
                        raise ValueError(
                            f"dependency group {name!r} is defined more than once"
                        )
                    available_groups[key] = (
                        str(name),
                        group_payload,
                        "pdm",
                    )

    selected_groups = (
        [canonicalize_name(name) for name in groups]
        if groups
        else list(available_groups)
    )
    for group_key in selected_groups:
        group_entry = available_groups.get(group_key)
        if group_entry is None:
            raise ValueError(f"unknown dependency group: {group_key}")
        if group_entry[2] == "poetry":
            requirements.extend(
                _extract_poetry_dependency_requirements(
                    group_entry[1],
                    base_path=base_path,
                )
            )
        elif group_entry[2] == "pdm":
            requirements.extend(
                _collect_requirement_strings(group_entry[1])
            )
        else:
            requirements.extend(
                _resolve_standard_dependency_group(
                    available_groups,
                    group_key,
                )
            )

    deduped: list[str] = []
    seen: set[str] = set()
    for requirement in requirements:
        if requirement not in seen:
            deduped.append(requirement)
            seen.add(requirement)
    return deduped


def _resolve_standard_dependency_group(
    available_groups: dict[str, tuple[str, object, str]],
    group: str,
    past_groups: tuple[str, ...] = (),
) -> list[str]:
    if group in past_groups:
        chain = " -> ".join((*past_groups, group))
        raise ValueError(f"cyclic dependency group include: {chain}")
    entry = available_groups.get(group)
    if entry is None or entry[2] != "standard":
        raise ValueError(f"unknown standard dependency group: {group}")
    raw_group = entry[1]
    if not isinstance(raw_group, list):
        raise ValueError(f"dependency group {entry[0]!r} must be a list")

    requirements: list[str] = []
    for item in raw_group:
        if isinstance(item, str):
            try:
                Requirement(item)
            except InvalidRequirement as exc:
                raise ValueError(
                    f"invalid requirement in dependency group {entry[0]!r}: {exc}"
                ) from exc
            requirements.append(item)
            continue
        if isinstance(item, dict) and tuple(item) == ("include-group",):
            include_name = item["include-group"]
            if not isinstance(include_name, str):
                raise ValueError(
                    f"dependency group include in {entry[0]!r} must name a group"
                )
            requirements.extend(
                _resolve_standard_dependency_group(
                    available_groups,
                    canonicalize_name(include_name),
                    (*past_groups, group),
                )
            )
            continue
        raise ValueError(f"invalid dependency group item in {entry[0]!r}: {item!r}")
    return requirements


def _collect_requirement_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if isinstance(item, str) and item.strip()]


def _extract_poetry_dependency_requirements(
    value: object,
    *,
    base_path: Path | None = None,
) -> list[str]:
    if not isinstance(value, dict):
        return []
    requirements: list[str] = []
    for name, spec in value.items():
        if str(name).lower() == "python":
            continue
        requirement = _poetry_dependency_to_requirement(
            str(name),
            spec,
            base_path=base_path,
        )
        if requirement:
            requirements.append(requirement)
    return requirements


def _poetry_dependency_to_requirement(
    name: str,
    spec: object,
    *,
    base_path: Path | None = None,
) -> str | None:
    if isinstance(spec, str):
        cleaned = spec.strip()
        if not cleaned or cleaned == "*":
            return name
        translated = _translate_poetry_version_specifier(cleaned)
        if translated is not None:
            return f"{name}{translated}"
        return f"{name}{cleaned}"
    if isinstance(spec, dict):
        extras = spec.get("extras")
        requirement_name = name
        if isinstance(extras, list):
            selected_extras = [
                item for item in extras if isinstance(item, str) and item
            ]
            if selected_extras:
                requirement_name = f"{name}[{','.join(selected_extras)}]"
        marker = spec.get("markers")
        marker_suffix = (
            f"; {marker}"
            if isinstance(marker, str) and marker.strip()
            else ""
        )
        git = spec.get("git")
        if isinstance(git, str) and git.strip():
            url = git.strip()
            if not url.startswith("git+"):
                url = f"git+{url}"
            reference = next(
                (
                    str(spec[key]).strip()
                    for key in ("rev", "tag", "branch")
                    if spec.get(key) is not None and str(spec[key]).strip()
                ),
                None,
            )
            if reference:
                url = f"{url}@{reference}"
            return f"{requirement_name} @ {url}{marker_suffix}"
        direct_url = spec.get("url")
        if isinstance(direct_url, str) and direct_url.strip():
            return f"{requirement_name} @ {direct_url.strip()}{marker_suffix}"
        path = spec.get("path")
        if isinstance(path, str) and path.strip():
            resolved_path = Path(path)
            if not resolved_path.is_absolute() and base_path is not None:
                resolved_path = base_path / resolved_path
            return (
                f"{requirement_name} @ "
                f"{resolved_path.resolve().as_uri()}{marker_suffix}"
            )
        version = spec.get("version")
        if version is None or str(version).strip() in {"", "*"}:
            return f"{requirement_name}{marker_suffix}"
        cleaned = str(version).strip()
        translated = _translate_poetry_version_specifier(cleaned)
        if translated is not None:
            return f"{requirement_name}{translated}{marker_suffix}"
        return f"{requirement_name}{cleaned}{marker_suffix}"
    return None


def _translate_poetry_version_specifier(spec: str) -> str | None:
    if spec.startswith("^"):
        return _expand_poetry_caret_specifier(spec[1:])
    if spec.startswith("~"):
        return _expand_poetry_tilde_specifier(spec[1:])
    return None


def _expand_poetry_caret_specifier(version_text: str) -> str:
    release = _parse_version_release_parts(version_text)
    upper = list(release)
    if release[0] != 0:
        upper[0] += 1
        upper = upper[:1]
    elif len(release) > 1 and release[1] != 0:
        upper[1] += 1
        upper = upper[:2]
    elif len(release) > 2:
        upper[2] += 1
        upper = upper[:3]
    else:
        upper[0] = 1
        upper = upper[:1]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _expand_poetry_tilde_specifier(version_text: str) -> str:
    release = _parse_version_release_parts(version_text)
    upper = list(release)
    if len(upper) == 1:
        upper[0] += 1
        upper = upper[:1]
    else:
        upper[1] += 1
        upper = upper[:2]
    return f">={version_text},<{'.'.join(str(part) for part in upper)}"


def _parse_version_release_parts(version_text: str) -> tuple[int, ...]:
    try:
        return Version(version_text).release
    except InvalidVersion:
        return (0,)


def _clean_requirement_line(raw_line: str) -> str:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return ""
    if " #" in line:
        line = line.split(" #", maxsplit=1)[0].rstrip()
    return line


def _resolve_scan_target_version_for_scan(
    requirement: Requirement,
    client: PypiClient,
) -> tuple[str | None, str | None, int]:
    try:
        return _resolve_scan_target_version(requirement, client), None, EXIT_OK
    except PypiClientError as exc:
        return None, _format_upstream_error(exc), EXIT_UPSTREAM_FAILURE
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return (
            None,
            f"error: unable to resolve scan requirement {requirement!s}: {exc}",
            EXIT_DATA_ERROR,
        )


def _resolve_scan_target_version(requirement: Requirement, client: PypiClient) -> str | None:
    exact_version = _exact_scan_target_version(requirement)
    if exact_version is not None:
        return exact_version
    if not requirement.specifier:
        return None

    payload = client.get_project(requirement.name)
    info = payload.get("info") or {}
    releases = payload.get("releases") or {}
    versions: list[Version] = []
    version_map: dict[Version, str] = {}

    if isinstance(releases, dict):
        for raw_version in releases:
            try:
                parsed = Version(str(raw_version))
            except InvalidVersion:
                continue
            if not requirement.specifier.contains(parsed, prereleases=None):
                continue
            versions.append(parsed)
            version_map[parsed] = str(raw_version)

    if versions:
        return version_map[max(versions)]

    fallback = info.get("version")
    if isinstance(fallback, str) and fallback:
        try:
            parsed_fallback = Version(fallback)
        except InvalidVersion:
            parsed_fallback = None
        if parsed_fallback is not None and requirement.specifier.contains(
            parsed_fallback,
            prereleases=None,
        ):
            return fallback
    raise ValueError(f"unable to resolve a compatible version for requirement {requirement!s}")


def _exact_scan_target_version(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1:
        return None
    specifier = specifiers[0]
    if specifier.operator == "===":
        return specifier.version
    if specifier.operator == "==" and not specifier.version.endswith(".*"):
        return specifier.version
    return None


def _render_text_report(report: TrustReport, *, verbose: bool = False) -> str:
    lines: list[str] = [
        f"trustcheck report for {report.project} {report.version}",
        "",
        "summary:",
        f"  recommendation: {report.recommendation}",
        f"  package: {report.package_url}",
    ]

    if report.summary:
        lines.append(f"  package summary: {report.summary}")

    lines.append(
        "  verification: "
        f"{report.coverage.verified_files}/{report.coverage.total_files} artifact(s) verified "
        f"({report.coverage.status})"
    )
    lines.append(
        "  publisher trust: "
        f"{report.publisher_trust.depth_label} "
        f"(score={report.publisher_trust.depth_score})"
    )
    lines.append(
        f"  policy: {report.policy.profile} ({'pass' if report.policy.passed else 'fail'})"
    )
    lines.append(
        "  diagnostics: "
        f"requests={report.diagnostics.request_count} "
        f"retries={report.diagnostics.retry_count} "
        f"failures={len(report.diagnostics.request_failures)} "
        f"cache_hits={report.diagnostics.cache_hit_count}"
    )
    lines.append(
        "  malicious-package heuristics: "
        f"{report.malicious_package.level} "
        f"(score={report.malicious_package.score}, "
        f"findings={len(report.malicious_package.findings)})"
    )
    lines.append(f"  why this result: {_evidence_summary(report)}")

    reasons = _recommendation_reasons(report)
    if reasons:
        lines.append("  why this result details:")
        lines.extend(f"    - {reason}" for reason in reasons)

    if report.declared_repository_urls:
        lines.append("")
        lines.append("declared repository urls:")
        lines.extend(f"  - {url}" for url in report.declared_repository_urls)

    if report.dependency_summary.requested:
        lines.append("")
        lines.append("dependencies:")
        lines.append(
            "  summary: "
            f"declared={report.dependency_summary.total_declared} "
            f"inspected={report.dependency_summary.total_inspected} "
            f"unique={report.dependency_summary.unique_dependencies} "
            f"max_depth={report.dependency_summary.max_depth} "
            f"highest_risk={report.dependency_summary.highest_risk_recommendation}"
        )
        if report.dependency_summary.high_risk_projects:
            lines.append(
                "  high-risk dependencies: "
                + ", ".join(report.dependency_summary.high_risk_projects)
            )
        if report.dependency_summary.review_required_projects:
            lines.append(
                "  review-required dependencies: "
                + ", ".join(report.dependency_summary.review_required_projects)
            )
        if report.dependency_summary.metadata_only_projects:
            lines.append(
                "  metadata-only dependencies: "
                + ", ".join(report.dependency_summary.metadata_only_projects)
            )
        if report.dependency_summary.verified_projects:
            lines.append(
                "  verified dependencies: " + ", ".join(report.dependency_summary.verified_projects)
            )
        if verbose and report.dependencies:
            for dependency in report.dependencies:
                lines.append(
                    "  - "
                    f"{dependency.project} {dependency.version} "
                    f"(depth={dependency.depth}, recommendation={dependency.recommendation})"
                )
                lines.append(f"    requirement: {dependency.requirement}")
                if dependency.parent_project:
                    lines.append(
                        "    parent: "
                        f"{dependency.parent_project} {dependency.parent_version or 'unknown'}"
                    )
                if dependency.error:
                    lines.append(f"    note: {dependency.error}")
                elif dependency.risk_flags:
                    lines.append("    risk flags:")
                    lines.extend(
                        f"      - [{flag.severity}] {flag.code}: {flag.message}"
                        for flag in dependency.risk_flags[:3]
                    )

    if report.expected_repository:
        lines.append(f"expected repository: {report.expected_repository}")
    if report.provenance_consistency.sdist_wheel_consistent is not None:
        consistency_label = (
            "consistent" if report.provenance_consistency.sdist_wheel_consistent else "mismatch"
        )
        lines.append("")
        lines.append(f"sdist/wheel provenance consistency: {consistency_label}")
    if report.release_drift.compared_to_version:
        lines.append(f"release drift baseline: {report.release_drift.compared_to_version}")
        drift_fields = [
            name
            for name, changed in (
                ("signer", report.release_drift.signer_drift),
                ("repository", report.release_drift.publisher_repository_drift),
                ("workflow", report.release_drift.publisher_workflow_drift),
                ("builder", report.release_drift.builder_drift),
                ("source commit", report.release_drift.source_commit_drift),
                ("build type", report.release_drift.build_type_drift),
            )
            if changed
        ]
        if drift_fields:
            lines.append("release provenance changes: " + ", ".join(drift_fields))

    if report.malicious_package.findings:
        lines.append("")
        lines.append("malicious-package heuristic indicators:")
        lines.append(f"  disclaimer: {report.malicious_package.disclaimer}")
        for finding in report.malicious_package.findings:
            location = (
                f" location={finding.location}" if finding.location else ""
            )
            artifact = (
                f" artifact={finding.artifact}" if finding.artifact else ""
            )
            lines.append(
                "  - "
                f"[{finding.severity}/{finding.confidence}] {finding.code}: "
                f"{finding.message} score={finding.score}{artifact}{location}"
            )
            if verbose:
                lines.extend(
                    f"    evidence: {evidence}"
                    for evidence in finding.evidence
                )

    ownership = report.ownership or {}
    roles = ownership.get("roles") or []
    organization = ownership.get("organization")
    if organization or roles:
        lines.append("")
        lines.append("ownership:")
        if organization:
            lines.append(f"  - organization: {organization}")
        for role in roles:
            lines.append(f"  - {role.get('role')}: {role.get('user')}")

    if report.vulnerabilities:
        lines.append("")
        lines.append("vulnerabilities:")
        for vuln in report.vulnerabilities:
            lines.append(f"  - {vuln.id}: {vuln.summary}")
            details = [
                f"source={vuln.source or 'unknown'}",
                f"severity={vuln.severity or 'unknown'}",
            ]
            if vuln.cvss_score is not None:
                details.append(f"cvss={vuln.cvss_score:.1f}")
            if vuln.cwes:
                details.append(f"cwes={','.join(vuln.cwes)}")
            if vuln.fixed_in:
                details.append(f"fixed_in={','.join(vuln.fixed_in)}")
            if vuln.withdrawn:
                details.append(
                    f"withdrawn={vuln.withdrawn_at or 'yes'}"
                )
            if vuln.kev:
                details.append("kev=yes")
                if vuln.kev_due_date:
                    details.append(f"kev_due={vuln.kev_due_date}")
            if vuln.epss_score is not None:
                details.append(f"epss={vuln.epss_score:.4f}")
            if vuln.epss_percentile is not None:
                details.append(
                    f"epss_percentile={vuln.epss_percentile:.4f}"
                )
            if vuln.suppression is not None:
                details.append(
                    "suppression="
                    f"{vuln.suppression.status}:"
                    f"{vuln.suppression.owner}:"
                    f"{vuln.suppression.expires}"
                )
            if vuln.link:
                details.append(f"advisory={vuln.link}")
            lines.append(f"    {' '.join(details)}")

    if verbose:
        lines.append("")
        lines.append("files:")
        for file in report.files:
            lines.append(f"  - {file.filename}")
            lines.append(f"    provenance: {'yes' if file.has_provenance else 'no'}")
            lines.append(f"    verified: {'yes' if file.verified else 'no'}")
            lines.append(
                "    attestations: "
                f"{file.verified_attestation_count}/{file.attestation_count} verified"
            )
            if file.sha256:
                lines.append(f"    sha256: {file.sha256}")
            if file.observed_sha256:
                lines.append(f"    observed sha256: {file.observed_sha256}")
            if file.publisher_identities:
                for identity in file.publisher_identities:
                    lines.append(
                        "    publisher: "
                        f"kind={identity.kind} "
                        f"repository={identity.repository or '-'} "
                        f"workflow={identity.workflow or '-'}"
                    )
            for assessment in file.slsa_provenance:
                lines.append("    SLSA provenance:")
                lines.append(
                    f"      source: {assessment.source_repository or '-'}"
                    f"@{assessment.source_commit or '-'}"
                )
                lines.append(f"      builder: {assessment.builder_id or '-'}")
                lines.append(f"      build type: {assessment.build_type or '-'}")
                lines.append(
                    "      workflow: "
                    f"{assessment.workflow_path or '-'}"
                    f"@{assessment.workflow_ref or '-'}"
                )
                lines.append(f"      materials: {len(assessment.materials)}")
                if assessment.action_references:
                    lines.append(
                        "      actions: "
                        + ", ".join(assessment.action_references)
                    )
                for issue in assessment.issues:
                    lines.append(
                        f"      issue: [{issue.severity}] "
                        f"{issue.code}: {issue.message}"
                    )
            if file.error:
                lines.append(f"    note: {file.error}")
            if file.artifact.inspected:
                lines.append("    artifact inspection:")
                lines.append(f"      kind: {file.artifact.kind}")
                lines.append(
                    "      archive valid: "
                    + (
                        "unknown"
                        if file.artifact.archive_valid is None
                        else "yes"
                        if file.artifact.archive_valid
                        else "no"
                    )
                )
                lines.append(f"      files: {file.artifact.file_count}")
                lines.append(
                    f"      uncompressed size: {file.artifact.total_uncompressed_size} bytes"
                )
                if file.artifact.record_valid is not None:
                    lines.append(
                        "      wheel RECORD: "
                        f"{'valid' if file.artifact.record_valid else 'invalid'}"
                    )
                if file.artifact.metadata_name or file.artifact.metadata_version:
                    lines.append(
                        "      metadata: "
                        f"name={file.artifact.metadata_name or '-'} "
                        f"version={file.artifact.metadata_version or '-'}"
                    )
                if file.artifact.wheel_version:
                    lines.append(
                        "      wheel metadata: "
                        f"version={file.artifact.wheel_version} "
                        "root_is_purelib="
                        f"{file.artifact.wheel_root_is_purelib} "
                        f"tags={','.join(file.artifact.wheel_tags) or '-'}"
                    )
                _append_artifact_findings(
                    lines,
                    "console scripts",
                    file.artifact.console_scripts,
                )
                _append_artifact_findings(
                    lines,
                    "native files",
                    file.artifact.native_files,
                )
                _append_artifact_findings(
                    lines,
                    "unexpected top-level files",
                    file.artifact.unexpected_top_level_files,
                )
                _append_artifact_findings(
                    lines,
                    "suspicious entry points",
                    file.artifact.suspicious_entry_points,
                )
                _append_artifact_findings(
                    lines,
                    "suspicious files",
                    file.artifact.suspicious_files,
                )
                _append_artifact_findings(
                    lines,
                    "oversized files",
                    file.artifact.oversized_files,
                )
                _append_artifact_findings(
                    lines,
                    "unusual files",
                    file.artifact.unusual_files,
                )
                _append_artifact_findings(
                    lines,
                    "RECORD errors",
                    file.artifact.record_errors,
                )
                _append_artifact_findings(
                    lines,
                    "metadata mismatches",
                    file.artifact.metadata_mismatches,
                )
                lines.append(
                    "      Python source files analyzed: "
                    f"{file.artifact.source_files_analyzed}"
                )
                _append_artifact_findings(
                    lines,
                    "source analysis errors",
                    file.artifact.source_parse_errors,
                )
                if file.artifact.native_binaries:
                    lines.append("      native binary analysis:")
                    for native in file.artifact.native_binaries:
                        lines.append(
                            "        - "
                            f"{native.path}: format={native.format} "
                            f"architecture={native.architecture or '-'} "
                            f"signature={native.signature_status} "
                            f"entropy={native.entropy if native.entropy is not None else '-'}"
                        )
                        if native.imports:
                            lines.append(
                                "          imports: " + ", ".join(native.imports)
                            )
                        if native.embedded_payloads:
                            lines.append(
                                "          embedded payloads: "
                                + ", ".join(native.embedded_payloads)
                            )
                        if native.parse_error:
                            lines.append(f"          parse note: {native.parse_error}")
                if file.artifact.error:
                    lines.append(f"      error: {file.artifact.error}")

    lines.append("")
    lines.append("diagnostics:")
    lines.append(
        "  network: "
        f"timeout={report.diagnostics.timeout} "
        f"retries={report.diagnostics.max_retries} "
        f"backoff={report.diagnostics.backoff_factor} "
        f"offline={report.diagnostics.offline} "
        f"cache_dir={report.diagnostics.cache_dir or '-'}"
    )
    if report.diagnostics.request_failures:
        lines.append("  request failures:")
        lines.extend(
            "    - "
            f"[{failure.subcode}] attempt={failure.attempt} "
            f"status={failure.status_code if failure.status_code is not None else '-'} "
            f"url={failure.url}"
            for failure in report.diagnostics.request_failures
        )
    else:
        lines.append("  request failures: none")
    if report.diagnostics.artifact_failures:
        lines.append("  artifact failures:")
        lines.extend(
            f"    - {item.filename} stage={item.stage} [{item.subcode}] {item.message}"
            for item in report.diagnostics.artifact_failures
        )
    else:
        lines.append("  artifact failures: none")

    lines.append("")
    lines.append("policy evaluation:")
    lines.append(
        "  settings: "
        f"verified_provenance={report.policy.require_verified_provenance} "
        f"expected_repo={report.policy.require_expected_repository_match} "
        "publisher_orgs="
        f"{','.join(report.policy.allowed_publisher_organizations) or 'any'} "
        f"metadata_only={report.policy.allow_metadata_only} "
        f"vulnerabilities={report.policy.vulnerability_mode} "
        f"suppressions={report.policy.suppressions_applied}/"
        f"{report.policy.suppressions_expired} "
        f"risk_severity={report.policy.fail_on_severity}"
    )
    if report.policy.violations:
        lines.append("  violations:")
        lines.extend(
            f"    - [{violation.severity}] {violation.code}: {violation.message}"
            for violation in report.policy.violations
        )
    else:
        lines.append("  violations: none")

    lines.append("")
    if report.risk_flags:
        lines.append("risk flags:")
        for flag in report.risk_flags:
            lines.append(f"  - [{flag.severity}] {flag.code}: {flag.message}")
            if flag.why:
                lines.append("    why:")
                lines.extend(f"      - {reason}" for reason in flag.why)
            if flag.remediation:
                lines.append("    remediation:")
                lines.extend(f"      - {step}" for step in flag.remediation)
    else:
        lines.append("risk flags: none")
    return "\n".join(lines)


def _append_artifact_findings(
    lines: list[str],
    label: str,
    findings: list[str],
) -> None:
    if not findings:
        return
    lines.append(f"      {label}:")
    lines.extend(f"        - {finding}" for finding in findings)


def _render_cve_json(report: TrustReport) -> dict[str, object]:
    payload: dict[str, object] = {
        "project": report.project,
        "version": report.version,
        "package_url": report.package_url,
        "vulnerabilities": [
            {
                "id": vuln.id,
                "summary": vuln.summary,
                "aliases": vuln.aliases,
                "source": vuln.source,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "cvss_version": vuln.cvss_version,
                "cwes": vuln.cwes,
                "fixed_in": vuln.fixed_in,
                "link": vuln.link,
                "withdrawn": vuln.withdrawn,
                "withdrawn_at": vuln.withdrawn_at,
                "kev": vuln.kev,
                "kev_date_added": vuln.kev_date_added,
                "kev_due_date": vuln.kev_due_date,
                "kev_required_action": vuln.kev_required_action,
                "kev_known_ransomware_campaign_use": (
                    vuln.kev_known_ransomware_campaign_use
                ),
                "epss_score": vuln.epss_score,
                "epss_percentile": vuln.epss_percentile,
                "epss_date": vuln.epss_date,
                "suppression": (
                    {
                        "vulnerability_id": (
                            vuln.suppression.vulnerability_id
                        ),
                        "owner": vuln.suppression.owner,
                        "justification": vuln.suppression.justification,
                        "expires": vuln.suppression.expires,
                        "status": vuln.suppression.status,
                    }
                    if vuln.suppression is not None
                    else None
                ),
            }
            for vuln in report.vulnerabilities
        ],
    }
    if report.remediation.status != "not-requested":
        payload["remediation"] = asdict(report.remediation)
    return payload


def _render_cve_report(report: TrustReport) -> str:
    lines = [
        f"known vulnerabilities for {report.project} {report.version}",
        f"package: {report.package_url}",
    ]
    if not report.vulnerabilities:
        lines.append("")
        lines.append("No known vulnerability records reported by configured sources.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"count: {len(report.vulnerabilities)}")
    lines.append("")
    for vuln in report.vulnerabilities:
        lines.append(f"- {vuln.id}: {vuln.summary}")
        if vuln.aliases:
            lines.append(f"  aliases: {', '.join(vuln.aliases)}")
        lines.append(f"  source: {vuln.source or 'unknown'}")
        lines.append(f"  severity: {vuln.severity or 'unknown'}")
        if vuln.cvss_score is not None:
            cvss = f"{vuln.cvss_score:.1f}"
            if vuln.cvss_vector:
                cvss += f" ({vuln.cvss_vector})"
            lines.append(f"  cvss: {cvss}")
        if vuln.cwes:
            lines.append(f"  cwes: {', '.join(vuln.cwes)}")
        if vuln.fixed_in:
            lines.append(f"  fixed in: {', '.join(vuln.fixed_in)}")
        if vuln.withdrawn:
            lines.append(f"  withdrawn: {vuln.withdrawn_at or 'yes'}")
        if vuln.kev:
            lines.append(
                "  CISA KEV: yes"
                + (
                    f" (due {vuln.kev_due_date})"
                    if vuln.kev_due_date
                    else ""
                )
            )
        if vuln.epss_score is not None:
            lines.append(
                f"  EPSS: {vuln.epss_score:.4f}"
                + (
                    f" (percentile {vuln.epss_percentile:.4f})"
                    if vuln.epss_percentile is not None
                    else ""
                )
            )
        if vuln.suppression is not None:
            lines.append(
                "  suppression: "
                f"{vuln.suppression.status}; "
                f"owner={vuln.suppression.owner}; "
                f"expires={vuln.suppression.expires}; "
                f"justification={vuln.suppression.justification}"
            )
        if vuln.link:
            lines.append(f"  link: {vuln.link}")
    return "\n".join(lines)


def _render_scan_text(
    filename: str,
    reports: list[TrustReport],
    *,
    failures: list[dict[str, str]],
    verbose: bool,
    vulnerability_only: bool,
) -> str:
    sections = [
        f"trustcheck scan results for {filename}",
        f"packages: {len(reports) + len(failures)}",
        f"successful: {len(reports)}",
        f"failed: {len(failures)}",
    ]

    rendered_reports = [
        (
            _render_cve_report(report)
            if vulnerability_only
            else _render_text_report(report, verbose=verbose)
        )
        for report in reports
    ]
    if rendered_reports:
        sections.append("")
        sections.extend(rendered_reports)

    if failures:
        sections.append("")
        sections.append("scan failures:")
        sections.extend(
            f"  - {failure['requirement']}: {failure['message']}" for failure in failures
        )
    return "\n\n".join(section for section in sections if section != "")


def _render_scan_json(
    filename: str,
    reports: list[TrustReport],
    *,
    failures: list[dict[str, str]],
    vulnerability_only: bool,
    targets: Sequence[ScanTarget] = (),
) -> dict[str, object]:
    return {
        "file": filename,
        "schema_version": JSON_SCHEMA_VERSION,
        "resolved": [
            {
                "requirement": target.requirement,
                "project": target.project,
                "version": target.version,
                "requested": target.requested,
                "source_url": target.source_url,
                "editable": target.editable,
                "vcs": target.vcs,
                "vcs_commit": target.vcs_commit,
                "index_url": (
                    redact_url_credentials(target.index_url)
                    if target.index_url
                    else None
                ),
                "artifacts": [
                    artifact.to_dict() for artifact in target.artifacts
                ],
                "dependency_confusion": list(target.dependency_confusion),
                "source_file": target.source_file,
                "source_line": target.source_line,
            }
            for target in targets
        ],
        "reports": [
            (
                _render_cve_json(report)
                if vulnerability_only
                else report.to_dict()["report"]
            )
            for report in reports
        ],
        "failures": failures,
    }


def _evidence_summary(report: TrustReport) -> str:
    if report.files and all(file.verified for file in report.files):
        return "cryptographic verification succeeded for all discovered release artifacts"
    if any(file.verified for file in report.files):
        return "mixed evidence; some release artifacts verified cryptographically, others did not"
    return (
        "heuristic metadata and provenance signals only; no cryptographically verified artifact set"
    )


def _recommendation_reasons(report: TrustReport) -> list[str]:
    reasons: list[str] = []
    if report.risk_flags:
        reasons.extend(flag.message for flag in report.risk_flags[:3])
    if report.files and not all(file.verified for file in report.files):
        reasons.append(
            "Only "
            f"{report.coverage.verified_files} of "
            f"{report.coverage.total_files} discovered artifact(s) "
            "verified successfully."
        )
    elif report.files:
        reasons.append("Every discovered release artifact verified successfully.")
    if report.expected_repository and not any(
        flag.code.startswith("expected_repository") for flag in report.risk_flags
    ):
        reasons.append("The expected repository matched available package and publisher evidence.")
    return reasons[:4]
