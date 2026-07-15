from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess  # nosec B404
import sys
import tempfile
import threading
import tomllib
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from typing import Callable, Mapping, Sequence, cast
from urllib import parse

import urllib3
from packaging.utils import canonicalize_name

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
from .cli_commands import diff as diff_command
from .cli_commands import doctor as doctor_command
from .cli_commands import environment as environment_command
from .cli_commands import impact as impact_command
from .cli_commands import inspect as inspect_command
from .cli_commands import install as install_command
from .cli_commands import manifest as manifest_command
from .cli_commands import plugin_manifest as plugin_manifest_command
from .cli_commands import scan as scan_command
from .cli_commands.context import CommandContext
from .cli_models import (
    EXIT_DATA_ERROR as EXIT_DATA_ERROR,
)
from .cli_models import (
    EXIT_OK as EXIT_OK,
)
from .cli_models import (
    EXIT_POLICY_FAILURE as EXIT_POLICY_FAILURE,
)
from .cli_models import (
    EXIT_REMEDIATION_FAILURE as EXIT_REMEDIATION_FAILURE,
)
from .cli_models import (
    EXIT_UPSTREAM_FAILURE as EXIT_UPSTREAM_FAILURE,
)
from .cli_models import (
    EXIT_USAGE as EXIT_USAGE,
)
from .cli_models import (
    ScanTarget as ScanTarget,
)
from .cli_render import (
    _evidence_summary as _evidence_summary,
)
from .cli_render import (
    _render_cve_json as _render_cve_json,
)
from .cli_render import (
    _render_cve_report as _render_cve_report,
)
from .cli_render import (
    _render_decision_report as _render_decision_report,
)
from .cli_render import (
    _render_decision_scan as _render_decision_scan,
)
from .cli_render import (
    _render_scan_json as _render_scan_json,
)
from .cli_render import (
    _render_scan_text as _render_scan_text,
)
from .cli_render import (
    _render_text_report as _render_text_report,
)
from .cli_runtime import (
    _format_upstream_error as _format_upstream_error,
)
from .cli_runtime import (
    _merge_exit_codes as _merge_exit_codes,
)
from .cli_runtime import (
    _target_environment_from_args as _target_environment_from_args,
)
from .cli_runtime import (
    _target_marker_environment as _target_marker_environment,
)
from .cli_targets import (
    _attach_source_locations as _attach_source_locations,
)
from .cli_targets import (
    _build_scan_targets as _build_scan_targets,
)
from .cli_targets import (
    _clean_requirement_line as _clean_requirement_line,
)
from .cli_targets import (
    _collect_requirement_strings as _collect_requirement_strings,
)
from .cli_targets import (
    _exact_scan_target_version as _exact_scan_target_version,
)
from .cli_targets import (
    _expand_poetry_caret_specifier as _expand_poetry_caret_specifier,
)
from .cli_targets import (
    _expand_poetry_tilde_specifier as _expand_poetry_tilde_specifier,
)
from .cli_targets import (
    _extract_poetry_dependency_requirements as _extract_poetry_dependency_requirements,
)
from .cli_targets import (
    _extract_scan_requirements_from_toml as _extract_scan_requirements_from_toml,
)
from .cli_targets import (
    _load_scan_targets as _load_scan_targets,
)
from .cli_targets import (
    _load_scan_targets_from_toml as _load_scan_targets_from_toml,
)
from .cli_targets import (
    _locked_versions_from_requirements as _locked_versions_from_requirements,
)
from .cli_targets import (
    _parse_version_release_parts as _parse_version_release_parts,
)
from .cli_targets import (
    _poetry_dependency_to_requirement as _poetry_dependency_to_requirement,
)
from .cli_targets import (
    _read_requirements_file as _read_requirements_file,
)
from .cli_targets import (
    _resolve_scan_target_version as _resolve_scan_target_version,
)
from .cli_targets import (
    _resolve_scan_target_version_for_scan as _resolve_scan_target_version_for_scan,
)
from .cli_targets import (
    _resolve_standard_dependency_group as _resolve_standard_dependency_group,
)
from .cli_targets import (
    _scan_target_from_resolved_distribution as _scan_target_from_resolved_distribution,
)
from .cli_targets import (
    _scan_targets_from_lockfile as _scan_targets_from_lockfile,
)
from .cli_targets import (
    _scan_targets_from_resolution as _scan_targets_from_resolution,
)
from .cli_targets import (
    _source_line_for_project as _source_line_for_project,
)
from .cli_targets import (
    _strip_requirement_hashes as _strip_requirement_hashes,
)
from .cli_targets import (
    _translate_poetry_version_specifier as _translate_poetry_version_specifier,
)
from .contract import JSON_SCHEMA_VERSION
from .dynamic import (
    DEFAULT_DYNAMIC_PYTHON,
    DIGEST_PINNED_IMAGE_PATTERN,
    SUPPORTED_DYNAMIC_PYTHONS,
)
from .exports import (
    OUTPUT_FORMATS,
    ExportPackage,
    SourceLocation,
    render_export,
)
from .indexes import (
    DEFAULT_INDEX_URL,
    IndexConfiguration,
    IndexURLPolicy,
    SimpleRepositoryClient,
    normalize_index_url,
    redact_url_credentials,
)
from .lockfiles import (
    is_supported_lockfile,
    load_lockfile,
    load_pip_tools_lock,
)
from .manifest import DEFAULT_MAX_MALICIOUS_SCORE, DEFAULT_TRUST_MANIFEST_PATH
from .models import RemediationSummary, TrustReport
from .plugins import PluginError, PluginManager, RepositoryClient
from .policy import BUILTIN_POLICIES, PolicySettings, evaluate_policy
from .policy import resolve_policy as resolve_policy
from .provenance import evaluate_source_release_provenance
from .pypi import IndexBackedPackageClient, PypiClient, PypiClientError
from .remediation import (
    CommandValidationResult,
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
    write_remediation_patch,
)
from .resolver import (
    SANDBOX_MODES,
    ArtifactReference,
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
)
from .resolver import (
    discover_installed_distributions as discover_installed_distributions,
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
        "--source-release-provenance",
        action="store_true",
        help=(
            "Require declared repository, release tag, PyPI artifact provenance, "
            "and attestations to agree on one source commit."
        ),
    )
    inspect_parser.add_argument(
        "--release-tag",
        help="Expected source release tag for --source-release-provenance.",
    )
    inspect_parser.add_argument(
        "--format",
        default="text",
        help="Output format.",
    )
    inspect_parser.add_argument(
        "--summary",
        "--decision",
        dest="decision",
        action="store_true",
        help=(
            "Print only pass/fail, blocking reason, affected package, "
            "recommended action, and evidence links."
        ),
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
    _add_dynamic_analysis_argument(inspect_parser)
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
    scan_parser.add_argument(
        "--source-release-provenance",
        action="store_true",
        help=(
            "Require declared repository, release tag, PyPI artifact provenance, "
            "and attestations to agree on one source commit."
        ),
    )
    scan_parser.add_argument(
        "--release-tag",
        help="Expected source release tag for --source-release-provenance.",
    )
    _add_dynamic_analysis_argument(scan_parser)
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
        "--summary",
        "--decision",
        dest="decision",
        action="store_true",
        help=(
            "Print only pass/fail, blocking reason, affected package, "
            "recommended action, and evidence links."
        ),
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

    install_parser = subparsers.add_parser(
        "install",
        help="Verify dependencies and install only the verified local artifacts.",
    )
    install_parser.add_argument(
        "requirements",
        nargs="*",
        metavar="PACKAGE",
        help="Requirement specifier to resolve and install, such as requests==2.32.5.",
    )
    install_parser.add_argument(
        "-r",
        "--requirement",
        dest="requirement_file",
        help=(
            "Resolve and install dependencies from requirements.txt, "
            "pyproject.toml, pylock.toml, Pipfile.lock, uv.lock, poetry.lock, "
            "or pdm.lock."
        ),
    )
    install_parser.add_argument(
        "--lock",
        default="trustcheck.lock",
        help="Write the verified install lock evidence to this path.",
    )
    install_parser.add_argument(
        "--report",
        default="trustcheck-install-report.json",
        help="Write the machine-readable install report to this path.",
    )
    install_parser.add_argument(
        "--attestation",
        default="trustcheck-install-attestation.json",
        help="Write the install attestation to this path.",
    )
    install_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify, download, and write evidence without invoking pip install.",
    )
    install_parser.add_argument(
        "--allow-sdist",
        action="store_true",
        help="Permit installing a source distribution when no compatible wheel is selected.",
    )
    install_parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="Require verified provenance for every selected install artifact.",
    )
    install_parser.add_argument(
        "--strict",
        action="store_true",
        help="Apply the built-in strict policy.",
    )
    install_parser.add_argument(
        "--policy",
        choices=tuple(BUILTIN_POLICIES),
        default="default",
        help="Built-in policy profile to enforce before installation.",
    )
    install_parser.add_argument(
        "--policy-file",
        help="Path to a JSON file containing policy settings.",
    )
    install_parser.add_argument(
        "--fail-on-vulnerability",
        choices=("ignore", "any", "critical", "kev", "fixable"),
        help="Override vulnerability handling for policy evaluation.",
    )
    install_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    install_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    install_parser.add_argument(
        "--output-file",
        help="Write the rendered install result to this file instead of standard output.",
    )
    install_parser.add_argument(
        "--with-osv",
        action="store_true",
        help="Query OSV for each resolved package version.",
    )
    _add_advisory_arguments(install_parser)
    install_parser.add_argument(
        "--timeout",
        type=float,
        help="Network timeout in seconds.",
    )
    install_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    install_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    install_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    install_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_file_resolution_arguments(install_parser)
    _add_target_environment_arguments(install_parser)
    _add_index_arguments(install_parser)
    _add_malicious_arguments(install_parser)
    _add_dynamic_analysis_argument(install_parser)
    _add_runtime_arguments(install_parser)

    impact_parser = subparsers.add_parser(
        "impact",
        help="Prioritize vulnerable dependencies by observed source usage.",
    )
    impact_parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        required=True,
        help=(
            "Dependency file to resolve and triage, such as requirements.txt, "
            "pylock.toml, Pipfile.lock, uv.lock, poetry.lock, or pdm.lock."
        ),
    )
    impact_parser.add_argument(
        "--source",
        action="append",
        required=True,
        metavar="PATH",
        help="First-party source root to analyze; repeat for multiple roots.",
    )
    impact_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    impact_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    impact_parser.add_argument(
        "--output-file",
        help="Write the rendered impact report to this file instead of standard output.",
    )
    impact_parser.add_argument(
        "--with-osv",
        action="store_true",
        help="Query OSV for each resolved package version.",
    )
    _add_advisory_arguments(impact_parser)
    impact_parser.add_argument(
        "--timeout",
        type=float,
        help="Network timeout in seconds.",
    )
    impact_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    impact_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    impact_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    impact_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_file_resolution_arguments(impact_parser)
    _add_target_environment_arguments(impact_parser)
    _add_index_arguments(impact_parser)
    _add_malicious_arguments(impact_parser)
    _add_runtime_arguments(impact_parser)

    diff_parser = subparsers.add_parser(
        "diff",
        help="Review trust changes between two dependency files or Git refs.",
    )
    diff_parser.add_argument(
        "old_file",
        nargs="?",
        help="Baseline dependency file.",
    )
    diff_parser.add_argument(
        "new_file",
        nargs="?",
        help="Updated dependency file.",
    )
    diff_parser.add_argument("--base", help="Base Git ref for PR diff mode.")
    diff_parser.add_argument("--head", help="Head Git ref for PR diff mode.")
    diff_parser.add_argument(
        "--github-pr",
        action="store_true",
        help="Discover changed dependency files from --base/--head Git refs.",
    )
    diff_parser.add_argument(
        "--comment",
        action="store_true",
        help="Post the Markdown trust diff to the current GitHub pull request with gh.",
    )
    diff_parser.add_argument(
        "--dependency-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Restrict Git ref mode to this dependency file; repeatable.",
    )
    diff_parser.add_argument(
        "--manifest",
        help="Trust manifest to enforce against changed packages.",
    )
    diff_parser.add_argument(
        "--format",
        choices=("text", "json", "markdown", "sarif"),
        default="text",
        help="Output format.",
    )
    diff_parser.add_argument(
        "--output-file",
        help="Write the rendered diff to this file instead of standard output.",
    )
    diff_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "med", "high"),
        default="high",
        help="Exit with policy failure when the diff reaches this severity.",
    )
    diff_parser.add_argument(
        "--artifact-scope",
        dest="diff_artifact_scope",
        choices=("target", "sdist", "all"),
        default="all",
        help="Artifact scope used while collecting trust evidence for changed packages.",
    )
    diff_parser.add_argument("--timeout", type=float, help="Network timeout in seconds.")
    diff_parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    diff_parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    diff_parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    diff_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    diff_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    diff_parser.add_argument(
        "--with-osv",
        action="store_true",
        help="Query OSV for each changed package version.",
    )
    _add_advisory_arguments(diff_parser)
    _add_dynamic_analysis_argument(diff_parser)
    _add_file_resolution_arguments(diff_parser)
    _add_target_environment_arguments(diff_parser)
    _add_index_arguments(diff_parser)
    _add_malicious_arguments(diff_parser)
    _add_runtime_arguments(diff_parser)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Create and enforce a dependency trust manifest.",
    )
    manifest_subparsers = manifest_parser.add_subparsers(
        dest="manifest_action",
        required=True,
    )

    manifest_init_parser = manifest_subparsers.add_parser(
        "init",
        help="Create a trust manifest from the current dependency file.",
    )
    _add_manifest_common_arguments(manifest_init_parser)
    manifest_init_parser.add_argument(
        "--output",
        default=DEFAULT_TRUST_MANIFEST_PATH,
        help="Trust manifest path to write.",
    )

    manifest_verify_parser = manifest_subparsers.add_parser(
        "verify",
        help="Verify the current dependency file against a trust manifest.",
    )
    _add_manifest_common_arguments(manifest_verify_parser)
    manifest_verify_parser.add_argument(
        "--manifest",
        default=DEFAULT_TRUST_MANIFEST_PATH,
        help="Trust manifest path to read.",
    )

    manifest_update_parser = manifest_subparsers.add_parser(
        "update",
        help="Refresh a trust manifest after reviewing dependency trust changes.",
    )
    _add_manifest_common_arguments(manifest_update_parser)
    manifest_update_parser.add_argument(
        "--manifest",
        default=DEFAULT_TRUST_MANIFEST_PATH,
        help="Trust manifest path to update.",
    )

    plugin_manifest_parser = subparsers.add_parser(
        "plugin-manifest",
        help="Generate, sign, and verify Trustcheck plugin manifests.",
    )
    plugin_manifest_subparsers = plugin_manifest_parser.add_subparsers(
        dest="plugin_manifest_action",
        required=True,
    )

    plugin_manifest_init_parser = plugin_manifest_subparsers.add_parser(
        "init",
        help="Render an unsigned v2 plugin manifest draft for a wheel.",
    )
    _add_plugin_manifest_common_arguments(
        plugin_manifest_init_parser,
        formats=("json",),
        default_format="json",
    )
    plugin_manifest_init_parser.add_argument(
        "distribution",
        metavar="DIST_OR_WHEEL",
        help="Plugin wheel to inspect.",
    )
    plugin_manifest_init_parser.add_argument(
        "--configuration-schema",
        metavar="PATH",
        help="JSON configuration schema to bind into the manifest statement.",
    )

    plugin_manifest_sign_parser = plugin_manifest_subparsers.add_parser(
        "sign",
        help="Sign a plugin wheel and insert the v2 manifest.",
    )
    _add_plugin_manifest_common_arguments(plugin_manifest_sign_parser)
    plugin_manifest_sign_parser.add_argument(
        "distribution",
        metavar="DIST_OR_WHEEL",
        help="Plugin wheel to rewrite.",
    )
    plugin_manifest_sign_parser.add_argument(
        "--key",
        required=True,
        metavar="PRIVATE_KEY",
        help="RSA private key PEM used to sign the canonical statement.",
    )
    plugin_manifest_sign_parser.add_argument(
        "--output",
        metavar="WHEEL",
        help="Write the signed wheel here; defaults to rewriting the input wheel.",
    )
    plugin_manifest_sign_parser.add_argument(
        "--configuration-schema",
        metavar="PATH",
        help="JSON configuration schema to bind into the manifest statement.",
    )

    plugin_manifest_verify_parser = plugin_manifest_subparsers.add_parser(
        "verify",
        help="Verify a signed plugin wheel or extracted distribution.",
    )
    _add_plugin_manifest_common_arguments(plugin_manifest_verify_parser)
    plugin_manifest_verify_parser.add_argument(
        "distribution",
        metavar="DIST_OR_WHEEL",
        help="Signed plugin wheel or extracted distribution to verify.",
    )

    plugin_manifest_fingerprint_parser = plugin_manifest_subparsers.add_parser(
        "fingerprint",
        help="Print the Trustcheck signer fingerprint for an RSA public key.",
    )
    _add_plugin_manifest_common_arguments(plugin_manifest_fingerprint_parser)
    plugin_manifest_fingerprint_parser.add_argument(
        "public_key",
        metavar="PUBLIC_KEY",
        help="RSA public key PEM.",
    )

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
        "--summary",
        "--decision",
        dest="decision",
        action="store_true",
        help=(
            "Print only pass/fail, blocking reason, affected package, "
            "recommended action, and evidence links."
        ),
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
    _add_dynamic_analysis_argument(environment_parser)
    _add_runtime_arguments(environment_parser, resumable=True)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check local trustcheck prerequisites and configuration.",
    )
    doctor_parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    doctor_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    doctor_parser.add_argument(
        "--output-file",
        help="Write the doctor report to this file instead of standard output.",
    )
    doctor_parser.add_argument(
        "--cache-dir",
        help="Persistent trustcheck cache directory to test for write access.",
    )
    doctor_parser.add_argument(
        "--sandbox",
        choices=SANDBOX_MODES,
        default="auto",
        help="Resolver isolation mode to validate.",
    )
    doctor_parser.add_argument(
        "--sandbox-image",
        default=None,
        help="Digest-pinned OCI image used by the container resolver sandbox.",
    )
    doctor_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with a policy failure when any required check fails.",
    )
    _add_index_arguments(doctor_parser)
    _add_runtime_arguments(doctor_parser)
    return parser


def _add_manifest_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        required=True,
        help=(
            "Dependency file to baseline or verify: requirements.txt, pyproject.toml, "
            "pylock.toml, Pipfile.lock, uv.lock, poetry.lock, or pdm.lock."
        ),
    )
    parser.add_argument(
        "--config-file",
        help="Path to a JSON, TOML, or pyproject.toml configuration file.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for command status or verification results.",
    )
    parser.add_argument(
        "--output-file",
        help="Write command status or verification results to this path.",
    )
    parser.add_argument(
        "--artifact-scope",
        dest="manifest_artifact_scope",
        choices=("target", "sdist", "all"),
        default="all",
        help=(
            "Choose target-compatible install artifact, source distributions, "
            "or every release artifact for manifest trust evidence."
        ),
    )
    parser.add_argument(
        "--max-malicious-score",
        type=int,
        default=DEFAULT_MAX_MALICIOUS_SCORE,
        help=(
            "Default maximum malicious-package heuristic score recorded for "
            "new manifest entries."
        ),
    )
    parser.add_argument("--timeout", type=float, help="Network timeout in seconds.")
    parser.add_argument(
        "--retries",
        type=int,
        help="Maximum retry count for transient failures.",
    )
    parser.add_argument(
        "--backoff",
        type=float,
        help="Retry backoff factor in seconds.",
    )
    parser.add_argument(
        "--cache-dir",
        help="Optional persistent cache directory for PyPI responses.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use cached responses only and do not make network requests.",
    )
    _add_dynamic_analysis_argument(parser)
    _add_file_resolution_arguments(parser)
    _add_target_environment_arguments(parser)
    _add_index_arguments(parser)
    _add_malicious_arguments(parser)
    _add_runtime_arguments(parser)


def _add_plugin_manifest_common_arguments(
    parser: argparse.ArgumentParser,
    *,
    formats: tuple[str, ...] = ("text", "json"),
    default_format: str = "text",
) -> None:
    parser.add_argument(
        "--format",
        choices=formats,
        default=default_format,
        help="Output format.",
    )
    parser.add_argument(
        "--output-file",
        help="Write command output to this path instead of standard output.",
    )


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
    parser.add_argument(
        "--allow-insecure-index",
        action="store_true",
        help=(
            "Allow HTTP package indexes and artifact URLs from those indexes; "
            "unsafe outside explicitly trusted local networks."
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


def _add_dynamic_analysis_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dynamic-analysis",
        action="store_true",
        help=(
            "Experimental: opt in to bounded install analysis of downloaded artifacts "
            "in a disposable Docker container with no network, a non-root user, "
            "digest-pinned image policy, and strict CPU, memory, PID, and time limits. "
            "This executes untrusted build and install hooks and may be inconclusive."
        ),
    )
    parser.add_argument(
        "--dynamic-python",
        choices=SUPPORTED_DYNAMIC_PYTHONS,
        default=DEFAULT_DYNAMIC_PYTHON,
        help=(
            "Python version for bounded install analysis. Supported values: "
            + ", ".join(SUPPORTED_DYNAMIC_PYTHONS)
            + f". Default: {DEFAULT_DYNAMIC_PYTHON}."
        ),
    )
    parser.add_argument(
        "--dynamic-image",
        default=None,
        metavar="IMAGE@sha256:DIGEST",
        help=(
            "Override the bounded install analyzer image. The image must be "
            "pinned by full sha256 digest."
        ),
    )


def _add_runtime_arguments(
    parser: argparse.ArgumentParser,
    *,
    resumable: bool = False,
) -> None:
    parser.add_argument(
        "--workers",
        dest="max_workers",
        type=int,
        metavar="N",
        help=(
            "Bound concurrent network and target work; defaults to 8. "
            "Use -1 for all available CPU cores."
        ),
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
        help="Experimental: enable installed trustcheck entry-point plugins.",
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
        if args.command == "plugin-manifest":
            config_payload = {}
        else:
            config_payload = _load_config_file(getattr(args, "config_file", None))
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
    if (
        getattr(args, "max_workers", None) is not None
        and args.max_workers != -1
        and not 1 <= args.max_workers <= 64
    ):
        parser.error("--workers must be -1 or between 1 and 64")
    if args.command == "diff":
        diff_command.validate_args(args, parser)
    if args.command == "scan":
        scan_command.validate_args(args, parser)
    if args.command == "install":
        install_command.validate_args(args, parser)
    if args.command == "impact":
        impact_command.validate_args(args, parser)
    if args.command == "manifest":
        manifest_command.validate_args(args, parser)
    if args.command == "plugin-manifest":
        plugin_manifest_command.validate_args(args, parser)

    try:
        if args.command == "plugin-manifest":
            context = CommandContext(
                parser=parser,
                config_payload=config_payload,
                plugin_manager=PluginManager(),
                facade=sys.modules[__name__],
            )
            return plugin_manifest_command.run(args, context)
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
        context = CommandContext(
            parser=parser,
            config_payload=config_payload,
            plugin_manager=plugin_manager,
            facade=sys.modules[__name__],
        )
        if args.command == "inspect":
            return inspect_command.run(args, context)
        if args.command == "scan":
            return scan_command.run(args, context)
        if args.command == "install":
            return install_command.run(args, context)
        if args.command == "impact":
            return impact_command.run(args, context)
        if args.command == "diff":
            return diff_command.run(args, context)
        if args.command == "manifest":
            return manifest_command.run(args, context)
        if args.command == "environment":
            return environment_command.run(args, context)
        if args.command == "doctor":
            return doctor_command.run(args, context)
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


def _apply_source_release_provenance(
    report: TrustReport,
    args: argparse.Namespace,
) -> TrustReport:
    if getattr(args, "source_release_provenance", False):
        evaluate_source_release_provenance(
            report,
            expected_tag=getattr(args, "release_tag", None),
        )
    return report


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
            _apply_source_release_provenance(resumed, args)
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
                allow_insecure_index=getattr(args, "allow_insecure_index", False),
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
                dynamic_analysis=getattr(args, "dynamic_analysis", False),
                dynamic_analysis_image=getattr(args, "dynamic_image", None),
                dynamic_analysis_python=getattr(
                    args,
                    "dynamic_python",
                    DEFAULT_DYNAMIC_PYTHON,
                ),
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
            _apply_source_release_provenance(report, args)
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
    if getattr(args, "decision", False):
        rendered = _render_decision_scan(
            source_label,
            reports,
            failures=failures,
        )
    elif args.format == "json":
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
            allow_insecure_index=getattr(args, "allow_insecure_index", False),
            plugin_manager=plugin_manager,
        )
    report = inspect_package(
        project,
        version=selected_version,
        client=scan_client,
        include_vulnerabilities=True,
        include_osv=vulnerability_client is not None,
        vulnerability_only=args.scan_profile == "fast" and not args.dynamic_analysis,
        dynamic_analysis=args.dynamic_analysis,
        dynamic_analysis_image=getattr(args, "dynamic_image", None),
        dynamic_analysis_python=getattr(args, "dynamic_python", DEFAULT_DYNAMIC_PYTHON),
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
    _apply_source_release_provenance(report, args)
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
        allow_insecure_index=getattr(args, "allow_insecure_index", False),
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
        if not plan.validation.accepted:
            raise RemediationError(
                "the generated patch failed post-write resolution or security "
                "validation: "
                + _fix_validation_failure_detail(plan)
            )
        clean_install, pip_check, command_results = _validate_fix_runtime(
            prepared,
            generated,
            args=args,
            offline=client.offline,
        )
        plan.validation = replace(
            plan.validation,
            clean_install_passed=clean_install.passed and pip_check.passed,
            configured_commands_passed=all(
                result.passed for result in command_results
            ),
        )
        plan.post_fix_result = post_fix_result(
            command=_post_fix_reproduction_command(source_path, args),
            resolution=generated,
            reports=generated_reports,
            validation=plan.validation,
            expected_versions=expected_versions,
            clean_install=clean_install,
            pip_check=pip_check,
            test_commands=command_results,
        )
        if not plan.validation.accepted:
            raise RemediationError(
                "the generated patch failed post-write resolution or security "
                "validation: "
                + _fix_validation_failure_detail(plan)
            )
        if args.dry_run:
            patch_path = _write_default_fix_patch(prepared)
            plan.message = (
                "the exact patch was regenerated and validated in an isolated "
                "workspace; no project files were modified"
                f"; patch written to {patch_path}"
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
        patch_path = _write_default_fix_patch(prepared)
        plan.message = (
            f"{plan.message}; patch written to {patch_path}"
            if plan.message
            else f"validated remediation was applied; patch written to {patch_path}"
        )
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
    scan_profile = getattr(args, "scan_profile", "fast")
    if scan_profile == "standard":
        command.append("--standard")
    elif scan_profile == "full":
        command.append("--full")
    if getattr(args, "dynamic_analysis", False):
        command.append("--dynamic-analysis")
        dynamic_python = getattr(args, "dynamic_python", DEFAULT_DYNAMIC_PYTHON)
        if dynamic_python != DEFAULT_DYNAMIC_PYTHON:
            command.extend(["--dynamic-python", dynamic_python])
        dynamic_image = getattr(args, "dynamic_image", None)
        if dynamic_image:
            command.extend(["--dynamic-image", dynamic_image])
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
    if getattr(args, "allow_insecure_index", False):
        command.append("--allow-insecure-index")
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


def _validate_fix_runtime(
    prepared: PreparedRemediation,
    resolution: Resolution,
    *,
    args: argparse.Namespace,
    offline: bool,
) -> tuple[
    CommandValidationResult,
    CommandValidationResult,
    tuple[CommandValidationResult, ...],
]:
    with tempfile.TemporaryDirectory(prefix="trustcheck-fix-venv-") as temporary:
        workspace = Path(temporary)
        venv_path = workspace / "venv"
        create = _run_validation_subprocess(
            "python -m venv <clean environment>",
            [sys.executable, "-m", "venv", str(venv_path)],
            cwd=prepared.root,
        )
        if not create.passed:
            raise RemediationError(_command_failure_message("clean venv", create))

        python = _venv_python(venv_path)
        requirements_file = workspace / "resolved-graph.txt"
        requirements_file.write_text(
            "\n".join(_clean_install_requirements(resolution)) + "\n",
            encoding="utf-8",
        )
        environment = _venv_environment(venv_path)
        pip_context = (
            nullcontext(([], environment))
            if offline
            else _index_configuration_from_args(args).pip_subprocess(env=environment)
        )
        with pip_context as (pip_arguments, environment):
            install_argv = [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
            ]
            if offline:
                install_argv.append("--no-index")
            install_argv.extend(pip_arguments)
            install_argv.extend(["-r", str(requirements_file)])
            install = _run_validation_subprocess(
                "python -m pip install -r <resolved graph>",
                install_argv,
                cwd=prepared.root,
                env=environment,
            )
        if not install.passed:
            return (
                install,
                CommandValidationResult(
                    command="python -m pip check",
                    argv=(),
                    returncode=1,
                    stderr="skipped because clean dependency installation failed",
                ),
                (),
            )

        pip_check = _run_validation_subprocess(
            "python -m pip check",
            [str(python), "-m", "pip", "check"],
            cwd=prepared.root,
            env=environment,
        )
        if not pip_check.passed:
            return install, pip_check, ()

        command_results: list[CommandValidationResult] = []
        for command in getattr(args, "fix_test_commands", ()) or ():
            argv = _validation_command_argv(command, python=python)
            result = _run_validation_subprocess(
                command,
                argv,
                cwd=prepared.root,
                env=environment,
            )
            command_results.append(result)
            if not result.passed:
                break
        return install, pip_check, tuple(command_results)


def _clean_install_requirements(resolution: Resolution) -> list[str]:
    if not resolution.distributions:
        raise RemediationError("cannot validate an empty dependency graph")
    return [
        _clean_install_requirement(distribution)
        for distribution in sorted(
            resolution.distributions,
            key=lambda item: str(canonicalize_name(item.name)),
        )
    ]


def _clean_install_requirement(distribution: ResolvedDistribution) -> str:
    if distribution.editable:
        raise RemediationError(
            f"clean install validation cannot install editable dependency "
            f"{distribution.name}=={distribution.version}"
        )
    if distribution.vcs is not None and distribution.source_url is None:
        raise RemediationError(
            f"clean install validation cannot reproduce VCS dependency "
            f"{distribution.name} without a source URL"
        )
    if distribution.source_url and (distribution.is_direct or distribution.vcs):
        return f"{distribution.name} @ {distribution.source_url}"
    return f"{distribution.name}=={distribution.version}"


def _validation_command_argv(command: str, *, python: Path) -> list[str]:
    try:
        argv = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise RemediationError(
            f"invalid [tool.trustcheck.fix] test command {command!r}: {exc}"
        ) from exc
    if not argv:
        raise RemediationError("[tool.trustcheck.fix] test commands cannot be empty")
    executable = argv[0].lower()
    if executable in {"python", "python3"}:
        return [str(python), *argv[1:]]
    if executable in {"pip", "pip3"}:
        return [str(python), "-m", "pip", *argv[1:]]
    return argv


def _venv_python(venv_path: Path) -> Path:
    name = "python.exe" if os.name == "nt" else "python"
    return _venv_bin_dir(venv_path) / name


def _venv_bin_dir(venv_path: Path) -> Path:
    return venv_path / ("Scripts" if os.name == "nt" else "bin")


def _venv_environment(venv_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["VIRTUAL_ENV"] = str(venv_path)
    environment["PATH"] = (
        str(_venv_bin_dir(venv_path))
        + os.pathsep
        + environment.get("PATH", "")
    )
    environment.pop("PYTHONHOME", None)
    return environment


def _run_validation_subprocess(
    command: str,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: float = 600.0,
) -> CommandValidationResult:
    try:
        # User-configured argv is executed directly without a shell.
        completed = subprocess.run(  # nosec B603
            list(argv),
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandValidationResult(
            command=command,
            argv=tuple(argv),
            returncode=124,
            stdout=_captured_output(exc.stdout),
            stderr=_captured_output(exc.stderr or f"timed out after {timeout:g}s"),
        )
    except OSError as exc:
        return CommandValidationResult(
            command=command,
            argv=tuple(argv),
            returncode=127,
            stderr=str(exc),
        )
    return CommandValidationResult(
        command=command,
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=_captured_output(completed.stdout),
        stderr=_captured_output(completed.stderr),
    )


def _captured_output(value: object, *, limit: int = 4000) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[-limit:].lstrip()


def _write_default_fix_patch(prepared: PreparedRemediation) -> Path:
    return write_remediation_patch(
        prepared.plan,
        prepared.source_root / "trustcheck-fix.patch",
    )


def _fix_validation_failure_detail(plan: RemediationPlan) -> str:
    if plan.post_fix_result is not None:
        results = [
            plan.post_fix_result.clean_install,
            plan.post_fix_result.pip_check,
            *plan.post_fix_result.test_commands,
        ]
        for result in results:
            if result is not None and not result.passed:
                return _command_failure_message("validation command", result)
    if plan.validation.errors:
        return "; ".join(plan.validation.errors)
    return "post-fix validation did not accept the generated result"


def _command_failure_message(label: str, result: CommandValidationResult) -> str:
    detail = result.stderr or result.stdout
    message = (
        f"{label} failed: {result.command} exited with status "
        f"{result.returncode}"
    )
    return f"{message}: {detail}" if detail else message


def _remediation_available_versions(
    targets: Sequence[ScanTarget],
    reports: Sequence[TrustReport],
    *,
    client: PypiClient,
    keyring_provider: str,
    allow_insecure_index: bool = False,
) -> dict[str, tuple[str, ...]]:
    reports_by_name = {
        str(canonicalize_name(report.project)): report
        for report in reports
    }
    versions: dict[str, tuple[str, ...]] = {}
    for target in targets:
        name = str(canonicalize_name(target.project))
        report = reports_by_name.get(name)
        if report is None:
            continue
        has_fixable_vulnerability = any(
            vulnerability.fixed_in
            and not vulnerability.withdrawn
            and not (
                vulnerability.suppression is not None
                and vulnerability.suppression.status == "active"
            )
            for vulnerability in report.vulnerabilities
        )
        if not has_fixable_vulnerability and report.policy.passed:
            continue
        target_client = _client_for_target(
            client,
            target,
            keyring_provider=keyring_provider,
            allow_insecure_index=allow_insecure_index,
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
    if _is_remediation_requirements_file(source_path):
        requirements_in = source_path.with_suffix(".in")
        if requirements_in.is_file():
            return requirements_in
        return source_path
    if source_path.suffix.lower() in {".txt", ".in"}:
        return source_path
    return None


def _is_remediation_requirements_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        name == "requirements.txt"
        or name == "requirements.lock"
        or (name.startswith("requirements") and path.suffix.lower() in {".txt", ".lock"})
    )


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
            allow_insecure_index=getattr(args, "allow_insecure_index", False),
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
            dynamic_analysis=getattr(args, "dynamic_analysis", False),
            dynamic_analysis_image=getattr(args, "dynamic_image", None),
            dynamic_analysis_python=getattr(
                args,
                "dynamic_python",
                DEFAULT_DYNAMIC_PYTHON,
            ),
            vulnerability_client=vulnerability_client,
            locked_versions=versions,
            complete_locked_versions=True,
            expected_artifacts=target.artifacts,
            dependency_confusion_indexes=target.dependency_confusion,
            trusted_projects=getattr(args, "trusted_project", ()),
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
                "dynamic_analysis": getattr(args, "dynamic_analysis", False),
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
                        "distribution_version": item.distribution_version,
                        "wheel_sha256": item.wheel_sha256,
                        "record_sha256": item.record_sha256,
                        "trust_policy_mode": item.trust_policy_mode,
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


def _index_configuration_from_args(
    args: argparse.Namespace,
) -> IndexConfiguration:
    return IndexConfiguration(
        index_url=args.index_url,
        extra_index_urls=tuple(args.extra_index_url),
        keyring_provider=args.keyring_provider,
        allow_insecure_index=getattr(args, "allow_insecure_index", False),
    )


def _resolver_from_args(
    args: argparse.Namespace,
    *,
    plugin_manager: PluginManager | None = None,
) -> PipResolver:
    indexes = _index_configuration_from_args(args)
    index_client: RepositoryClient = SimpleRepositoryClient(
        keyring_provider=indexes.keyring_provider,
        url_policy=IndexURLPolicy(
            allow_insecure_index=indexes.allow_insecure_index,
        ),
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
    allow_insecure_index: bool = False,
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
        url_policy=IndexURLPolicy(allow_insecure_index=allow_insecure_index),
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
        allow_insecure_index=allow_insecure_index,
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
    return _normalize_worker_count(workers)


def _normalize_worker_count(workers: int) -> int:
    if workers == -1:
        return _available_worker_count()
    if workers < 1 or workers > 64:
        raise ValueError("max_workers must be -1 or between 1 and 64")
    return workers


def _available_worker_count() -> int:
    get_affinity = cast(
        Callable[[int], set[int]] | None,
        getattr(os, "sched_getaffinity", None),
    )
    if get_affinity is not None:
        try:
            return max(1, len(get_affinity(0)))
        except OSError:
            pass
    return max(1, os.cpu_count() or 1)


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
        "dynamic_analysis",
        "dynamic_python",
        "dynamic_image",
        "network",
        "advisories",
        "performance",
        "fix",
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
    if hasattr(args, "dynamic_analysis"):
        args.dynamic_analysis = _resolve_bool(
            args.dynamic_analysis if "dynamic_analysis" in explicit else False,
            env_name="TRUSTCHECK_DYNAMIC_ANALYSIS",
            config_value=config.get("dynamic_analysis"),
            default=False,
        )
    if hasattr(args, "dynamic_python"):
        args.dynamic_python = _resolve_choice(
            args.dynamic_python if "dynamic_python" in explicit else None,
            env_name="TRUSTCHECK_DYNAMIC_PYTHON",
            config_value=config.get("dynamic_python"),
            default=DEFAULT_DYNAMIC_PYTHON,
            choices=set(SUPPORTED_DYNAMIC_PYTHONS),
        )
    if hasattr(args, "dynamic_image"):
        args.dynamic_image = _resolve_str(
            args.dynamic_image if "dynamic_image" in explicit else None,
            env_name="TRUSTCHECK_DYNAMIC_IMAGE",
            config_value=config.get("dynamic_image"),
        )
        if (
            args.dynamic_image is not None
            and DIGEST_PINNED_IMAGE_PATTERN.fullmatch(args.dynamic_image) is None
        ):
            raise ValueError("dynamic_image must be pinned by a full sha256 digest")
    if hasattr(args, "fix"):
        args.fix_test_commands = _fix_test_commands_from_config(config)


def _fix_test_commands_from_config(config: dict[str, object]) -> list[str]:
    raw_config = config.get("fix")
    if raw_config is None:
        return []
    if not isinstance(raw_config, dict):
        raise ValueError("fix config must be an object")
    unknown = sorted(set(raw_config) - {"test_commands"})
    if unknown:
        raise ValueError(
            "unknown fix config setting(s): " + ", ".join(unknown)
        )
    commands = raw_config.get("test_commands", [])
    if not isinstance(commands, list) or any(
        not isinstance(item, str) or not item.strip()
        for item in commands
    ):
        raise ValueError("fix.test_commands must be a list of commands")
    return [item.strip() for item in commands]


def _explicit_config_fields(argv: Sequence[str]) -> set[str]:
    flags = {
        "--policy": "policy",
        "--with-osv": "with_osv",
        "--with-kev": "with_kev",
        "--fast": "scan_profile",
        "--standard": "scan_profile",
        "--full": "scan_profile",
        "--artifact-scope": "artifact_scope",
        "--dynamic-analysis": "dynamic_analysis",
        "--dynamic-python": "dynamic_python",
        "--dynamic-image": "dynamic_image",
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
