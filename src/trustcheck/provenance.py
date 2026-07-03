from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, cast
from urllib.parse import urlparse

from .models import (
    ProvenanceIssue,
    ProvenanceMaterial,
    PublisherIdentity,
    RiskFlag,
    SlsaProvenance,
    TrustReport,
)

SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
GITHUB_WORKFLOW_BUILD_TYPE_V1 = (
    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
)
_GITHUB_WORKFLOW_BUILD_TYPES = {
    GITHUB_WORKFLOW_BUILD_TYPE_V1,
    "https://actions.github.io/buildtypes/workflow/v1",
}

_COMMIT_DIGEST = re.compile(r"(?i)^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_ACTION_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?)"
    r"@(?P<ref>[A-Za-z0-9_.:/+-]+)"
)
_ALLOWLIST_ENTRY = re.compile(
    r"(?i)^(?:(?P<kind>github|gitlab|circleci|google):)?"
    r"(?P<organization>[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)$"
)


class SlsaValidationError(ValueError):
    pass


def analyze_slsa_provenance(
    predicate: object,
    *,
    publisher_kind: str,
    publisher_repository: str | None,
    publisher_workflow: str | None,
) -> SlsaProvenance:
    if not isinstance(predicate, Mapping):
        raise SlsaValidationError("SLSA provenance predicate must be an object")

    build_definition = _required_mapping(
        predicate.get("buildDefinition"),
        "buildDefinition",
    )
    run_details = _required_mapping(predicate.get("runDetails"), "runDetails")
    builder = _required_mapping(run_details.get("builder"), "runDetails.builder")
    build_type = _required_resource_uri(
        build_definition.get("buildType"),
        "buildDefinition.buildType",
    )
    builder_id = _required_resource_uri(
        builder.get("id"),
        "runDetails.builder.id",
    )
    if (
        build_type in _GITHUB_WORKFLOW_BUILD_TYPES
        and "github" not in publisher_kind.lower()
    ):
        raise SlsaValidationError(
            "GitHub workflow provenance does not match the publisher kind"
        )
    if (
        build_type in _GITHUB_WORKFLOW_BUILD_TYPES
        and urlparse(builder_id).hostname != "github.com"
    ):
        raise SlsaValidationError(
            "GitHub workflow provenance uses a non-GitHub builder identity"
        )

    materials = _parse_materials(build_definition.get("resolvedDependencies"))
    external_parameters = _optional_mapping(
        build_definition.get("externalParameters")
    )
    workflow = _optional_mapping(external_parameters.get("workflow"))
    workflow_uri = _optional_text(
        workflow.get("repository")
        or workflow.get("uri")
        or external_parameters.get("repository")
    )
    workflow_path = _optional_text(
        workflow.get("path")
        or workflow.get("workflow")
        or external_parameters.get("workflowPath")
    )
    workflow_ref = _optional_text(
        workflow.get("ref")
        or workflow.get("reference")
        or external_parameters.get("ref")
    )
    workflow_repository = normalize_repository_uri(workflow_uri)
    publisher_repository_url = normalize_publisher_repository(
        publisher_kind,
        publisher_repository,
    )
    source_material = _select_source_material(
        materials,
        expected_repository=workflow_repository or publisher_repository_url,
    )
    if source_material is None:
        raise SlsaValidationError(
            "SLSA provenance has no source repository material"
        )
    source_repository = cast(
        str,
        normalize_repository_uri(source_material.uri),
    )
    source_commit = _source_commit(source_material)
    if source_commit is None:
        raise SlsaValidationError(
            "SLSA source material must contain a full git commit digest"
        )
    if (
        publisher_repository_url is not None
        and source_repository != publisher_repository_url
    ):
        raise SlsaValidationError(
            "SLSA source repository does not match the verified publisher "
            f"repository: {source_repository} != {publisher_repository_url}"
        )
    if workflow_repository is not None and workflow_repository != source_repository:
        raise SlsaValidationError(
            "SLSA workflow repository does not match the source material"
        )
    if publisher_workflow and workflow_path and not _workflow_matches(
        publisher_workflow,
        workflow_path,
    ):
        raise SlsaValidationError(
            "SLSA workflow path does not match the verified publisher workflow"
        )

    issues: list[ProvenanceIssue] = []
    workflow_immutable: bool | None = None
    expects_workflow = bool(workflow) or bool(publisher_workflow) or (
        build_type in _GITHUB_WORKFLOW_BUILD_TYPES
    )
    if workflow_ref:
        workflow_immutable = is_immutable_reference(workflow_ref)
        if not workflow_immutable:
            issues.append(
                ProvenanceIssue(
                    code="mutable_workflow_reference",
                    severity="medium",
                    message="The SLSA workflow reference is mutable.",
                    evidence=[workflow_ref],
                )
            )
        elif _normalized_digest(workflow_ref) != source_commit:
            raise SlsaValidationError(
                "SLSA workflow commit does not match the source material commit"
            )
    elif expects_workflow:
        issues.append(
            ProvenanceIssue(
                code="missing_workflow_reference",
                severity="medium",
                message="The SLSA predicate does not identify the workflow revision.",
            )
        )

    action_references = sorted(_collect_action_references(predicate))
    unpinned_actions = sorted(
        reference
        for reference in action_references
        if not is_immutable_reference(reference.rsplit("@", 1)[-1])
    )
    if unpinned_actions:
        issues.append(
            ProvenanceIssue(
                code="unpinned_build_actions",
                severity="high",
                message="The build provenance contains actions not pinned to commits.",
                evidence=unpinned_actions,
            )
        )
    issues.extend(_material_issues(materials, source_material))

    metadata = _optional_mapping(run_details.get("metadata"))
    invocation_id = _optional_text(
        metadata.get("invocationId") or metadata.get("invocationID")
    )
    signer_identity = ":".join(
        (
            publisher_kind or "unknown",
            publisher_repository_url or publisher_repository or "-",
            publisher_workflow or "-",
        )
    )
    source_material.source = True
    return SlsaProvenance(
        valid=True,
        signer_identity=signer_identity,
        source_uri=source_material.uri,
        source_repository=source_repository,
        source_commit=source_commit,
        builder_id=builder_id,
        build_type=build_type,
        workflow_uri=workflow_uri,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
        workflow_ref_immutable=workflow_immutable,
        invocation_id=invocation_id,
        materials=materials,
        action_references=action_references,
        unpinned_actions=unpinned_actions,
        issues=issues,
    )


def normalize_publisher_repository(
    kind: str,
    repository: str | None,
) -> str | None:
    if not repository:
        return None
    if "://" in repository or repository.startswith("git@"):
        return normalize_repository_uri(repository)
    lowered = kind.lower()
    if "gitlab" in lowered:
        return normalize_repository_uri(f"https://gitlab.com/{repository}")
    if "github" in lowered:
        return normalize_repository_uri(f"https://github.com/{repository}")
    return normalize_repository_uri(repository)


def normalize_repository_uri(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if raw.startswith("git@"):
        match = re.fullmatch(r"git@([^:]+):(.+)", raw)
        if match is None:
            return None
        raw = f"https://{match.group(1)}/{match.group(2)}"
    if raw.startswith("git+"):
        raw = raw[4:]
    raw, _ = _split_uri_reference(raw)
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if host not in {"github.com", "gitlab.com"}:
        return None
    path = parsed.path.strip("/").removesuffix(".git")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    if host == "github.com":
        parts = parts[:2]
    return f"https://{host}/{'/'.join(parts).lower()}"


def is_immutable_reference(value: str) -> bool:
    candidate = _normalized_digest(value)
    return _COMMIT_DIGEST.fullmatch(candidate) is not None


def validate_publisher_organization_allowlist(
    values: Sequence[str],
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("publisher organization allowlist must be a list")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip().lower()
        if not value:
            continue
        if _ALLOWLIST_ENTRY.fullmatch(value) is None:
            raise ValueError(
                "publisher organization allowlist entries must use "
                "'organization' or 'provider:organization' syntax"
            )
        if value not in seen:
            seen.add(value)
            normalized.append(value)
    return tuple(normalized)


def publisher_matches_organization_allowlist(
    identity: PublisherIdentity,
    allowlist: Sequence[str],
) -> bool:
    repository = _publisher_repository_path(identity)
    if repository is None:
        return False
    kind = identity.kind.lower()
    for entry in validate_publisher_organization_allowlist(allowlist):
        match = _ALLOWLIST_ENTRY.fullmatch(entry)
        match = cast(re.Match[str], match)
        expected_kind = match.group("kind")
        organization = match.group("organization").lower()
        if expected_kind is not None and expected_kind not in kind:
            continue
        if repository == organization or repository.startswith(f"{organization}/"):
            return True
    return False


def evaluate_source_release_provenance(
    report: TrustReport,
    *,
    expected_tag: str | None = None,
) -> list[RiskFlag]:
    """Attach risk flags for source, release tag, artifact, and attestation parity."""
    existing = [
        flag
        for flag in report.risk_flags
        if not flag.code.startswith("source_release_")
    ]
    flags: list[RiskFlag] = []
    declared_repositories = {
        normalized
        for url in (*report.declared_repository_urls, *report.repository_urls)
        if (normalized := normalize_repository_uri(url)) is not None
    }
    slsa = [
        provenance
        for file in report.files
        for provenance in file.slsa_provenance
        if provenance.valid
    ]
    source_repositories = {
        provenance.source_repository
        for provenance in slsa
        if provenance.source_repository
    }
    source_commits = {
        provenance.source_commit
        for provenance in slsa
        if provenance.source_commit
    }
    release_refs = [
        provenance.workflow_ref
        for provenance in slsa
        if provenance.workflow_ref
    ]
    expected_ref = expected_tag or f"v{report.version}"

    if not declared_repositories:
        flags.append(
            _source_release_flag(
                "source_release_declared_repository_missing",
                "No declared source repository was available for provenance parity.",
                why=[
                    "Project metadata did not expose a supported GitHub or GitLab repository URL.",
                ],
            )
        )
    if not slsa:
        flags.append(
            _source_release_flag(
                "source_release_attestation_missing",
                "No valid SLSA provenance was available for source/release parity.",
                why=[
                    "PyPI artifact attestations did not contain a validated source material.",
                ],
            )
        )
    if declared_repositories and source_repositories:
        unexpected = sorted(source_repositories.difference(declared_repositories))
        if unexpected:
            flags.append(
                _source_release_flag(
                    "source_release_repository_mismatch",
                    "Attested source repositories do not match declared repository metadata.",
                    why=[
                        "declared=" + ", ".join(sorted(declared_repositories)),
                        "attested=" + ", ".join(sorted(source_repositories)),
                    ],
                )
            )
    if len(source_commits) > 1:
        flags.append(
            _source_release_flag(
                "source_release_commit_mismatch",
                "Attestations point to more than one source commit.",
                why=sorted(source_commits),
            )
        )
    elif not source_commits and slsa:
        flags.append(
            _source_release_flag(
                "source_release_commit_missing",
                "Attestations did not identify a source commit.",
            )
        )
    mismatched_refs = [
        ref
        for ref in release_refs
        if not _source_release_tag_matches(ref, expected_ref)
    ]
    if mismatched_refs:
        flags.append(
            _source_release_flag(
                "source_release_tag_mismatch",
                "Attested workflow refs do not match the intended release tag.",
                why=[
                    f"expected={expected_ref}",
                    "observed=" + ", ".join(sorted(set(mismatched_refs))),
                ],
            )
        )
    if report.files and not all(file.verified for file in report.files):
        flags.append(
            _source_release_flag(
                "source_release_artifact_unverified",
                "One or more PyPI artifacts lack verified provenance.",
                why=[
                    (
                        f"verified={report.coverage.verified_files}/"
                        f"{report.coverage.total_files}"
                    )
                ],
            )
        )
    github_asset_refs = [
        file.url
        for file in report.files
        if urlparse(file.url).hostname == "github.com"
        and "/releases/download/" in urlparse(file.url).path
    ]
    mismatched_assets = [
        url
        for url in github_asset_refs
        if not _github_release_asset_tag_matches(url, expected_ref)
    ]
    if mismatched_assets:
        flags.append(
            _source_release_flag(
                "source_release_github_asset_mismatch",
                "GitHub release asset URLs do not match the intended release tag.",
                why=mismatched_assets,
            )
        )

    report.risk_flags = [*existing, *flags]
    return flags


def _parse_materials(value: object) -> list[ProvenanceMaterial]:
    if not isinstance(value, list) or not value:
        raise SlsaValidationError(
            "buildDefinition.resolvedDependencies must contain materials"
        )
    materials: list[ProvenanceMaterial] = []
    seen: dict[str, dict[str, str]] = {}
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise SlsaValidationError(
                f"resolvedDependencies[{index}] must be an object"
            )
        uri = _required_resource_uri(
            item.get("uri"),
            f"resolvedDependencies[{index}].uri",
        )
        raw_digest = item.get("digest")
        if raw_digest is not None and not isinstance(raw_digest, Mapping):
            raise SlsaValidationError(
                f"resolvedDependencies[{index}].digest must be an object"
            )
        digests = {
            str(algorithm).strip().lower(): str(digest).strip().lower()
            for algorithm, digest in (
                raw_digest.items() if isinstance(raw_digest, Mapping) else ()
            )
            if str(algorithm).strip() and str(digest).strip()
        }
        if uri in seen and seen[uri] != digests:
            raise SlsaValidationError(
                f"resolved dependency {uri} has conflicting digests"
            )
        _validate_material_digests(digests, index=index)
        seen[uri] = digests
        materials.append(
            ProvenanceMaterial(
                uri=uri,
                digests=digests,
                name=_optional_text(item.get("name")),
            )
        )
    return materials


def _select_source_material(
    materials: Sequence[ProvenanceMaterial],
    *,
    expected_repository: str | None,
) -> ProvenanceMaterial | None:
    repository_materials = [
        material
        for material in materials
        if normalize_repository_uri(material.uri) is not None
    ]
    if expected_repository:
        for material in repository_materials:
            if normalize_repository_uri(material.uri) == expected_repository:
                return material
    return repository_materials[0] if repository_materials else None


def _source_commit(material: ProvenanceMaterial) -> str | None:
    for algorithm in ("gitcommit", "sha1", "sha256"):
        digest = material.digests.get(algorithm)
        if digest and _COMMIT_DIGEST.fullmatch(digest):
            return digest.lower()
    _, reference = _split_uri_reference(material.uri)
    if reference and is_immutable_reference(reference):
        return _normalized_digest(reference)
    return None


def _material_issues(
    materials: Sequence[ProvenanceMaterial],
    source: ProvenanceMaterial,
) -> list[ProvenanceIssue]:
    issues: list[ProvenanceIssue] = []
    weak = [
        material.uri
        for material in materials
        if material is not source
        and not any(
            algorithm.lower() in {"sha256", "sha384", "sha512", "gitcommit"}
            for algorithm in material.digests
        )
    ]
    if weak:
        issues.append(
            ProvenanceIssue(
                code="weak_material_digest",
                severity="medium",
                message="One or more build materials use no strong digest.",
                evidence=weak,
            )
        )
    return issues


def _collect_action_references(value: object, *, key: str = "") -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for nested_key, nested_value in value.items():
            references.update(
                _collect_action_references(
                    nested_value,
                    key=str(nested_key).lower(),
                )
            )
        return references
    if isinstance(value, list):
        for item in value:
            references.update(_collect_action_references(item, key=key))
        return references
    if not isinstance(value, str):
        return references
    if (
        key not in {"uses", "action", "actions", "actionref", "action_ref"}
        and "action" not in key
    ):
        return references
    for match in _ACTION_REFERENCE.finditer(value):
        references.add(f"{match.group('action')}@{match.group('ref')}")
    return references


def _publisher_repository_path(identity: PublisherIdentity) -> str | None:
    normalized = normalize_publisher_repository(identity.kind, identity.repository)
    if normalized is None:
        return None
    parsed = urlparse(normalized)
    return parsed.path.strip("/").lower()


def _source_release_flag(
    code: str,
    message: str,
    *,
    why: list[str] | None = None,
) -> RiskFlag:
    return RiskFlag(
        code=code,
        severity="high",
        message=message,
        why=why or [],
        remediation=[
            "Confirm the release tag, source repository, uploaded artifacts, and "
            "attestation subject through the publisher's trusted release channel.",
            "Regenerate and republish artifacts from the intended immutable commit "
            "when the evidence cannot be reconciled.",
        ],
    )


def _source_release_tag_matches(observed: str, expected: str) -> bool:
    observed_tag = observed.strip().removeprefix("refs/tags/")
    expected_tag = expected.strip().removeprefix("refs/tags/")
    bare_expected = expected_tag.removeprefix("v")
    return observed_tag in {expected_tag, bare_expected, f"v{bare_expected}"}


def _github_release_asset_tag_matches(url: str, expected: str) -> bool:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    try:
        marker = parts.index("download")
    except ValueError:
        return True
    if marker + 1 >= len(parts):
        return False
    return _source_release_tag_matches(parts[marker + 1], expected)


def _workflow_matches(expected: str, observed: str) -> bool:
    expected_path = expected.replace("\\", "/").strip("/")
    observed_path = observed.replace("\\", "/").strip("/")
    return (
        observed_path == expected_path
        or observed_path.endswith(f"/{expected_path}")
        or observed_path.rsplit("/", 1)[-1] == expected_path.rsplit("/", 1)[-1]
    )


def _split_uri_reference(uri: str) -> tuple[str, str | None]:
    at = uri.rfind("@")
    if at <= uri.find("://") + 2:
        return uri, None
    return uri[:at], uri[at + 1 :]


def _normalized_digest(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("sha256:"):
        candidate = candidate.split(":", 1)[1]
    if candidate.startswith("refs/"):
        candidate = candidate.rsplit("/", 1)[-1]
    return candidate.lower()


def _required_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SlsaValidationError(f"{field} must be an object")
    return value


def _optional_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _required_resource_uri(value: object, field: str) -> str:
    text = _optional_text(value)
    if text is None:
        raise SlsaValidationError(f"{field} is required")
    parsed = urlparse(text)
    if not parsed.scheme:
        raise SlsaValidationError(f"{field} must be an absolute URI")
    if parsed.scheme in {"http", "https", "git+http", "git+https"}:
        if not parsed.netloc:
            raise SlsaValidationError(f"{field} must be an absolute URI")
    elif not parsed.path:
        raise SlsaValidationError(f"{field} must be an absolute URI")
    return text


def _validate_material_digests(
    digests: Mapping[str, str],
    *,
    index: int,
) -> None:
    lengths = {
        "sha1": {40},
        "sha256": {64},
        "sha384": {96},
        "sha512": {128},
        "gitcommit": {40, 64},
    }
    for algorithm, digest in digests.items():
        expected = lengths.get(algorithm)
        if expected is None:
            continue
        if len(digest) not in expected or re.fullmatch(r"[0-9a-f]+", digest) is None:
            raise SlsaValidationError(
                f"resolvedDependencies[{index}].digest.{algorithm} is invalid"
            )


def _optional_text(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()
