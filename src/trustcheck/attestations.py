from __future__ import annotations

import base64
import importlib
import json
import sys
from typing import Any, Literal, cast

from cryptography import x509
from cryptography.x509 import Certificate
from packaging.tags import Tag
from packaging.utils import (
    BuildTag,
    NormalizedName,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import Version
from pydantic import Base64Bytes, BaseModel, ConfigDict, Field, ValidationError

from .provenance import (
    SLSA_PROVENANCE_V1,
    SlsaValidationError,
    analyze_slsa_provenance,
)

PYPI_PUBLISH_V1 = "https://docs.pypi.org/attestations/publish/v1"
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
SUPPORTED_ATTESTATION_TYPES = {PYPI_PUBLISH_V1, SLSA_PROVENANCE_V1}

_SdistName = tuple[NormalizedName, Version]
_BdistName = tuple[NormalizedName, Version, BuildTag, frozenset[Tag]]
_DistName = _SdistName | _BdistName
_SIGSTORE_EXPORTS = {
    "Bundle": ("sigstore.models", "Bundle"),
    "SigstoreError": ("sigstore.errors", "Error"),
    "SigstoreVerificationError": ("sigstore.errors", "VerificationError"),
    "TUFError": ("sigstore.errors", "TUFError"),
    "Verifier": ("sigstore.verify", "Verifier"),
    "policy": ("sigstore.verify", "policy"),
}


class AttestationError(ValueError):
    pass


class ConversionError(AttestationError):
    pass


class VerificationError(AttestationError):
    def __init__(self, message: str) -> None:
        super().__init__(f"Verification failed: {message}")


class Distribution(BaseModel):
    name: str
    digest: str

    def model_post_init(self, __context: Any) -> None:
        _parse_distribution_filename(self.name)


class VerificationMaterial(BaseModel):
    certificate: Base64Bytes
    transparency_entries: list[dict[str, Any]] = Field(min_length=1)


class Envelope(BaseModel):
    statement: Base64Bytes
    signature: Base64Bytes


class StatementSubject(BaseModel):
    name: str | None
    digest: dict[str, str]


class Statement(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type_: Literal["https://in-toto.io/Statement/v1"] = Field(alias="_type")
    subjects: list[StatementSubject] = Field(alias="subject", min_length=1)
    predicate_type: str = Field(alias="predicateType")
    predicate: dict[str, Any] | None = None


class Publisher(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str
    repository: str | None = None
    workflow: str | None = None
    workflow_filepath: str | None = None
    environment: str | None = None
    email: str | None = None
    project_id: str | None = None
    pipeline_definition_id: str | None = None
    vcs_origin: str | None = None
    vcs_ref: str | None = None

    def as_policy(self) -> Any:
        policy_module = _sigstore_policy()
        if self.kind == "GitHub":
            return _GitHubPublisherPolicy(
                repository=_required(self.repository, "repository", self.kind),
                workflow=_required(self.workflow, "workflow", self.kind),
            )
        if self.kind == "GitLab":
            return _GitLabPublisherPolicy(
                repository=_required(self.repository, "repository", self.kind),
                workflow_filepath=_required(
                    self.workflow_filepath,
                    "workflow_filepath",
                    self.kind,
                ),
            )
        if self.kind == "Google":
            return policy_module.Identity(
                identity=_required(self.email, "email", self.kind),
                issuer="https://accounts.google.com",
            )
        if self.kind == "CircleCI":
            return _CircleCIPublisherPolicy(
                project_id=_required(self.project_id, "project_id", self.kind),
                pipeline_definition_id=_required(
                    self.pipeline_definition_id,
                    "pipeline_definition_id",
                    self.kind,
                ),
                vcs_origin=self.vcs_origin,
                vcs_ref=self.vcs_ref,
            )
        raise VerificationError(f"unsupported Trusted Publisher kind: {self.kind}")


class Attestation(BaseModel):
    version: Literal[1]
    verification_material: VerificationMaterial
    envelope: Envelope

    def to_bundle(self) -> Any:
        material = self.verification_material
        bundle_payload = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {
                    "rawBytes": _base64_text(material.certificate),
                },
                "tlogEntries": [material.transparency_entries[0]],
                "timestampVerificationData": {
                    "rfc3161Timestamps": [],
                },
            },
            "dsseEnvelope": {
                "payload": _base64_text(self.envelope.statement),
                "payloadType": IN_TOTO_PAYLOAD_TYPE,
                "signatures": [
                    {
                        "sig": _base64_text(self.envelope.signature),
                    }
                ],
            },
        }
        try:
            bundle_type = _sigstore_symbol("Bundle")
            sigstore_error = _sigstore_symbol("SigstoreError")
            return bundle_type.from_json(json.dumps(bundle_payload))
        except ImportError as exc:
            raise ConversionError(
                f"invalid Sigstore bundle: {exc}"
            ) from exc
        except (sigstore_error, ValueError) as exc:
            raise ConversionError(f"invalid Sigstore bundle: {exc}") from exc

    def verify(
        self,
        publisher: Publisher,
        distribution: Distribution,
        *,
        offline: bool = False,
    ) -> tuple[str, dict[str, Any] | None]:
        bundle = self.to_bundle()
        try:
            sigstore_verification_error = _sigstore_symbol(
                "SigstoreVerificationError"
            )
            payload_type, payload = _production_verifier(offline=offline).verify_dsse(
                bundle,
                publisher.as_policy(),
            )
        except ImportError as exc:
            raise VerificationError(f"sigstore package is not importable: {exc}") from exc
        except sigstore_verification_error as exc:
            raise VerificationError(str(exc)) from exc

        if payload_type != IN_TOTO_PAYLOAD_TYPE:
            raise VerificationError(f"expected JSON envelope, got {payload_type}")

        try:
            statement = Statement.model_validate_json(payload)
        except ValidationError as exc:
            raise VerificationError(f"invalid statement: {exc}") from exc

        if len(statement.subjects) != 1:
            raise VerificationError("too many subjects in statement (must be exactly one)")
        subject = statement.subjects[0]
        if not subject.name:
            raise VerificationError("invalid subject: missing name")

        try:
            subject_name = _parse_distribution_filename(subject.name)
        except ValueError as exc:
            raise VerificationError(f"invalid subject: {exc}") from exc

        distribution_name = _parse_distribution_filename(distribution.name)
        if subject_name != distribution_name:
            raise VerificationError(
                "subject does not match distribution name: "
                f"{subject.name} != {distribution.name}"
            )

        if subject.digest.get("sha256") != distribution.digest:
            raise VerificationError("subject does not match distribution digest")
        if statement.predicate_type not in SUPPORTED_ATTESTATION_TYPES:
            raise VerificationError(
                f"unknown attestation type: {statement.predicate_type}"
            )
        if statement.predicate_type == SLSA_PROVENANCE_V1:
            try:
                analyze_slsa_provenance(
                    statement.predicate,
                    publisher_kind=publisher.kind,
                    publisher_repository=publisher.repository,
                    publisher_workflow=(
                        publisher.workflow or publisher.workflow_filepath
                    ),
                )
            except SlsaValidationError as exc:
                raise VerificationError(f"invalid SLSA provenance: {exc}") from exc

        return statement.predicate_type, statement.predicate


class AttestationBundle(BaseModel):
    publisher: Publisher
    attestations: list[Attestation]


class Provenance(BaseModel):
    version: Literal[1] = 1
    attestation_bundles: list[AttestationBundle]


class _GitHubPublisherPolicy:
    def __init__(self, repository: str, workflow: str) -> None:
        self._repository = repository
        self._workflow = workflow
        policy_module = _sigstore_policy()
        self._base_policy = policy_module.AllOf(
            [
                policy_module.OIDCIssuerV2(
                    "https://token.actions.githubusercontent.com"
                ),
                policy_module.OIDCSourceRepositoryURI(
                    f"https://github.com/{repository}"
                ),
            ]
        )

    def verify(self, cert: Certificate) -> None:
        policy_module = _sigstore_policy()
        self._base_policy.verify(cert)
        suffixes = _optional_claims(
            cert,
            policy_module.OIDCSourceRepositoryDigest.oid,
            policy_module.OIDCSourceRepositoryRef.oid,
        )
        if not suffixes:
            raise _sigstore_verification_error(
                "Certificate must contain either Source Repository Digest "
                "or Source Repository Ref"
            )

        policy_module.AnyOf(
            [
                policy_module.OIDCBuildConfigURI(
                    "https://github.com/"
                    f"{self._repository}/.github/workflows/{self._workflow}@{suffix}"
                )
                for suffix in suffixes
            ]
        ).verify(cert)


class _GitLabPublisherPolicy:
    def __init__(self, repository: str, workflow_filepath: str) -> None:
        self._repository = repository
        self._workflow_filepath = workflow_filepath
        policy_module = _sigstore_policy()
        self._base_policy = policy_module.AllOf(
            [
                policy_module.OIDCIssuerV2("https://gitlab.com"),
                policy_module.OIDCSourceRepositoryURI(
                    f"https://gitlab.com/{repository}"
                ),
            ]
        )

    def verify(self, cert: Certificate) -> None:
        policy_module = _sigstore_policy()
        self._base_policy.verify(cert)
        suffixes = [
            _claim(cert, policy_module.OIDCSourceRepositoryDigest.oid),
            _claim(cert, policy_module.OIDCSourceRepositoryRef.oid),
        ]
        policy_module.AnyOf(
            [
                policy_module.OIDCBuildConfigURI(
                    f"https://gitlab.com/{self._repository}//"
                    f"{self._workflow_filepath}@{suffix}"
                )
                for suffix in suffixes
            ]
        ).verify(cert)


class _CircleCIPublisherPolicy:
    def __init__(
        self,
        project_id: str,
        pipeline_definition_id: str,
        vcs_origin: str | None,
        vcs_ref: str | None,
    ) -> None:
        policy_module = _sigstore_policy()
        policies: list[Any] = [
            policy_module.OIDCIssuerV2("https://oidc.circleci.com"),
            policy_module.OIDCBuildSignerURI(
                f"https://circleci.com/api/v2/projects/{project_id}/"
                f"pipeline-definitions/{pipeline_definition_id}"
            ),
        ]
        if vcs_origin is not None:
            policies.append(policy_module.OIDCSourceRepositoryURI(vcs_origin))
        if vcs_ref is not None:
            policies.append(policy_module.OIDCSourceRepositoryRef(vcs_ref))
        self._policy = policy_module.AllOf(policies)

    def verify(self, cert: Certificate) -> None:
        self._policy.verify(cert)


def _required(value: str | None, field: str, publisher_kind: str) -> str:
    if value is None or not value.strip():
        raise VerificationError(
            f"{publisher_kind} Trusted Publisher is missing required field {field}"
        )
    return value


def _production_verifier(*, offline: bool) -> Any:
    verifier_type = _sigstore_symbol("Verifier")
    tuf_error = _sigstore_symbol("TUFError")
    try:
        return verifier_type.production(offline=offline)
    except tuf_error as exc:
        if offline or sys.platform != "win32" or not _has_windows_symlink_error(exc):
            raise

        # TUF refresh requires Windows symlink privileges. Sigstore's offline
        # verifier uses the trusted-root snapshot embedded in its wheel.
        return verifier_type.production(offline=True)


def _has_windows_symlink_error(error: BaseException) -> bool:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, OSError) and getattr(current, "winerror", None) == 1314:
            return True
        current = current.__cause__ or current.__context__
    return False


def _base64_text(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _parse_distribution_filename(filename: str) -> _DistName:
    if filename.endswith(".whl"):
        return parse_wheel_filename(filename)
    if filename.endswith((".tar.gz", ".zip")):
        return parse_sdist_filename(filename)
    raise ValueError(f"unknown distribution format: {filename}")


def _optional_claims(cert: Certificate, *oids: x509.ObjectIdentifier) -> list[str]:
    claims: list[str] = []
    for oid in oids:
        try:
            claims.append(_claim(cert, oid))
        except x509.ExtensionNotFound:
            continue
    return claims


def _claim(cert: Certificate, oid: x509.ObjectIdentifier) -> str:
    extension = cert.extensions.get_extension_for_oid(oid).value
    encoded = cast(Any, extension).public_bytes()
    return _decode_der_utf8_string(encoded)


def _decode_der_utf8_string(encoded: bytes) -> str:
    if len(encoded) < 2 or encoded[0] != 0x0C:
        raise _sigstore_verification_error(
            "certificate claim is not a DER UTF8String"
        )

    first_length = encoded[1]
    if first_length & 0x80:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or len(encoded) < 2 + length_bytes:
            raise _sigstore_verification_error(
                "certificate claim has invalid DER length"
            )
        length = int.from_bytes(encoded[2 : 2 + length_bytes], "big")
        value_offset = 2 + length_bytes
    else:
        length = first_length
        value_offset = 2

    if value_offset + length != len(encoded):
        raise _sigstore_verification_error(
            "certificate claim has invalid DER length"
        )
    try:
        return encoded[value_offset:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _sigstore_verification_error(
            "certificate claim is not valid UTF-8"
        ) from exc


def __getattr__(name: str) -> Any:
    if name not in _SIGSTORE_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = _SIGSTORE_EXPORTS[name]
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value


def _sigstore_symbol(name: str) -> Any:
    try:
        return globals()[name]
    except KeyError:
        return __getattr__(name)


def _sigstore_policy() -> Any:
    try:
        return _sigstore_symbol("policy")
    except ImportError as exc:
        raise VerificationError(f"sigstore package is not importable: {exc}") from exc


def _sigstore_verification_error(message: str) -> Exception:
    try:
        error_type = cast(type[Exception], _sigstore_symbol("SigstoreVerificationError"))
    except ImportError:
        return VerificationError(message)
    return error_type(message)
