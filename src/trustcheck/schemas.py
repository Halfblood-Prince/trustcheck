from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DigestsPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sha256: str | None = None


class ReleaseFilePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    filename: str
    url: str
    digests: DigestsPayload = Field(default_factory=DigestsPayload)


class VulnerabilityPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    summary: str | None = None
    details: str | None = None
    aliases: list[str] = Field(default_factory=list)
    source: str | None = None
    fixed_in: list[str] = Field(default_factory=list)
    link: str | None = None


class RolePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str | None = None
    user: str | None = None


class OwnershipPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    organization: str | None = None
    roles: list[RolePayload] = Field(default_factory=list)


class ProjectInfoPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: str | None = None
    summary: str | None = None
    project_urls: dict[str, str] = Field(default_factory=dict)
    ownership: OwnershipPayload = Field(default_factory=OwnershipPayload)


class ProjectResponsePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    info: ProjectInfoPayload = Field(default_factory=ProjectInfoPayload)
    releases: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    urls: list[ReleaseFilePayload] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityPayload] = Field(default_factory=list)


class ProvenanceEnvelopePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: int | None = None
    attestation_bundles: list[dict[str, Any]] = Field(default_factory=list)
