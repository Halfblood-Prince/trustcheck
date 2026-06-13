from importlib.metadata import PackageNotFoundError, version

from .advisories import (
    CisaKevClient,
    EpssClient,
    OsvClient,
    OsvProvider,
    VulnerabilityIntelligenceClient,
)
from .contract import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, get_json_schema
from .exports import (
    INDUSTRY_OUTPUT_FORMATS,
    OUTPUT_FORMATS,
    ExportPackage,
    SourceLocation,
    package_purl,
    render_export,
)
from .indexes import (
    DependencyConfusionFinding,
    IndexConfiguration,
    IndexFile,
    IndexProject,
    SimpleRepositoryClient,
)
from .lockfiles import LockedPackage, LockfileResolution, load_lockfile
from .models import TrustReport, VulnerabilitySuppression
from .resolver import (
    ArtifactReference,
    PipResolver,
    Resolution,
    ResolutionError,
    ResolvedDistribution,
    TargetEnvironment,
    discover_installed_distributions,
)
from .service import inspect_package

try:
    from ._version import version as __version__
except ImportError:
    try:
        __version__ = version("trustcheck")
    except PackageNotFoundError:
        __version__ = "0+unknown"

__all__ = [
    "JSON_SCHEMA_ID",
    "JSON_SCHEMA_VERSION",
    "INDUSTRY_OUTPUT_FORMATS",
    "OUTPUT_FORMATS",
    "ArtifactReference",
    "CisaKevClient",
    "DependencyConfusionFinding",
    "EpssClient",
    "ExportPackage",
    "IndexConfiguration",
    "IndexFile",
    "IndexProject",
    "LockfileResolution",
    "OsvClient",
    "OsvProvider",
    "LockedPackage",
    "PipResolver",
    "Resolution",
    "ResolutionError",
    "ResolvedDistribution",
    "SourceLocation",
    "TargetEnvironment",
    "TrustReport",
    "VulnerabilityIntelligenceClient",
    "VulnerabilitySuppression",
    "SimpleRepositoryClient",
    "__version__",
    "discover_installed_distributions",
    "get_json_schema",
    "inspect_package",
    "load_lockfile",
    "package_purl",
    "render_export",
]
