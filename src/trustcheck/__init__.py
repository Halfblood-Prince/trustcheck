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
from .malicious import (
    DEFAULT_TRUSTED_PROJECTS,
    analyze_python_source,
    heuristic_score,
    inspect_native_binary,
)
from .models import (
    HeuristicFinding,
    MaliciousPackageAssessment,
    NativeBinaryInspection,
    RemediationSummary,
    TrustReport,
    VulnerabilitySuppression,
)
from .remediation import (
    REMEDIATION_SCHEMA_ID,
    REMEDIATION_SCHEMA_VERSION,
    BlockedFix,
    FilePatch,
    PullRequestResult,
    RemediationError,
    RemediationPlan,
    RemediationUpgrade,
    RemediationValidation,
    SemanticEdit,
    apply_prepared_remediation,
    create_pull_request,
    plan_remediation,
    prepare_remediation,
)
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
    "REMEDIATION_SCHEMA_ID",
    "REMEDIATION_SCHEMA_VERSION",
    "INDUSTRY_OUTPUT_FORMATS",
    "OUTPUT_FORMATS",
    "ArtifactReference",
    "BlockedFix",
    "CisaKevClient",
    "DEFAULT_TRUSTED_PROJECTS",
    "DependencyConfusionFinding",
    "EpssClient",
    "ExportPackage",
    "FilePatch",
    "IndexConfiguration",
    "IndexFile",
    "IndexProject",
    "HeuristicFinding",
    "LockfileResolution",
    "MaliciousPackageAssessment",
    "OsvClient",
    "OsvProvider",
    "NativeBinaryInspection",
    "LockedPackage",
    "PipResolver",
    "PullRequestResult",
    "RemediationError",
    "RemediationPlan",
    "RemediationSummary",
    "RemediationUpgrade",
    "RemediationValidation",
    "Resolution",
    "ResolutionError",
    "ResolvedDistribution",
    "SourceLocation",
    "SemanticEdit",
    "TargetEnvironment",
    "TrustReport",
    "VulnerabilityIntelligenceClient",
    "VulnerabilitySuppression",
    "SimpleRepositoryClient",
    "__version__",
    "analyze_python_source",
    "apply_prepared_remediation",
    "create_pull_request",
    "discover_installed_distributions",
    "get_json_schema",
    "heuristic_score",
    "inspect_package",
    "inspect_native_binary",
    "load_lockfile",
    "package_purl",
    "plan_remediation",
    "prepare_remediation",
    "render_export",
]
