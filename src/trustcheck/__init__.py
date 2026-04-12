from importlib.metadata import PackageNotFoundError, version

from .contract import JSON_SCHEMA_ID, JSON_SCHEMA_VERSION, get_json_schema
from .models import TrustReport
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
    "TrustReport",
    "__version__",
    "get_json_schema",
    "inspect_package",
]
