"""trustcheck package."""

from importlib.metadata import PackageNotFoundError, version

from .models import TrustReport
from .service import inspect_package

try:
    __version__ = version("trustcheck")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["TrustReport", "__version__", "inspect_package"]
