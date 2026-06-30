from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any

from ..plugins import PluginManager


@dataclass(slots=True)
class CommandContext:
    parser: argparse.ArgumentParser
    config_payload: dict[str, object]
    plugin_manager: PluginManager
    facade: Any
