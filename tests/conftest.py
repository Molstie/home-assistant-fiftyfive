"""Shared test setup."""

from __future__ import annotations

import sys
import types
from pathlib import Path

# The integration package is called ``fiftyfive``, like the PyPI library it
# uses. Mount it under another name so both can be imported, without running
# the integration's __init__ (which needs Home Assistant).
_INTEGRATION = (
    Path(__file__).resolve().parent.parent / "custom_components" / "fiftyfive"
)
_package = types.ModuleType("fiftyfive_fork")
_package.__path__ = [str(_INTEGRATION)]
sys.modules.setdefault("fiftyfive_fork", _package)
