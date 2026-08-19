"""Curated breach/leak/forum intel sources (clearnet RSS + Tor-gated)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).with_name("intel_catalog.json")


def load_intel_catalog(path: Path | None = None) -> list[dict[str, Any]]:
    """Load curated intel feed rows for seeding."""
    target = path or CATALOG_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("intel catalog must be a JSON list")
    return data
