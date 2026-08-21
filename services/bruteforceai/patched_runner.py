"""Run upstream BruteForceAI with BreachSentinel's lab-only detector patch."""

from __future__ import annotations

import os
from pathlib import Path
import runpy
import sys


repo = Path(os.getenv("BRUTEFORCEAI_REPO", "/opt/BruteForceAI"))
entrypoint = repo / "BruteForceAI.py"
if not entrypoint.is_file():
    raise SystemExit(f"BruteForceAI entrypoint is unavailable: {entrypoint}")

sys.path.insert(0, str(repo))

from bs_multisignal_detector import install_patch  # noqa: E402


install_patch()
runpy.run_path(str(entrypoint), run_name="__main__")
