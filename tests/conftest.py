"""Pytest configuration and environment setup."""

import sys
from pathlib import Path


repo_root = Path(__file__).parent.parent
scripts_dir = repo_root / "installation_scripts"
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))
