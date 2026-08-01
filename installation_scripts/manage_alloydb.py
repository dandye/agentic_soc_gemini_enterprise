#!/usr/bin/env python3
"""
CLI entry point for the AlloyDB detection-reports manager.

The single authored implementation lives in ``agent_soc_manager/manage_alloydb.py``.
It has to live inside the agent package because Agent Engine deployment ships the
``extra_packages`` list in ``manage_agent_engine.py`` — which includes
``agent_soc_manager`` but not ``installation_scripts`` — and the deployed agent
imports ``AlloyDBManager`` at runtime (see ``agent_soc_manager/agent.py``).

This module used to be a verbatim 2,351-line copy of that file. It is now a thin
re-export so there is exactly one authored copy.

The implementation is loaded *by file path* rather than as
``agent_soc_manager.manage_alloydb`` on purpose: importing it as a package member
would execute ``agent_soc_manager/__init__.py``, which does ``from . import agent``
and pulls the entire ADK agent stack into what should be a lightweight database
CLI. Loading the module file directly keeps ``just alloydb-*`` dependency-light.
"""

import importlib.util
import sys
from pathlib import Path


_IMPL = (
    Path(__file__).resolve().parent.parent / "agent_soc_manager" / "manage_alloydb.py"
)

if not _IMPL.is_file():  # pragma: no cover - packaging error
    raise ModuleNotFoundError(
        f"AlloyDB manager implementation not found at {_IMPL}. "
        "It is the single authored copy; see agent_soc_manager/manage_alloydb.py."
    )

_spec = importlib.util.spec_from_file_location("_alloydb_impl", _IMPL)
_impl = importlib.util.module_from_spec(_spec)
sys.modules["_alloydb_impl"] = _impl
_spec.loader.exec_module(_impl)

AlloyDBManager = _impl.AlloyDBManager
app = _impl.app

__all__ = ["AlloyDBManager", "app"]

if __name__ == "__main__":
    app()
