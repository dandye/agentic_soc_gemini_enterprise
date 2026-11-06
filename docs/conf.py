"""Sphinx configuration for Agentic SOC for Gemini Enterprise documentation."""

from __future__ import annotations

import pathlib
import sys


DOCS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = DOCS_DIR.parent
if str(DOCS_DIR) not in sys.path:
    sys.path.insert(0, str(DOCS_DIR))

project = "Agentic SOC for Gemini Enterprise"
author = "Dan Dye"
copyright = "2026, Dan Dye"  # noqa: A001

root_doc = "index"
language = "en"

extensions = [
    "myst_parser",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinxcontrib.mermaid",
    "_ext.gfm_accessibility",
]

myst_enable_extensions = [
    "amsmath",
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "linkify",
    "replacements",
    "smartquotes",
    "strikethrough",
    "tasklist",
]
myst_fence_as_directive = ["mermaid"]
myst_heading_anchors = 4
myst_linkify_fuzzy_links = False

gfm_repo_root = str(REPO_ROOT)
gfm_repo_url = "https://github.com/dandye/agentic_soc_gemini_enterprise"
gfm_repo_branch = "main"

exclude_patterns = [
    "_build",
    "docs-dist",
    "Thumbs.db",
    ".DS_Store",
    ".aqua_goal_stripped.md",
]

html_theme = "pydata_sphinx_theme"
html_title = "Agentic SOC for Gemini Enterprise"
html_baseurl = "https://dandye.github.io/agentic_soc_gemini_enterprise/"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_show_sourcelink = False

html_context = {
    "default_mode": "dark",
    "github_user": "dandye",
    "github_repo": "agentic_soc_gemini_enterprise",
    "github_version": "main",
    "doc_path": "docs",
}

html_theme_options = {
    "github_url": "https://github.com/dandye/agentic_soc_gemini_enterprise",
    "use_edit_page_button": True,
    "navigation_with_keys": False,
    "show_nav_level": 2,
    "navigation_depth": 4,
    "header_links_before_dropdown": 5,
    "pygments_light_style": "a11y-high-contrast-light",
    "pygments_dark_style": "a11y-high-contrast-dark",
    "primary_sidebar_end": [],
    "secondary_sidebar_items": ["page-toc", "edit-this-page"],
    "footer_start": ["copyright"],
    "footer_end": ["sphinx-version", "theme-version"],
}

mermaid_d3_zoom = False
copybutton_prompt_text = r"^\$ |^>>> |^\.\.\. "
copybutton_prompt_is_regexp = True
