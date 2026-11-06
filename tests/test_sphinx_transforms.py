"""Tests for GitHub-Flavored Markdown to WCAG Sphinx AST transforms."""

import pathlib
import sys
import tempfile

from docutils import nodes
from sphinx.application import Sphinx
from sphinx.util.docutils import docutils_namespace


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "docs") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "docs"))


def _build_temp_site(
    files: dict[str, str],
    repo_files: dict[str, str] | None = None,
    binary_docs_files: dict[str, bytes] | None = None,
):
    """Run a real Sphinx HTML build in a temp repo layout and return (out_dir, doctrees, warnings)."""
    tmp_dir = tempfile.TemporaryDirectory()
    root = pathlib.Path(tmp_dir.name)
    docs_dir = root / "docs"
    out_dir = root / "_build" / "html"
    doctree_dir = root / "_build" / "doctrees"
    docs_dir.mkdir(parents=True)

    for rel, content in (repo_files or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    for rel, payload in (binary_docs_files or {}).items():
        target = docs_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    conf_code = """
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
extensions = ["myst_parser", "_ext.gfm_accessibility"]
gfm_repo_root = str(pathlib.Path(__file__).resolve().parents[1])
gfm_repo_url = "https://github.com/dandye/agentic_soc_gemini_enterprise"
gfm_repo_branch = "main"
"""
    # Symlink _ext into temp docs_dir
    (docs_dir / "_ext").symlink_to(REPO_ROOT / "docs" / "_ext")
    (docs_dir / "conf.py").write_text(conf_code, encoding="utf-8")

    for rel, content in files.items():
        target = docs_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    import io

    warning_stream = io.StringIO()
    with docutils_namespace():
        app = Sphinx(
            srcdir=str(docs_dir),
            confdir=str(docs_dir),
            outdir=str(out_dir),
            doctreedir=str(doctree_dir),
            buildername="html",
            warning=warning_stream,
        )
        app.build()
        doctree = app.env.get_doctree("index")
    html = (out_dir / "index.html").read_text(encoding="utf-8")
    return tmp_dir, doctree, html, warning_stream.getvalue()


# Minimal 1x1 PNG bytes for image tests
TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc`\x00\x00"
    b"\x00\x02\x00\x01\xe5'\xde\xfc\x00\x00\x00\x00IEND\xaeB`\x82"
)


def test_promotes_gfm_image_and_italic_caption_to_semantic_figure():
    md = """# Governance Overview

![Agent Gateway details showing three extensions](gateway.png)\\
*Figure 1. **Agent Platform > Gateways** details for `agw-secops-egress`.*

Regular paragraph with *emphasis* stays a paragraph.
"""
    tmp_dir, doctree, html, warnings = _build_temp_site(
        {"index.md": md}, binary_docs_files={"gateway.png": TINY_PNG}
    )
    try:
        assert warnings == ""
    finally:
        tmp_dir.cleanup()

    figures = list(doctree.findall(nodes.figure))
    assert len(figures) == 1
    fig = figures[0]
    imgs = list(fig.findall(nodes.image))
    captions = list(fig.findall(nodes.caption))
    assert len(imgs) == 1
    assert imgs[0]["alt"] == "Agent Gateway details showing three extensions"
    assert len(captions) == 1
    assert "Figure 1." in captions[0].astext()
    assert "agw-secops-egress" in captions[0].astext()
    assert "<figure" in html
    assert "<figcaption>" in html
    assert "<strong>Agent Platform &gt; Gateways</strong>" in html
    assert "Regular paragraph with <em>emphasis</em> stays a paragraph." in html


def test_promotes_gfm_blockquote_alerts_to_admonitions():
    md = """# Alerts

> [!IMPORTANT]
> Set `verify_enforcement = "enforced"` in production.

> [!WARNING]
> Deleting the gateway unbinds dependent agents.
"""
    tmp_dir, doctree, html, warnings = _build_temp_site({"index.md": md})
    try:
        assert warnings == ""
        importants = list(doctree.findall(nodes.important))
        warnings_nodes = list(doctree.findall(nodes.warning))
        assert len(importants) == 1
        assert len(warnings_nodes) == 1
        assert "[!IMPORTANT]" not in importants[0].astext()
        assert "verify_enforcement" in importants[0].astext()
        assert 'class="admonition important"' in html
        assert 'class="admonition warning"' in html
    finally:
        tmp_dir.cleanup()


def test_rewrites_repo_relative_links_outside_docs_to_github_urls():
    md = """# Troubleshooting

Inspect [`60-model-armor.tf`](../terraform/60-model-armor.tf#L12) and the
[`terraform/`](../terraform/) directory.
"""
    repo_files = {"terraform/60-model-armor.tf": "# model armor\n"}
    tmp_dir, _doctree, html, warnings = _build_temp_site(
        {"index.md": md}, repo_files=repo_files
    )
    try:
        assert warnings == ""
        assert (
            'href="https://github.com/dandye/agentic_soc_gemini_enterprise/blob/main/terraform/60-model-armor.tf#L12"'
            in html
        )
        assert (
            'href="https://github.com/dandye/agentic_soc_gemini_enterprise/tree/main/terraform"'
            in html
        )
    finally:
        tmp_dir.cleanup()
