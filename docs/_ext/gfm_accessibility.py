"""Sphinx AST transforms that preserve GitHub Markdown while emitting WCAG HTML.

These transforms let ``docs/*.md`` stay clean CommonMark/GFM when viewed on
``github.com`` while upgrading rendered documentation on GitHub Pages to:

1. Semantic ``<figure>`` + ``<figcaption>`` elements (WCAG 1.1.1 / 1.3.1) from
   ``![alt](path)\\`` followed by ``*Figure N. ...*``.
2. Semantic Docutils admonitions from GFM ``> [!NOTE]`` / ``> [!IMPORTANT]`` /
   ``> [!WARNING]`` / ``> [!TIP]`` / ``> [!CAUTION]`` blockquotes.
3. External GitHub ``blob/`` and ``tree/`` links (preserving ``#L...`` line
   anchors) when a doc links to a tracked repository path outside ``docs/``
   (such as ``../terraform/60-model-armor.tf#L12`` or ``../terraform/``).
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

from docutils import nodes
from myst_parser.mdit_to_docutils import sphinx_ as myst_sphinx
from pygments.lexers.configs import IniLexer
from pygments.lexers.make import MakefileLexer
from pygments.lexers.special import TextLexer
from sphinx import addnodes
from sphinx.application import Sphinx
from sphinx.transforms import SphinxTransform


_GFM_ALERT_RE = re.compile(
    r"^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\](?:[ \t]*\n|[ \t]*$)"
)

_ADMONITION_NODE_BY_KIND: dict[str, type[nodes.Admonition]] = {
    "NOTE": nodes.note,
    "TIP": nodes.tip,
    "IMPORTANT": nodes.important,
    "WARNING": nodes.warning,
    "CAUTION": nodes.caution,
}

_RAW_BREAK_TOKENS = frozenset({"<br>", "<br/>", "<br />", r"\\"})


def _is_image_or_linked_image(node: nodes.Node) -> bool:
    """Return True when ``node`` is an image or a reference wrapping one image."""
    if isinstance(node, nodes.image):
        return True
    if isinstance(node, nodes.reference) and len(node.children) == 1:
        return isinstance(node.children[0], nodes.image)
    return False


def _is_hard_break_or_whitespace(node: nodes.Node) -> bool:
    """Return True for CommonMark/MyST hard-break nodes between image and caption."""
    if isinstance(node, nodes.Text):
        return not node.astext().strip()
    if isinstance(node, nodes.raw) and node.get("format") in {"html", "latex"}:
        return node.astext().strip() in _RAW_BREAK_TOKENS
    return False


def _resolve_repo_outside_docs_url(
    raw_target: str,
    *,
    doc_dir: pathlib.Path,
    docs_root: pathlib.Path,
    repo_root: pathlib.Path,
    repo_url: str,
    repo_branch: str,
) -> str | None:
    """Return a GitHub blob/tree URL when ``raw_target`` resolves outside ``docs/``."""
    if not raw_target or raw_target.startswith(
        ("#", "http://", "https://", "mailto:", "ftp://")
    ):
        return None
    path_part, sep, anchor = raw_target.partition("#")
    if not path_part or not repo_url:
        return None

    resolved = (doc_dir / path_part).resolve()
    if not resolved.exists():
        return None
    if not resolved.is_relative_to(repo_root):
        return None
    if resolved.is_relative_to(docs_root):
        return None

    rel_repo = resolved.relative_to(repo_root).as_posix()
    kind = "tree" if resolved.is_dir() else "blob"
    fragment = f"#{anchor}" if sep else ""
    return f"{repo_url.rstrip('/')}/{kind}/{repo_branch}/{rel_repo}{fragment}"


class PromoteGfmFigureCaptionTransform(SphinxTransform):
    """Promote ``![alt](src)\\`` + ``*Figure ...*`` paragraphs to ``nodes.figure``."""

    default_priority = 210

    def apply(self, **kwargs: Any) -> None:
        for paragraph in list(self.document.findall(nodes.paragraph)):
            children = paragraph.children
            if len(children) < 2:
                continue
            first, middle, last = children[0], children[1:-1], children[-1]
            if not _is_image_or_linked_image(first):
                continue
            if not isinstance(last, nodes.emphasis) or not last.children:
                continue
            if not all(_is_hard_break_or_whitespace(m) for m in middle):
                continue

            figure = nodes.figure()
            figure.source = paragraph.source
            figure.line = paragraph.line
            self.document.set_id(figure)
            figure += first.deepcopy()

            caption = nodes.caption()
            caption.source = last.source
            caption.line = last.line
            for child in last.children:
                caption += child.deepcopy()
            figure += caption

            paragraph.replace_self(figure)


class PromoteGfmAlertBlockquoteTransform(SphinxTransform):
    """Promote GFM ``> [!NOTE]``-style blockquotes to semantic admonitions."""

    default_priority = 211

    def apply(self, **kwargs: Any) -> None:
        for bq in list(self.document.findall(nodes.block_quote)):
            if not bq.children or not isinstance(bq.children[0], nodes.paragraph):
                continue
            first_para = bq.children[0]
            if not first_para.children or not isinstance(
                first_para.children[0], nodes.Text
            ):
                continue

            lead_text = first_para.children[0].astext()
            match = _GFM_ALERT_RE.match(lead_text)
            if not match:
                continue

            kind = match.group(1)
            admonition_cls = _ADMONITION_NODE_BY_KIND[kind]
            admonition = admonition_cls()
            admonition.source = bq.source
            admonition.line = bq.line

            remainder = lead_text[match.end() :]
            new_first_para = first_para.deepcopy()
            if remainder:
                new_first_para[0] = nodes.Text(remainder)
            else:
                del new_first_para[0]

            if new_first_para.children:
                admonition += new_first_para
            for sibling in bq.children[1:]:
                admonition += sibling.deepcopy()

            if admonition.children:
                bq.replace_self(admonition)


class RewriteRepoRelativeLinksTransform(SphinxTransform):
    """Fallback AST rewrite for repo-relative links outside ``docs/``."""

    default_priority = 4

    def apply(self, **kwargs: Any) -> None:
        source_str = self.document.get("source")
        if not source_str:
            return
        doc_dir = pathlib.Path(source_str).resolve().parent
        docs_root = pathlib.Path(self.env.srcdir).resolve()
        repo_root = pathlib.Path(
            self.config.gfm_repo_root or docs_root.parent
        ).resolve()
        repo_url = self.config.gfm_repo_url or ""
        repo_branch = self.config.gfm_repo_branch or "main"

        candidate_types = (
            nodes.reference,
            addnodes.pending_xref,
            addnodes.download_reference,
        )
        for node in list(
            self.document.findall(lambda n: isinstance(n, candidate_types))
        ):
            raw_target = (
                node.get("refuri", "")
                if isinstance(node, nodes.reference)
                else node.get("reftarget", "")
            )
            github_url = _resolve_repo_outside_docs_url(
                raw_target,
                doc_dir=doc_dir,
                docs_root=docs_root,
                repo_root=repo_root,
                repo_url=repo_url,
                repo_branch=repo_branch,
            )
            if not github_url:
                continue

            new_ref = nodes.reference("", "", refuri=github_url, internal=False)
            new_ref.source = node.source
            new_ref.line = node.line

            inner_children = list(node.children)
            if (
                len(inner_children) == 1
                and isinstance(inner_children[0], nodes.inline)
                and "xref" in inner_children[0].get("classes", [])
            ):
                inner_children = list(inner_children[0].children)
            for child in inner_children:
                new_ref += child.deepcopy()

            node.replace_self(new_ref)


def _install_myst_repo_link_hook() -> None:
    """Preserve ``#L...`` anchors on repo links outside ``docs/`` before MyST strips them."""
    if getattr(myst_sphinx.SphinxRenderer, "_gfm_repo_link_hook_installed", False):
        return
    orig_render_link_unknown = myst_sphinx.SphinxRenderer.render_link_unknown

    def _wrapped_render_link_unknown(
        self: myst_sphinx.SphinxRenderer, token: Any
    ) -> None:
        env = getattr(self, "sphinx_env", None)
        if env is not None and getattr(env, "srcdir", None):
            href = str(token.attrGet("href") or "")
            destination = self.md.normalizeLinkText(href)
            docs_root = pathlib.Path(env.srcdir).resolve()
            doc_file = pathlib.Path(env.doc2path(env.docname)).resolve()
            cfg = env.config
            repo_root = pathlib.Path(
                getattr(cfg, "gfm_repo_root", "") or docs_root.parent
            ).resolve()
            github_url = _resolve_repo_outside_docs_url(
                destination,
                doc_dir=doc_file.parent,
                docs_root=docs_root,
                repo_root=repo_root,
                repo_url=getattr(cfg, "gfm_repo_url", ""),
                repo_branch=getattr(cfg, "gfm_repo_branch", "main"),
            )
            if github_url:
                token.attrs["href"] = github_url
                self.render_link_url(token)
                return
        orig_render_link_unknown(self, token)

    myst_sphinx.SphinxRenderer.render_link_unknown = _wrapped_render_link_unknown  # type: ignore[method-assign]
    myst_sphinx.SphinxRenderer._gfm_repo_link_hook_installed = True  # type: ignore[attr-defined]


def setup(app: Sphinx) -> dict[str, Any]:
    """Register configuration values and GFM-to-WCAG transforms."""
    app.add_config_value("gfm_repo_root", "", "env")
    app.add_config_value(
        "gfm_repo_url",
        "https://github.com/dandye/agentic_soc_gemini_enterprise",
        "env",
    )
    app.add_config_value("gfm_repo_branch", "main", "env")

    app.add_lexer("env", IniLexer)
    app.add_lexer("just", MakefileLexer)
    app.add_lexer("udm", TextLexer)

    _install_myst_repo_link_hook()
    app.add_transform(RewriteRepoRelativeLinksTransform)
    app.add_transform(PromoteGfmFigureCaptionTransform)
    app.add_transform(PromoteGfmAlertBlockquoteTransform)

    return {
        "version": "1.0.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
