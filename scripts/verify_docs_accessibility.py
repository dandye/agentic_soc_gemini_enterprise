#!/usr/bin/env python3
"""Verify built Sphinx HTML documentation against WCAG 2.1 Level AA with axe-core.

Serves ``docs/_build/html`` over an ephemeral localhost HTTP server, opens
representative pages in headless Chromium across both ``dark`` and ``light``
themes, runs ``axe-core`` (``wcag2a``, ``wcag2aa``, ``wcag21a``, ``wcag21aa``),
and asserts semantic ``<figure>`` + ``<figcaption>`` promotion on governance
screenshots.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, sync_playwright
from playwright.sync_api import Error as PlaywrightError


DEFAULT_PAGES: tuple[str, ...] = (
    "index.html",
    "agent_governance.html",
    "agent_governance_design.html",
    "agent_governance_troubleshooting.html",
    "architecture.html",
    "alloydb_similarity_engine_summary.html",
    "commands.html",
)

EXPECTED_FIGURE_COUNTS: dict[str, int] = {
    "agent_governance.html": 12,
    "agent_governance_design.html": 4,
    "agent_governance_troubleshooting.html": 2,
    "architecture.html": 1,
}

WCAG_TAGS: list[str] = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]


class _QuietHandler(SimpleHTTPRequestHandler):
    """Silence per-request HTTP access logs during automated audits."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        del format, args


def _launch_chromium(pw: Any) -> Browser:
    """Launch Playwright's Chromium, falling back to system Chrome if needed."""
    try:
        return pw.chromium.launch(headless=True)
    except PlaywrightError:
        for candidate in ("google-chrome", "chromium", "chromium-browser"):
            binary = shutil.which(candidate)
            if binary:
                return pw.chromium.launch(
                    headless=True,
                    executable_path=binary,
                    args=["--no-sandbox", "--disable-gpu"],
                )
        raise


def run_audit(html_dir: pathlib.Path, pages: tuple[str, ...]) -> int:
    """Audit ``pages`` inside ``html_dir`` in dark and light modes."""
    if not html_dir.is_dir():
        print(f"ERROR: HTML build directory not found: {html_dir}", file=sys.stderr)
        return 1

    for page_rel in pages:
        if not (html_dir / page_rel).is_file():
            print(
                f"ERROR: Expected built page missing: {html_dir / page_rel}",
                file=sys.stderr,
            )
            return 1

    handler = partial(_QuietHandler, directory=str(html_dir))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    axe = Axe()
    failures: list[str] = []

    try:
        with sync_playwright() as pw:
            browser = _launch_chromium(pw)
            try:
                context = browser.new_context(viewport={"width": 1440, "height": 900})
                page = context.new_page()

                for theme in ("dark", "light"):
                    for page_rel in pages:
                        url = f"http://127.0.0.1:{port}/{page_rel}"
                        page.goto(url, wait_until="load")
                        page.evaluate(
                            """(mode) => {
                  document.documentElement.dataset.theme = mode;
                  document.documentElement.dataset.mode = mode;
                  localStorage.setItem("mode", mode);
                  localStorage.setItem("theme", mode);
                }""",
                            theme,
                        )
                        page.wait_for_function(
                            """() => {
                  const blocks = Array.from(document.querySelectorAll(".mermaid"));
                  return blocks.every(
                    (el) =>
                      el.getAttribute("data-processed") === "true" ||
                      el.hasAttribute("data-mermaid-deferred") ||
                      el.hasAttribute("data-mermaid-render-failed")
                  );
                }""",
                            timeout=10000,
                        )
                        page.wait_for_timeout(150)

                        results = axe.run(
                            page,
                            options={
                                "runOnly": {"type": "tag", "values": WCAG_TAGS},
                                "resultTypes": ["violations"],
                            },
                        )
                        violations = results.response.get("violations", [])
                        status = (
                            "PASS" if not violations else f"FAIL ({len(violations)})"
                        )
                        print(f"[{theme:5s}] {page_rel:40s} -> {status}")

                        for violation in violations:
                            vid = violation.get("id", "unknown")
                            impact = violation.get("impact", "unknown")
                            help_text = violation.get("help", "")
                            targets = [
                                n.get("target", [])
                                for n in violation.get("nodes", [])[:3]
                            ]
                            failures.append(
                                f"[{theme}] {page_rel}: {vid} ({impact}) - {help_text} | targets={targets}"
                            )

                        if theme == "dark" and page_rel in EXPECTED_FIGURE_COUNTS:
                            expected = EXPECTED_FIGURE_COUNTS[page_rel]
                            fig_stats = page.evaluate(
                                """() => {
                    const figs = Array.from(document.querySelectorAll("main figure"));
                    return {
                      count: figs.length,
                      missingAlt: figs.filter(f => {
                        const img = f.querySelector("img");
                        return !img || !(img.getAttribute("alt") || "").trim();
                      }).length,
                      missingCaption: figs.filter(f => {
                        const cap = f.querySelector("figcaption");
                        return !cap || !(cap.textContent || "").trim();
                      }).length,
                    };
                  }"""
                            )
                            if fig_stats["count"] != expected:
                                failures.append(
                                    f"[semantic-figure] {page_rel}: expected {expected} <figure> elements, found {fig_stats['count']}"
                                )
                            if fig_stats["missingAlt"] > 0:
                                failures.append(
                                    f"[semantic-figure] {page_rel}: {fig_stats['missingAlt']} <figure> elements missing non-empty img[alt]"
                                )
                            if fig_stats["missingCaption"] > 0:
                                failures.append(
                                    f"[semantic-figure] {page_rel}: {fig_stats['missingCaption']} <figure> elements missing non-empty <figcaption>"
                                )
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()

    if failures:
        print("\nAccessibility verification failed:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1

    print(
        f"\nWCAG 2.1 Level AA verification passed across {len(pages)} pages x 2 themes (0 violations)."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--html-dir",
        type=pathlib.Path,
        default=pathlib.Path("docs/_build/html"),
        help="Path to the built Sphinx HTML output directory.",
    )
    parser.add_argument(
        "--page",
        action="append",
        dest="pages",
        help="Specific relative HTML page(s) to audit (defaults to core suite).",
    )
    args = parser.parse_args()
    pages = tuple(args.pages) if args.pages else DEFAULT_PAGES
    return run_audit(args.html_dir.resolve(), pages)


if __name__ == "__main__":
    raise SystemExit(main())
