"""Workflow 4: Pre-agent multimodal CTI ingress gate (`gemini-decision-1`).

Generates synthetic PNG screenshots (phishing credential-harvest page vs clean
status dashboard), PDFs (threat advisory vs benign maintenance notice), and
text OSINT reports, then evaluates each through
`triage_multimodal_security_artifact` BEFORE waking any generative LLM.

Writes structured JSON metrics to
`/tmp/decision1_v2_results/workflow4_multimodal_ingress.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governed_agents.shared_decision_guards.multimodal_cti_ingress import (  # noqa: E402
    triage_multimodal_security_artifact,
)


RESULTS_DIR = Path("/tmp/decision1_v2_results")  # noqa: S108
RESULTS_PATH = RESULTS_DIR / "workflow4_multimodal_ingress.json"

# Minimal 5x7 bitmap font for uppercase ASCII + digits + space/punctuation so
# synthetic PNG screenshots contain crisp, readable text with zero external deps.
_FONT_5X7: dict[str, tuple[str, ...]] = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "G": ("01111", "10000", "10000", "10111", "10001", "10001", "01111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "11011", "10001"),
    "X": ("10001", "10001", "01010", "00100", "01010", "10001", "10001"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
    "0": ("01110", "10011", "10101", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00110", "01000", "10000", "11111"),
    ":": ("00000", "00100", "00100", "00000", "00100", "00100", "00000"),
    "-": ("00000", "00000", "00000", "11111", "00000", "00000", "00000"),
    ".": ("00000", "00000", "00000", "00000", "00000", "00000", "00100"),
    "/": ("00001", "00010", "00100", "00100", "01000", "10000", "00000"),
    " ": ("00000", "00000", "00000", "00000", "00000", "00000", "00000"),
}


def render_text_png(
    lines: list[str],
    *,
    bg: tuple[int, int, int] = (248, 250, 252),
    fg: tuple[int, int, int] = (15, 23, 42),
    banner_bg: tuple[int, int, int] | None = None,
    scale: int = 3,
) -> bytes:
    """Renders readable bitmap text lines into an uncompressed RGB PNG."""
    max_chars = max(len(line) for line in lines)
    pad = 16
    width = max(320, pad * 2 + max_chars * 6 * scale)
    height = max(160, pad * 2 + len(lines) * 10 * scale)

    pixels = bytearray(bg * (width * height))

    if banner_bg is not None:
        banner_h = pad + 10 * scale
        for y in range(min(banner_h, height)):
            for x in range(width):
                idx = (y * width + x) * 3
                pixels[idx : idx + 3] = bytes(banner_bg)

    for line_idx, line in enumerate(lines):
        y0 = pad + line_idx * 10 * scale
        for char_idx, ch in enumerate(line.upper()):
            glyph = _FONT_5X7.get(ch, _FONT_5X7[" "])
            x0 = pad + char_idx * 6 * scale
            for gy, row in enumerate(glyph):
                for gx, bit in enumerate(row):
                    if bit != "1":
                        continue
                    for sy in range(scale):
                        for sx in range(scale):
                            px = x0 + gx * scale + sx
                            py = y0 + gy * scale + sy
                            if 0 <= px < width and 0 <= py < height:
                                idx = (py * width + px) * 3
                                pixels[idx : idx + 3] = bytes(fg)

    raw_rows = bytearray()
    stride = width * 3
    for y in range(height):
        raw_rows.append(0)
        raw_rows.extend(pixels[y * stride : (y + 1) * stride])

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw_rows)))
        + chunk(b"IEND", b"")
    )


def render_text_pdf(lines: list[str]) -> bytes:
    """Renders a valid single-page PDF 1.4 document with an xref table."""
    escaped_ops = ["BT", "/F1 11 Tf", "50 750 Td", "15 TL"]
    for idx, line in enumerate(lines):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if idx == 0:
            escaped_ops.append(f"({safe}) Tj")
        else:
            escaped_ops.append(f"T* ({safe}) Tj")
    escaped_ops.append("ET")
    stream_bytes = "\n".join(escaped_ops).encode("latin-1")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        ),
        (
            f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        ),
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    buf = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for obj in objects:
        offsets.append(len(buf))
        buf.extend(obj)

    xref_offset = len(buf)
    buf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(buf)


def _resolve_gemini_api_key() -> str:
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if env_key:
        return env_key
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
    if not project:
        return ""
    try:
        key = subprocess.check_output(  # noqa: S603, S607
            [
                "gcloud",
                "secrets",
                "versions",
                "access",
                "latest",
                "--secret=gemini-api-key",
                f"--project={project}",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if key:
            os.environ["GEMINI_API_KEY"] = key
        return key
    except Exception:  # noqa: BLE001
        return ""


def build_artifacts(out_dir: Path) -> list[dict[str, Any]]:
    """Creates synthetic multimodal CTI artifacts in `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)

    phish_png = out_dir / "artifact_phishing_login.png"
    phish_png.write_bytes(
        render_text_png(
            [
                "URGENT SECURITY ALERT: PASSWORD EXPIRED",
                "CORPORATE SSO VERIFICATION REQUIRED",
                "URL: HTTPS://LOGIN-CORP-VERIFY.EXAMPLE/AUTH",
                "ENTER USERNAME, PASSWORD, AND MFA CODE NOW",
            ],
            bg=(255, 245, 245),
            fg=(127, 29, 29),
            banner_bg=(254, 202, 202),
        )
    )

    clean_png = out_dir / "artifact_clean_dashboard.png"
    clean_png.write_bytes(
        render_text_png(
            [
                "INTERNAL STATUS PAGE",
                "ALL SYSTEMS OPERATIONAL",
                "UPTIME: 99.99 PERCENT",
                "NEXT MAINTENANCE: SUNDAY 02:00 UTC",
            ],
            bg=(240, 253, 244),
            fg=(20, 83, 45),
            banner_bg=(187, 247, 208),
        )
    )

    threat_pdf = out_dir / "artifact_threat_advisory.pdf"
    threat_pdf.write_bytes(
        render_text_pdf(
            [
                "TLP:AMBER Threat Intelligence Advisory - APT Intrusion Campaign",
                "Observed malicious loader delivering Cobalt Strike beacon over HTTPS.",
                "C2 Domain: update-cdn-sync.example (resolves to 198.51.100.77)",
                "Persistence: Scheduled task invoking rundll32.exe with encoded payload.",
                "Action: Immediate SIEM UDM hunt for DNS queries and process execution.",
            ]
        )
    )

    benign_pdf = out_dir / "artifact_benign_maintenance.pdf"
    benign_pdf.write_bytes(
        render_text_pdf(
            [
                "IT Change Notice - Routine Patch Window",
                "Scheduled Linux kernel security updates on non-production runners.",
                "Window: Sunday 02:00 - 04:00 UTC. No external indicators or threats.",
                "Contact: infrastructure-ops@example.com for scheduling questions.",
            ]
        )
    )

    return [
        {
            "id": "png_phishing_lure",
            "modality": "image/png",
            "source": phish_png,
            "context": {
                "email_subject": "Action Required: Verify SSO",
                "spf_dkim": "fail",
            },
            "expected_actionable": True,
        },
        {
            "id": "png_clean_dashboard",
            "modality": "image/png",
            "source": clean_png,
            "context": {"source": "internal_status_monitor"},
            "expected_actionable": False,
        },
        {
            "id": "pdf_threat_advisory",
            "modality": "application/pdf",
            "source": threat_pdf,
            "context": {"feed": "isac_advisory", "tlp": "AMBER"},
            "expected_actionable": True,
        },
        {
            "id": "pdf_benign_maintenance",
            "modality": "application/pdf",
            "source": benign_pdf,
            "context": {"feed": "internal_change_calendar"},
            "expected_actionable": False,
        },
        {
            "id": "text_osint_c2",
            "modality": "text/plain",
            "source": (
                "OSINT threat report: Ransomware affiliate exploiting edge VPN "
                "appliances to deploy Sliver C2 implants beaconing to 203.0.113.88 "
                "and exfiltrating LSASS dumps."
            ),
            "context": {"feed": "osint_rss"},
            "expected_actionable": True,
        },
        {
            "id": "text_benign_release_note",
            "modality": "text/plain",
            "source": (
                "Quarterly SDK release notes: added pagination support and "
                "updated documentation examples for Python 3.12."
            ),
            "context": {"feed": "vendor_changelog"},
            "expected_actionable": False,
        },
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-json",
        type=Path,
        default=RESULTS_PATH,
        help="Path to write structured workflow results JSON.",
    )
    args = parser.parse_args()

    api_key = _resolve_gemini_api_key()
    if not api_key:
        print(
            "GEMINI_API_KEY not found in env or Secret Manager.",
            file=sys.stderr,
        )
        return 1

    artifacts = build_artifacts(RESULTS_DIR / "artifacts")
    records: list[dict[str, Any]] = []
    latencies: list[float] = []
    total_input_tokens = 0
    total_output_tokens = 0
    correct = 0

    for item in artifacts:
        t0 = time.perf_counter()
        res = triage_multimodal_security_artifact(
            item["source"],
            mime_type=item["modality"],
            context=item["context"],
        )
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        latencies.append(latency_ms)

        usage = res.get("usage") or {}
        total_input_tokens += int(usage.get("total_input_tokens") or 0)
        total_output_tokens += int(usage.get("total_output_tokens") or 0)

        predicted = res.get("is_actionable_threat")
        matched = predicted == item["expected_actionable"] and "error" not in res
        if matched:
            correct += 1

        records.append(
            {
                "id": item["id"],
                "modality": item["modality"],
                "expected_actionable": item["expected_actionable"],
                "predicted_actionable": predicted,
                "matched": matched,
                "is_actionable_threat_probability": res.get(
                    "is_actionable_threat_probability"
                ),
                "threat_category": res.get("threat_category"),
                "severity": res.get("severity"),
                "requires_immediate_hunt": res.get("requires_immediate_hunt"),
                "confidence": res.get("confidence"),
                "recommended_route": res.get("recommended_route"),
                "latency_ms": latency_ms,
                "usage": usage,
                "error": res.get("error"),
            }
        )

    summary = {
        "workflow": "workflow4_multimodal_cti_ingress",
        "model": "gemini-decision-1",
        "total_cases": len(records),
        "accuracy": round(correct / len(records), 4) if records else 0.0,
        "correct": correct,
        "mean_latency_ms": (round(statistics.mean(latencies), 2) if latencies else 0.0),
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "records": records,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
