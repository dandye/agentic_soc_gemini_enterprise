# Style Guide: Gemini Decision 1 Interactive Security Demos

Every demo tab teaches one security guard in under 30 seconds using a pixel-locked Option 1 layout across all three tabs: **vertical stacks separate contrasting examples or stages**, and **horizontal columns compare `Without Decision 1` (red, middle) against `With Decision 1` (green, right)**.

## 1. Fixed Four-Band Page Shell

Switching between Tab 1, Tab 2, and Tab 3 must never shift the top four bands vertically or move the primary action buttons.

1. **Header Bar:** Page title (`24px` bold), subtitle (`14px` muted), right-aligned green `LIVE: gemini-decision-1` pill.
2. **Tab Bar:** Three equal-style tab buttons (`1. Fake Note in the Log`, `2. Phishing Screenshot Inbox`, `3. Check Twice Before Pulling the Plug`).
3. **Story Banner:** Exactly one plain-English sentence explaining the operational risk and what Decision 1 prevents, framed with a `4px` blue left accent border.
4. **Standalone Action Bar:** Always a dedicated single-row card (`height: 62px`) directly beneath the Story Banner on every tab:
   - Primary blue CTA following `<Verb> <Object> with Decision 1`:
     - Tab 1: `Scan Logs with Decision 1`
     - Tab 2: `Score Inbox with Decision 1`
     - Tab 3: `Check Server with Decision 1`
   - Secondary dark CTA verbatim on every tab: `Copy Prompt for Gemini Enterprise Chat`
   - Optional utility CTA (Tab 2 only): `Upload PNG / JPG / PDF`
   - Right-aligned one-line muted helper text (`13px`).

## 2. Two-Row Three-Column Matrix (`320px | 1fr | 1fr`)

Every tab contrasts two examples or sequential stages stacked vertically (Row 1 = benign or uncertain; Row 2 = malicious or confirmed attack) inside the exact same `320px 1fr 1fr` grid:

- **Tab 1 (`Fake Note in the Log`):** `1. Normal Admin Log` (clean `winget` update) above `2. Injected PowerShell Log` (editable PowerShell alert hiding a fake IT ignore note).
- **Tab 2 (`Phishing Screenshot Inbox`):** `1. IT Maintenance Notice` (routine weekend patching notice) above `2. Fake Corporate Login Page` (SSO credential lure).
- **Tab 3 (`Check Twice Before Pulling the Plug`):** `1. 24-Hour Logs (1 event)` (single ambiguous `/healthz` ping) above `2. 7-Day Logs (3 events)` (hidden C2 beacon and `/etc/shadow` staging).

### Non-Duplicated Column Headers

Print the column header row once above the two-row stack on each tab (`ENDPOINT LOG` / `INBOX SCREENSHOT` / `CHRONICLE LOG WINDOW`, `WITHOUT DECISION 1` in red, `WITH DECISION 1` in green). Never repeat `Without Decision 1` or `With Decision 1` inside individual cards.

## 3. Unified Card Anatomy

### Left Artifact Card (`320px` fixed width)

1. **Top Title Row:** Blue numbered circle (`1` or `2`), bold title (`14.5px`), and optional blue `Editable` tag (Tab 1).
2. **Middle Artifact Frame (`height: 142px`, `#090d14` background):** Monospace editable textarea (Tab 1), uncropped `object-fit: contain` image (Tab 2), or read-only Chronicle log snippet (Tab 3). Never use `object-fit: cover`.
3. **Bottom Caption:** Single muted line (`12.5px`) summarizing the artifact.

### Comparison Cards (`Without Decision 1` and `With Decision 1`)

Both comparison cards share the exact same three-slot rhythm so badges, text, and footer pills align horizontally across columns before and after clicking Run:

1. **Slot 1 (Matched Top Row):**
   - Left: Verdict Pill (always on line 1 left, both pre-run and post-run).
   - Right: Monospace latency tag (`~3,000 ms LLM` on `Without Decision 1`; `Idle` pre-run -> `Live <ms> ms` with one decimal place on `With Decision 1`).
2. **Slot 2 (Signal and Evidence Body):**
   - `Without Decision 1`: One concise failure explanation (plus compact raw note excerpt on Tab 1).
   - `With Decision 1`: `10px` calibrated meter bar (`Math.max(score_pct, 4)%` width when live, `0%` pre-run), uniform telemetry line (`Threat Score: <N>% | Confidence: <M>%`), and concise action note or sanitized monospace preview.
3. **Slot 3 (Bottom Outcome Pills):**
   - `Without Decision 1`: 2 red impact pills (`ev-pill-danger`).
   - `With Decision 1`: 2-3 green outcome pills (`ev-pill`), always beginning with `0 Output Tokens`.

### Pre-Run State Rule (Visible Ready State)

Render both stacked rows immediately on tab load with a teal `Ready to Score` pill in Slot 1 left and `Idle` in Slot 1 right inside every `With Decision 1` card. Clicking the primary button updates results in place with zero layout shift and zero badge jump.

## 4. Theme and Semantic Color Tokens

Dark mode canvas (`#0b0f17`), `max-width: 1280px` container.

| Token | Hex | Semantic Role | Strict Boundary |
| --- | --- | --- | --- |
| `--bg` | `#0b0f17` | Page canvas | Never use light outer chrome |
| `--card` | `#131a26` | Band containers and row wrappers | `1px solid #263145`, `12px` radius |
| `--card-2` | `#0f1520` | Artifact tiles and comparison cards | `1.5px solid` border, `10px` radius |
| `--code-bg` | `#090d14` | Monospace boxes, meter tracks, image letterbox | Neutral dark inset |
| `--border` | `#263145` | Default structural dividers | Neutral dividers only |
| `--blue` | `#58a6ff` | Primary CTA, active tab, story left bar, numbered circles, editable outline | Never used for threat verdicts |
| `--red` | `#ff7b72` | `Without Decision 1` header/border/pills; malicious (`>= 80%`) verdict pill and meter bar inside `With Decision 1`; redacted strikethrough | Never color the outer `With Decision 1` card border red |
| `--green` | `#3fb950` | `With Decision 1` header/border/timing/outcome pills (always); safe (`< 25%`) verdict pill and meter bar | Never pair a green verdict pill with a red meter bar |
| `--amber` | `#e3b341` | Uncertain / hold-off verdict pill and meter bar inside `With Decision 1` | Intermediate hold-off states only |
| `--teal` | `#39c5cf` | Pre-run `Ready to Score` pill inside `With Decision 1` | Pre-run state only |

**Verdict-to-Meter Parity Rule:** Inside `With Decision 1`, the verdict pill color always matches the meter bar fill color (green for safe, amber for hold-off, red for confirmed threats), while the outer border, live latency tag, and bottom outcome pills remain green.

## 5. Viewport Budget, Copywriting, and Verification

- **1920x1080 single-screen budget:** Every complete active tab must render within `<= 960px` total height at `1920x1080` so live screen-sharing and documentation screenshots fit with zero vertical scrolling.
- **Concurrent execution:** All multi-row API routes (`/api/demo1`, `/api/demo2`, `/api/demo3`) run independent Decision 1 calls concurrently (`asyncio.gather`) so both rows resolve together in sub-second wall time.
- **Plain English and hygiene:** Translate internal enums (`FORCE_PROBE_MORE`, `AUTO_ISOLATE_CONTAIN`, `archive_no_llm`) into plain operational labels. Never include emojis, em-dashes, or internal shortlink patterns. Always write **YARA-L 2.0** when referencing Chronicle SIEM detection rules.
- **Verification gates:** Every change must pass `tests/test_simple_demos.py`, `pyink --check`, `ruff check`, `sphinx-build -W`, `pre-commit run --all-files`, `scripts/check_public_repo_hygiene.py`, and live `1920x1080` Playwright visual inspection with `fallback: False`.
