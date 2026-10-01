# hotcell — runtime exploit monitor for Apple document/image pipelines

An iOS/macOS implementation of the EXPMON concept (runtime, agent-based exploit
detection for file-format attack surfaces, no sandbox). Prompted by
[@haifeili](https://x.com/haifeili/status/2105522676265816078): *"I wish someone
could build an iOS/MacOS version of @EXPMON_, for the good."*

It watches the exact pipeline Apple ships for untrusted documents —

```
WhatsApp / Mail / Files → QuickLook ext → PDFKit → PaperKit → PDFKit
                        → CoreGraphics (aa_cache_render via glyph rasterization)
                        ← reachable from a crafted PDF/font through the
                          ImageIO / thumbnail path (QuickLook, sips)
```

— and flags **exploit behavior**, not file signatures. First validated target:
the Great Glyph Grift chain (CVE-2026-86950, CoreGraphics `aa_cache_render`
fixed-point bbox corruption, reachable from a PDF-embedded font).

## Design (EXPMON philosophy)

- **In-process Frida agent** — hooks the *real* renderer/processor processes
  (QuickLook extension, `qlmanage`, `sips`, WhatsApp, Mail, Preview, …), not an
  emulation. What is measured is what actually runs.
- **Behavioral rules over signatures** — the agent emits tagged signals
  (cross-format data flow, absurd glyph bounding boxes, oversized allocations,
  RWX transitions); the host correlates them into verdicts.
- **Fail-open, noise-aware** — every hook is guarded; capability report at
  attach tells you exactly what could and could not be instrumented.

## Layout

```
agent/hotcell_agent.js  Frida agent (macOS + iOS; same script, both platforms)
hotcell/                host CLI (attach/spawn, event pipeline, scoring, report)
  static.py             optional static stage: elegant-bouncer subprocess adapter
rules/default.yaml      signal → severity/verdict rule pack (editable)
docs/glyph-grift.md     how CVE-2026-86950 maps onto hooks/rules
docs/coverage.md        hook matrix vs. the EXPMON (Windows) concept
tests/                  pipeline tests (run anywhere; frida optional via mocks)
```

## Two-stage scanning with ELEGANTBOUNCER

hotcell (runtime behavior) and [elegant-bouncer](https://github.com/msuiche/elegant-bouncer)
(static structure) are complementary layers over the same threat class:

- **elegant-bouncer** — what the *file* is: structural detection of known
  mobile exploit shapes (FORCEDENTRY, BLASTPASS, TRIANGULATION, DNG/libheif
  CVEs). No execution required; also scans iOS backups / messaging DBs.
- **hotcell** — what the *process does* with the file: in-process behavioral
  signals, zero-day subclasses, delivered exactly on Apple's own pipeline.

`hotcell scan --file F` fuses both. If `elegantbouncer` is on `PATH` (or
`HOTCELL_BOUNCER` points at it), stage 1 runs the static scan and its
findings fold into the same rule engine (`bouncer-static-hit`); agreement
chains fire when static + runtime signals corroborate. No binary → static
stage is skipped and reported honestly in the session. `--static-only`
scans without frida; `--no-static` forces runtime-only.

Static hits alone score `investigate`; static hit + runtime anomaly scores
`exploit-likely`. An upstream `--json` output flag for elegant-bouncer would
make the adapter contract even tighter (currently parses `THREAT found:` lines).

## Usage (macOS)

```bash
# headless scan of one file through Apple's own thumbnail pipeline
hotcell scan --file sketchy.pdf --out report/

# attach to a live app and watch
hotcell watch --target WhatsApp --minutes 30

# enumerate candidate renderer processes
hotcell list

# iOS: same agent over USB (jailbroken + frida-server, or gadget-repackaged app)
hotcell watch --device usb --target WhatsApp
```

`scan` spawns `qlmanage -t` under the agent: the file travels the exact
QuickLook → PDFKit/ImageIO → CoreGraphics path the in-the-wild chain used.
`--spawn file` and `--target NAME` attach before resume, so nothing is missed.

## Verdicts

| verdict | meaning |
| --- | --- |
| `exploit-likely` | critical/high signals + a confirmed cross-boundary chain in-window |
| `investigate` | high signal(s), uncorroborated |
| `log` | informational (document opened, oversized image, …) |

Signals carry a short stack, rule id, and structured detail; reports are JSON +
markdown. Rule packs are YAML — new zero-day behavior = new rule, no code.

## Honest limits

- Hook resolution is best-effort per OS build; `aa_cache_render` is not an
  exported symbol — the agent watches the exported rasterization entrypoints
  (`CGPathGetBoundingBox`, glyph draw APIs, `CGContextDrawPDFPage`) that sit on
  the published backtrace and reports any sink it cannot resolve in the
  capability event. Pattern-scan sink resolution is a roadmap item.
- Developed on Linux; pipeline logic is unit-tested with mock sessions, but the
  Apple-framework hooks need a real macOS/iOS host to verify end-to-end. Treat
  first-run results as qualification runs, exactly like EXPMON's own rule packs.
- Detection is behavioral: no signature mode, zero-day *behavior* only.
- Defensive tool. It monitors your own devices' own processes.

## Status

Working: agent JS (hooks + signal emission), host CLI, rule engine, scan/watch
modes, reports, tests. See `docs/coverage.md` for the verified/pending matrix.
