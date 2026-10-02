# hotcell — runtime monitor for Apple document/image pipelines

hotcell instruments real Apple rendering APIs with Frida and correlates observed
behavior with optional static findings from
[elegant-bouncer](https://github.com/msuiche/elegant-bouncer).
It is an experimental defensive monitor, inspired by EXPMON. A quiet session is
not proof that a file is safe, and the glyph rules have not been validated against
an in-the-wild exploit corpus.

Version 0.3 is a Rust application: CLI, Frida lifecycle, native Apple renderer,
static adapter, correlation, and reporting. The Frida JavaScript agent and YAML
rules are embedded in the executable. Python is not required.

## Build and install

Use Rust 1.88 or newer. macOS builds require Apple's Command Line Tools
(`xcode-select --install`), including Clang/libclang for generating Frida bindings.

```bash
cargo build --release --locked
./target/release/hotcell --version

# Install from this checkout.
cargo install --path . --locked
```

The first build downloads the pinned Frida 17.19.0 native devkit. A small local
copy of the Rust bindings selects this qualified version; see
[vendor/frida-sys](vendor/frida-sys/README.md). Runtime scans use a subprocess of
the same executable calling CoreGraphics/ImageIO directly. No compiler, Python,
separate agent file, or separately installed Frida is needed on the scanning host.

For static scanning and report replay without the Frida dependency:

```bash
cargo build --release --locked --no-default-features
```

## Usage

```bash
# Scan every PDF page or image frame in one monitored process.
hotcell scan --file document.pdf --out report/

# Static only; requires elegantbouncer on PATH or HOTCELL_BOUNCER pointing at it.
hotcell scan --file document.pdf --static-only --out report/

# Runtime only.
hotcell scan --file image.png --no-static --minutes 1 --out report/

# Enumerate candidate processes, then attach by name or PID.
hotcell list
hotcell watch --target Preview --minutes 5
hotcell watch --target 12345 --target 12346 --minutes 5

# iOS monitoring requires an accessible Frida device/process.
hotcell watch --device usb --target WhatsApp

# Replay raw observations with the embedded or another rule pack.
hotcell report --session report/SESSION.session.json --out replay/
hotcell report --session report/SESSION.session.json --rules custom.yaml
```

`scan` loads and verifies the agent before resuming the renderer, records actual
rendering calls, and requires an acknowledged completion handshake. It writes a
PNG preview of the first page/frame. Runtime file scans require macOS.

This does **not** reproduce the QuickLook/PDFKit/PaperKit delivery chain:
system `qlmanage` can reject injection, and QuickLook can render in separate
services. `watch` monitors only the attached processes; it does not automatically
follow XPC services or children. macOS may refuse attachment to protected
applications; the report records that failure.

## Results

Each run writes a JSON session and Markdown report. JSON contains raw signals,
process identity, timestamps in seconds, context, capabilities, errors, and
verdicts. Reports with raw signals from Python v0.2 remain replayable. Legacy
reports without raw signals are rejected because their verdict cannot be
faithfully recalculated. Replay also rejects missing or malformed timestamps and
unsupported timestamp units; it never substitutes the current time for saved
observations.

| Verdict | Meaning |
| --- | --- |
| `log` | No score threshold reached; does not mean safe |
| `investigate` | Score at least 35 without a sufficiently weighted matched chain |
| `exploit-likely` | Score at least 100 with a matched rule chain; a heuristic, not proof |

Scan status is separate from the verdict. Missing hooks are listed. Agent failures,
render timeouts, malformed/unsupported inputs, and static-scanner errors produce
`incomplete` and exit status **2**. A completed run exits **0**, including runs with
findings; consumers should inspect the report's verdict. A missing optional static
scanner is disclosed and runtime scanning continues; `--static-only` requires it.
You cannot combine `--static-only` and `--no-static`.

Static results parse ELEGANTBOUNCER's single-file summary table and legacy threat
lines. Startup failures, nonzero exits, timeouts, and unrecognized output are
incomplete. Setting `HOTCELL_BOUNCER` makes the static stage required: a missing
or unusable configured scanner marks the scan incomplete even if rendering
succeeds. Without that override, an absent scanner is reported as unavailable
and runtime scanning can still complete. `--no-static` explicitly skips it.
Static findings remain available when runtime scanning fails.

## Detection and limits

- PDF opens/renders, ImageIO decoding, PDF-associated font ingestion, large
  successful anonymous mappings, and successful RWX permission changes.
- Glyph bounds are queried from the final `CTFontCreatePathForGlyph` result,
  using a native struct-return signature. Bounds are in user-space units; the
  public API does not expose the rasterizer's internal fixed-point bounds.
- Non-finite/negative or very large glyph bounds are heuristics. Large legitimate
  type can trigger the size rule; its 1024-unit threshold needs corpus calibration.
- The internal `aa_cache_render` sink is reported missing when not exported.
  Rendering paths that do not call these exported APIs can evade these rules.
- Rule chains and deduplication separate process identities. A scan's static
  findings can corroborate its runtime observations.
- This executes untrusted files in native Apple parsers. It is not a sandbox.

## Layout and verification

```text
src/                    Rust CLI, lifecycle, Apple renderer, rules and reporting
assets/hotcell_agent.js  embedded Frida instrumentation
assets/default.yaml     embedded default rules (override with --rules)
vendor/frida-sys/        bindings pinned to the qualified native devkit
tests/                  Rust regression, CLI, and opt-in native tests
docs/coverage.md         verified coverage and remaining limits
```

```bash
cargo test --locked
cargo test --locked --no-default-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings

# macOS tests that instrument only their own benign processes.
cargo test --locked -- --ignored --test-threads=1
```

Native tests compile a small Objective-C test probe, inject the real embedded
agent, scan benign PDF/PNG fixtures, check malformed inputs, compare native and
observed glyph bounds, exercise 64-bit mapping lengths, and replay reports.
Oversized glyphs are controlled test signals, not real exploits.
