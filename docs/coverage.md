# coverage.md — hook matrix and verification status

EXPMON (Windows, Haifei Li) was a Frida-based in-process monitor detecting
file-based zero-day exploit *behavior* in browsers and document readers.
This is the Apple-platform implementation of that concept.

## Hooks (agent/hotcell_agent.js)

| area | hook | platforms | verified on-device |
| --- | --- | --- | --- |
| PDFKit | `PDFDocument -initWithData:`, `-initWithURL:` | macOS, iOS | pending (needs a Mac/iOS host) |
| PaperKit | all `*data*`/`*Data*` selectors of `PaperDocument` | macOS | pending |
| QuickLook | `QLThumbnailGenerator generateBestRepresentation*` | macOS, iOS | pending |
| ImageIO | `CGImageSourceCreateImageAtIndex` (+100MP image-bomb), `CGImageSourceCreateThumbnailAtIndex` (tag) | macOS, iOS | pending |
| CoreGraphics | `CGPathGetBoundingBox` (glyph-anomaly), `CGContextDrawPDFPage` (tag), `CGFontCreateWithDataProvider` (crossing) | macOS, iOS | pending |
| CoreText | `CTFontCreatePathForGlyph` (per-thread glyph context), `CTFontCreateWithGraphicsFont` | macOS, iOS | pending |
| sink | `aa_cache_render` — resolved only if exported; else honestly missing | macOS | resolved=null on checked builds |
| primitives | `mmap` ≥128MB anon, `mprotect` → RWX | macOS, iOS | pending |

Symbol resolution is guarded (`Module.findExportByName`, try/catch per hook):
a build that moved a symbol degrades that hook to `capability.missing`, never
to a crash.

## Verified *here* (build host, Linux)

- agent JS syntax (node --check) — yes
- pipeline: rule matching, escalation, chains, dedupe, verdicts — yes (unit
  tests, including the glyph-grift replay)
- report render (markdown/JSON), CLI arg surface — yes (tests + `--help`)
- frida imports: lazy — pipeline runs without frida installed

## To qualify on device (macOS first)

1. `pip install -e ".[live]"` on the Mac; `hotcell list`
2. `hotcell scan --file docs/poc.pdf` (any PDF) → confirm `quicklook-render`
   fires on the qlmanage run and the capability event lists the expected hooks
3. `hotcell watch --target Preview` while opening a big PDF → `pdf-opened`
4. Sanity: verify no false `glyph-path-anomaly` on normal document browsing;
   calibrate `GLYPH_BBOX_MAX_PX` if normal oversized glyph art trips it
5. iOS: jailbroken device with frida-server → `--device usb`; non-jailbroken →
   repackage target app with FridaGadget loading this agent script

## Roadmap

- pattern-scan resolution for local symbols (aa_cache_render) with integrity
  bounds (module range + prologue fingerprint), reported as untrusted if loose
- per-rule YAML versioning + rule-pack signing
- Safari web content (JSC) rules — EXPMON's browser coverage, Apple edition
- sysextenable host (notification-only, no TCC prompts on monitor reads)
