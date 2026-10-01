# glyph-grift.md — how CVE-2026-86950 maps onto expmon-apple

Source chain (public, calif.io "The Great Glyph Grift", Sept 2026; quoted by
@odinshell, wished-for-tool tweet by @haifeili):

```
WhatsApp → QuickLook ext → PDFKit → PaperKit → PDFKit → CoreGraphics
                                                      aa_cache_render
```

Root cause: a unit-conversion bug (compiler-introduced fixed-point error) in
the CoreGraphics glyph rasterizer. `aa_cache_render` sizes its coverage buffer
from the glyph path bounding box as `width_px = (bbox_max_x − bbox_min_x) / 4096`;
a corrupted bbox range ⇒ out-of-bounds write, reachable from a crafted PDF with
a specially crafted font — on macOS *and* iOS, via thumbnail/rasterize paths
(QuickLook, sips).

## Detection surface (agent → rules)

| chain leg | where we watch | signal |
| --- | --- | --- |
| delivery: attachment thumbnail | `QLThumbnailGenerator generateBestRepresentation*` (ObjC) | `quicklook-render` (low tag) |
| document data in flight | `PDFDocument -initWithData:` / `-initWithURL:`, PaperKit `*Data*` selectors | `pdf-opened`, `paperkit-data` (low) |
| PDF → font boundary | `CGFontCreateWithDataProvider`, `CTFontCreateWithGraphicsFont` while PDF context recent | `pdf-embedded-font` (medium) |
| glyph path construction | `CTFontCreatePathForGlyph` (per-thread marker) | context only |
| **the fingerprint** | `CGPathGetBoundingBox` returned range ⇒ `w/4096` px | `glyph-path-anomaly` (high, context-escalated) |
| sink reachability | `aa_cache_render` if exported on the build; else reported in capability event | `aa-cache-render-hit` |
| chain assembly (host) | quicklook/pdf context tags + anomaly within 120 s | `glyph-grift-chain` (critical) |

The bbox rule mirrors the bug's shape rather than any specific CVE: *any*
font-parsing corruption that shows up as a nonsense glyph-path bounding box in
a document-delivery context lands here — which is the EXPMON point: detect
the exploit *behavior*, survive zero-day subclasses.

## Honest notes

- `aa_cache_render` is a local (non-exported) symbol in CoreGraphics on the
  builds we could check; the agent watches the *exported* APIs around the
  published backtrace (`CGGlyphBitmapCreateWithPathAndDilation` frame #1
  equivalent) and says so in the capability report rather than pretending.
- `CGPathGetBoundingBox` fires for all paths (not only glyph paths) — hence
  the `in_glyph_path` correlation and context-escalation rather than one
  blanket high-severity per path.
- Rule thresholds (1024 px cap, 120 s windows, weights) are first-pass
  calibration: qualify on real Mac/iOS traffic before trusting silence.
