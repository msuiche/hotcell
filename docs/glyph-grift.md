# Glyph-path monitoring

The original project was motivated by reports of corruption in Apple's glyph
rasterizer. Its initial implementation incorrectly read `CGPathGetBoundingBox`'s
return value as a pointer and divided the result by 4096. Public CoreGraphics
path coordinates are not the rasterizer's private fixed-point coordinates.

The current agent inspects the final path returned by `CTFontCreatePathForGlyph`
with a native `CGRect` return signature. This lets Frida/libffi handle arm64's
floating-point aggregate return convention. Hook traps are disabled during the
read-only bounding-box query to avoid recursion. Intermediate font-parser paths
are not size-scored: normal design-space outlines commonly exceed 1024 units
before scaling, even for a 12-point font.

A glyph-path anomaly is emitted for non-finite/negative dimensions or dimensions
above 1024 user-space units. PDF/thumbnail context can corroborate this signal;
a static finding from the same scan can form another chain. Large legitimate
fonts can trigger this heuristic and require investigation, not an assumption
that corruption occurred.

The live test compares an emitted oversized glyph's bounding box against the
value read by a native CoreGraphics caller. It also verifies that an ordinary
glyph and an unrelated large geometric path produce no glyph anomaly.

This is exported-path coverage only. The internal `aa_cache_render` symbol is
reported missing when it cannot be resolved. No particular CVE, internal
fixed-point corruption, or complete QuickLook → PDFKit → PaperKit chain has
been verified by these tests.
