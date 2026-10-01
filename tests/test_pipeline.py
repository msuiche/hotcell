"""Pipeline tests — no frida needed; feeds a replay of the published
Great Glyph Grift signal shape through the rule engine and verdicts.
Run: python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from expmon.events import RuleEngine, Signal  # noqa: E402

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "rules", "default.yaml")


def engine():
    return RuleEngine.load_yaml(RULES)


class TestGlyphGriftReplay(unittest.TestCase):
    """Signal shape matching the CVE-2026-86950 delivery chain."""

    def test_full_chain_is_exploit_likely(self):
        e = engine()
        e.record_capability({"hooks": ["CGPathGetBoundingBox"], "missing": ["aa_cache_render"]})

        # 1. delivery channel: QuickLook renders the attachment
        e.process(Signal("quicklook-render", "low", {},
                         {"quicklook_recent": True}, ts=0.0))
        # 2. PDF data in flight
        e.process(Signal("pdf-opened", "low", {"bytes": 9 * 1024 * 1024},
                         {"pdf_open_recent": True}, ts=1.0))
        # 3. embedded font crossed into the rasterizer
        e.process(Signal("pdf-embedded-font", "medium", {},
                         {"pdf_open_recent": True, "quicklook_recent": True}, ts=2.0))
        # 4. the fingerprint: corrupted glyph path bbox (fixed-point overflow)
        e.process(Signal("glyph-path-anomaly", "high",
                         {"bbox": {"x0": 0, "y0": 0, "w": 6.1e6, "h": 4.0e6},
                          "width_px": 1490, "why": ["oversized-glyph-bbox"],
                          "in_glyph_path": True},
                         {"quicklook_recent": True, "pdf_render_recent": True}, ts=3.0))

        v = e.verdict()
        self.assertEqual(v.label, "exploit-likely")
        self.assertGreaterEqual(v.score, 100)
        self.assertTrue(any(c.chain == "glyph-grift-chain" for c in v.chains))
        self.assertTrue(any(c.chain == "font-crossing" for c in v.chains))

    def test_single_high_signal_is_investigate(self):
        e = engine()
        e.process(Signal("rwx-transition", "high", {"bytes": 4096}, {}, ts=0.0))
        v = e.verdict()
        self.assertEqual(v.label, "investigate")
        self.assertEqual(v.score, 45)

    def test_clean_session_is_log(self):
        e = engine()
        e.process(Signal("pdf-opened", "low", {"bytes": 5 * 1024 * 1024},
                         {"pdf_open_recent": True}, ts=0.0))
        e.process(Signal("quicklook-render", "low", {}, {"quicklook_recent": True}, ts=1.0))
        self.assertEqual(e.verdict().label, "log")

    def test_dedupe_collapses_identical_signals(self):
        e = engine()
        for _ in range(3):
            e.process(Signal("glyph-path-anomaly", "high", {"bbox": {"w": 6.1e6}},
                             {"quicklook_recent": True}, ts=0.5))
        self.assertEqual(len(e.matches), 1)

    def test_heap_spray_escalates_by_size(self):
        e = engine()
        e.process(Signal("big-anon-map", "medium", {"bytes": 600 * 1024 * 1024}, {}, ts=0.0))
        m = e.matches[-1]
        self.assertEqual(m.weight, 45)  # >=512MB escalates to high

    def test_unknown_rule_gets_fallback_weight(self):
        e = engine()
        m = e.process(Signal("future-agent-rule", "medium", {}, {}, ts=0.0))
        self.assertEqual(m.weight, 1)


class TestMarkdownReport(unittest.TestCase):
    def test_render_includes_verdict_and_capability(self):
        from expmon.report import render_markdown
        e = engine()
        e.record_capability({"hooks": ["CGPathGetBoundingBox"], "missing": ["aa_cache_render (not exported)"]})
        e.process(Signal("glyph-path-anomaly", "high", {"width_px": 1490},
                         {"quicklook_recent": True}, ts=0.0))
        md = render_markdown(e.session_dict({"session": "unit", "target": "WhatsApp"}))
        self.assertIn("EXPLOIT-LIKELY", md)
        self.assertIn("glyph-path-anomaly", md)
        self.assertIn("glyph-grift-chain", md)
        self.assertIn("aa_cache_render (not exported)", md)


if __name__ == "__main__":
    unittest.main()
