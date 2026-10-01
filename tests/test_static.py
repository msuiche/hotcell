"""Static-stage (elegant-bouncer) integration tests — no real bouncer needed;
a stub binary stands in for the subprocess contract."""
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hotcell import static as static_mod          # noqa: E402
from hotcell.events import RuleEngine, Signal      # noqa: E402
from hotcell.report import render_markdown        # noqa: E402

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "rules", "default.yaml")

STUB_OUT = """[+] Scanning directory: /tmp/samples
[1] Scanning: /tmp/samples/malicious.webp
  └─ THREAT found: BLASTPASS
[2] Scanning: /tmp/samples/report.pdf
  └─ THREAT found: FORCEDENTRY
[+] Scanned 2 files
"""


def engine():
    return RuleEngine.load_yaml(RULES)


class _StubBouncerMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        stub = os.path.join(self.tmp.name, "fakebouncer")
        with open(stub, "w") as fh:
            fh.write("#!/bin/sh\ncat <<'EOT'\n" + STUB_OUT + "EOT\n")
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        self._old = os.environ.get(static_mod.BOUNCER_ENV)
        os.environ[static_mod.BOUNCER_ENV] = stub

    def tearDown(self):
        if self._old is None:
            os.environ.pop(static_mod.BOUNCER_ENV, None)
        else:
            os.environ[static_mod.BOUNCER_ENV] = self._old
        self.tmp.cleanup()


class TestStaticAdapter(_StubBouncerMixin):
    def test_parse_threat_lines_and_cves(self):
        res = static_mod.scan_file("anything.pdf")
        self.assertTrue(res["available"])
        names = [t["name"] for t in res["threats"]]
        self.assertEqual(names, ["BLASTPASS", "FORCEDENTRY"])
        by_name = {t["name"]: t["cves"] for t in res["threats"]}
        self.assertEqual(by_name["BLASTPASS"], ["CVE-2023-4863", "CVE-2023-41064"])
        self.assertEqual(by_name["FORCEDENTRY"], ["CVE-2021-30860"])

    def test_unavailable_binary_is_graceful(self):
        old = os.environ.pop(static_mod.BOUNCER_ENV, None)
        try:
            os.environ["PATH"] = ""     # nothing findable
            res = static_mod.scan_file("x.pdf")
            self.assertFalse(res["available"])
            self.assertIn("HOTCELL_BOUNCER", res["error"])
            self.assertEqual(res["threats"], [])
        finally:
            if old is not None:
                os.environ[static_mod.BOUNCER_ENV] = old


class TestStaticRuntimeAgreement(unittest.TestCase):
    def test_static_plus_glyph_anomaly_is_exploit_likely(self):
        e = engine()
        e.process(Signal("bouncer-static-hit", "high",
                         {"threat": "TRIANGULATION", "cves": ["CVE-2023-41990"],
                          "stage": "static"}, {}, ts=0.0))
        e.process(Signal("glyph-path-anomaly", "high", {"width_px": 1490},
                         {"quicklook_recent": True}, ts=1.0))
        v = e.verdict()
        self.assertEqual(v.label, "exploit-likely")
        self.assertTrue(any(c.chain == "static-runtime-agreement" for c in v.chains))

    def test_static_plus_image_bomb_is_exploit_likely(self):
        e = engine()
        e.process(Signal("bouncer-static-hit", "high",
                         {"threat": "BLASTPASS", "cves": ["CVE-2023-4863"],
                          "stage": "static"}, {}, ts=0.0))
        e.process(Signal("image-bomb", "medium", {"width": 30000, "height": 30000}, {}, ts=1.0))
        v = e.verdict()
        self.assertEqual(v.label, "exploit-likely")
        self.assertTrue(any(c.chain == "static-image-agreement" for c in v.chains))

    def test_static_hit_alone_is_investigate(self):
        e = engine()
        e.process(Signal("bouncer-static-hit", "high",
                         {"threat": "BLASTPASS", "cves": ["CVE-2023-4863"]}, {}, ts=0.0))
        self.assertEqual(e.verdict().label, "investigate")


class TestScanStaticOnlyE2E(_StubBouncerMixin):
    def test_cli_scan_static_only(self):
        from hotcell.cli import main
        with tempfile.TemporaryDirectory() as out:
            target = os.path.join(self.tmp.name, "suspicious.webp")
            open(target, "w").write("stub")
            rc = main(["scan", "--file", target, "--static-only", "--out", out])
            self.assertEqual(rc, 0)
            reports = [f for f in os.listdir(out) if f.endswith(".md")]
            self.assertEqual(len(reports), 1)
            md = open(os.path.join(out, reports[0])).read()
            self.assertIn("INVESTIGATE", md)          # single static hit = 45
            self.assertIn("THREAT: **BLASTPASS**", md)
            self.assertIn("THREAT: **FORCEDENTRY**", md)
            self.assertIn("static stage (elegant-bouncer)", md)

    def test_no_static_flag_skips_stage(self):
        from hotcell.cli import main
        with tempfile.TemporaryDirectory() as out:
            target = os.path.join(self.tmp.name, "x.pdf")
            open(target, "w").write("stub")
            rc = main(["scan", "--file", target, "--static-only", "--no-static", "--out", out])
            self.assertEqual(rc, 0)
            md = open(os.path.join(out, [f for f in os.listdir(out) if f.endswith(".md")][0])).read()
            self.assertIn("skipped (--no-static)", md)


class TestMarkdownStaticSection(unittest.TestCase):
    def test_render_includes_static_block(self):
        e = engine()
        e.process(Signal("bouncer-static-hit", "high",
                         {"threat": "BLASTPASS", "cves": ["CVE-2023-4863"]}, {}, ts=0.0))
        md = render_markdown(e.session_dict({
            "session": "unit", "target": "x.webp",
            "static": {"available": True, "threats": [
                {"name": "BLASTPASS", "cves": ["CVE-2023-4863"]}]}}))
        self.assertIn("static stage (elegant-bouncer)", md)
        self.assertIn("BLASTPASS", md)


if __name__ == "__main__":
    unittest.main()
