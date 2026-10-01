"""hotcell CLI.

    hotcell list                    enumerate target renderer processes
    hotcell watch --target NAME     attach + watch live processes
    hotcell scan  --file F          two-stage file scan: static (elegant-bouncer,
                                    if available) + runtime (QuickLook under agent)
    hotcell report --session F      rebuild a verdict from a saved session.json
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__
from . import static as static_mod
from .events import RuleEngine, Signal
from .session import Monitor
from . import report as report_mod

DEFAULT_RULES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "default.yaml")


def _engine(args) -> RuleEngine:
    return RuleEngine.load_yaml(args.rules)


def _finish(engine: RuleEngine, stem_meta: dict, args) -> int:
    """Write the session report, print verdict + chains, optionally notify."""
    session = engine.session_dict({
        **stem_meta,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ended": time.strftime("%Y-%m-%d %H:%M:%S"),
        "signals": len(engine.signals),
    })
    v = engine.verdict()
    paths = report_mod.write_report(session, args.out, stem=stem_meta["session"])
    print(f"[*] verdict: {v.label.upper()} (score {v.score})")
    for c in v.chains:
        print(f"    chain: {c.chain} (+{c.weight}) — {c.description}")
    print(f"[*] report: {paths['markdown']}")
    if getattr(args, "notify", False):
        report_mod.notify_macos(f"hotcell: {v.label}", f"score {v.score} — {stem_meta['target']}")
    return 0


def _run_and_report(monitor, engine, sessions, args, stem_meta) -> int:
    events_out = {"capability": {}, "signals": []}

    def on_event(payload):
        ptype = payload.get("type")
        if ptype == "capability":
            events_out["capability"] = payload
            engine.record_capability(payload)
        elif ptype == "signal":
            m = engine.process(Signal.from_payload(payload))
            events_out["signals"].append(payload)
            if m:
                print(f"  [signal] {m.signal.rule} (+{m.weight}) — {m.reason}")
        elif ptype == "error":
            print(f"  [agent-error] {payload.get('detail', {}).get('description', '')}",
                  file=sys.stderr)

    monitor.on_event = on_event
    print(f"[*] monitoring for {args.minutes} min — Ctrl-C to stop early")
    try:
        end = time.time() + args.minutes * 60
        while time.time() < end:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("[*] interrupted")
    for s in sessions:
        s.close()
    return _finish(engine, stem_meta, args)


def _run_static_stage(engine: RuleEngine, file_path: str, args) -> dict:
    """Stage 1 of scan: static structural detection via elegant-bouncer."""
    if getattr(args, "no_static", False):
        return {"available": False, "threats": [], "skipped": True}
    static = static_mod.scan_file(file_path)
    for t in static.get("threats", []):
        engine.process(Signal("bouncer-static-hit", "high",
                              {"threat": t["name"], "cves": t["cves"], "stage": "static"},
                              {}, ts=time.time()))
        print(f"  [static] THREAT found: {t['name']} ({', '.join(t['cves']) or 'n/a'})")
    if not static["available"]:
        print(f"[*] static stage: unavailable — {static.get('error', '')} (runtime-only session)")
    elif static["threats"]:
        print("[*] static stage: threats found — dynamic stage will confirm behavior")
    else:
        print("[*] static stage: clean (no known exploit shapes)")
    return static


def cmd_list(args) -> int:
    m = Monitor(args.device)
    try:
        procs = m.list_processes()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"{'PID':>7}  {'NAME':38} TARGET")
    for p in procs:
        if p["target"]:
            print(f"{p['pid']:>7}  {p['name'][:38]:38} ★")
    others = sum(1 for p in procs if not p["target"])
    print(f"({len(procs)} processes total, {others} not document-related; hidden)")
    return 0


def cmd_watch(args) -> int:
    engine = _engine(args)
    monitor = Monitor(args.device)
    sessions = []
    try:
        for t in args.target:
            print(f"[*] attaching to {t!r}…")
            sessions.append(monitor.attach(t))
    except (RuntimeError, Exception) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return _run_and_report(monitor, engine, sessions, args,
                           {"session": f"watch-{report_mod.now()}",
                            "target": ",".join(args.target), "pid": "-", "device": args.device})


def cmd_scan(args) -> int:
    """Two-stage file scan:
    stage 1 static (elegant-bouncer, optional binary), stage 2 runtime
    (file travels Apple's own QuickLook thumbnail pipeline under the agent)."""
    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return 2
    engine = _engine(args)
    stem_meta = {"session": f"scan-{report_mod.now()}",
                 "target": f"scan:{os.path.basename(args.file)}",
                 "pid": "-", "device": args.device}

    stem_meta["static"] = _run_static_stage(engine, args.file, args)
    if getattr(args, "static_only", False):
        return _finish(engine, stem_meta, args)

    monitor = Monitor(args.device)
    tmp = os.path.abspath(args.out)
    os.makedirs(tmp, exist_ok=True)
    try:
        s = monitor.spawn(["qlmanage", "-t", "-s", "1024", "-o", tmp, os.path.abspath(args.file)])
    except (RuntimeError, Exception) as e:
        print(f"error spawning qlmanage: {e}", file=sys.stderr)
        return 2
    return _run_and_report(monitor, engine, [s], args, stem_meta)


def cmd_report(args) -> int:
    import json
    with open(args.session, "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    engine = RuleEngine.load_yaml(args.rules)
    for sig in saved.get("signals", []):
        engine.process(Signal.from_payload(sig))
    caps = saved.get("capability") or {}
    if caps:
        engine.record_capability(caps)
    v = engine.verdict()
    rebuilt = engine.session_dict(saved.get("meta", {}))
    paths = report_mod.write_report(rebuilt, args.out, stem=f"replay-{report_mod.now()}")
    print(f"verdict: {v.label.upper()} (score {v.score}) → {paths['markdown']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hotcell",
                                 description="runtime exploit monitor for Apple document pipelines")
    ap.add_argument("--version", action="version", version=f"hotcell {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--device", default="local", choices=["local", "usb"],
                       help="local (mac) or usb (iOS) frida device")
        p.add_argument("--rules", default=DEFAULT_RULES, help="rule pack YAML")
        p.add_argument("--out", default="report", help="output dir")
        p.add_argument("--minutes", type=float, default=10, help="watch duration")
        p.add_argument("--notify", action="store_true", help="macOS notification on verdict")

    p_list = sub.add_parser("list", help="list target renderer processes")
    common(p_list)

    p_watch = sub.add_parser("watch", help="attach to a process and monitor")
    p_watch.add_argument("--target", action="append", required=True,
                         help="process name (repeatable)")
    common(p_watch)

    p_scan = sub.add_parser("scan", help="two-stage file scan (static + runtime)")
    p_scan.add_argument("--file", required=True, help="file to scan")
    p_scan.add_argument("--static-only", action="store_true",
                        help="run only the elegant-bouncer static stage (no frida needed)")
    p_scan.add_argument("--no-static", action="store_true",
                        help="skip the static stage even if elegantbouncer is installed")
    common(p_scan)

    p_rep = sub.add_parser("report", help="rebuild verdict from saved session.json")
    p_rep.add_argument("--session", required=True, help="path to *.session.json")
    common(p_rep)

    args = ap.parse_args(argv)
    return {"list": cmd_list, "watch": cmd_watch, "scan": cmd_scan,
            "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
