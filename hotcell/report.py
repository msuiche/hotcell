"""Reports: markdown verdict + optional macOS notification."""
from __future__ import annotations

import json
import os
import platform
import time
from typing import Any, Dict

VERDICT_ICON = {"exploit-likely": "!!", "investigate": "?", "log": "."}


def write_report(session: Dict[str, Any], out_dir: str, stem: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"{stem}.session.json")
    md_path = os.path.join(out_dir, f"{stem}.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(session, fh, indent=2, default=str)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(session))
    return {"json": json_path, "markdown": md_path}


def render_markdown(session: Dict[str, Any]) -> str:
    meta = session.get("meta", {})
    v = session.get("verdict", {})
    caps = session.get("capability", {})
    lines = [
        f"# hotcell — session {meta.get('session', 'n/a')}",
        "",
        f"**verdict: {VERDICT_ICON.get(v.get('verdict', 'log'), '.')} {v.get('verdict', 'log').upper()}** "
        f"(score {v.get('score', 0)})",
        f"- target: {meta.get('target', '?')} (pid {meta.get('pid', '?')}, device {meta.get('device', '?')})",
        f"- window: {meta.get('started', '?')} → {meta.get('ended', '?')}",
        "",
        "## matched signals",
    ]
    for m in v.get("matches", []):
        d = m.get("detail") or {}
        d.pop("stack", None)
        lines.append(f"- `{m['rule']}` [{m['severity']}, +{m['weight']}] — {m['reason']}")
        if d:
            lines.append(f"  - detail: `{json.dumps(d, default=str)[:300]}`")
        st = m.get("stack") or []
        if st:
            lines.append(f"  - stack: {' → '.join(map(str, st[:3]))}")
    if v.get("chains"):
        lines += ["", "## chains"]
        for c in v["chains"]:
            lines.append(f"- `{c['chain']}` (+{c['weight']}): {c['description']} "
                         f"(rules: {', '.join(c['rules_seen'])}, window {c['window_s']}s)")
    lines += ["", "## capability (hooks resolved at attach)"]
    if caps:
        for h in caps.get("hooks", []):
            lines.append(f"- ok: {h}")
        for miss in caps.get("missing", []):
            lines.append(f"- missing: {miss}")
    else:
        lines.append("_n/a (mock session)_")
    return "\n".join(lines) + "\n"


def notify_macos(title: str, body: str) -> bool:
    """Best-effort macOS notification. Never required."""
    if platform.system() != "Darwin":
        return False
    try:
        os.system(
            "osascript -e 'display notification %r with title %r'"
            % (body.replace("'", ""), title.replace("'", ""))
        )
        return True
    except Exception:
        return False


def now() -> str:
    return time.strftime("%Y%m%d-%H%M%S")
