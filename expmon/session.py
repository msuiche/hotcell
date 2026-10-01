"""Frida device/session handling. frida is a *lazy* dependency: the pipeline
and tests run anywhere; only driving real targets needs frida on the host.
"""
from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional

AGENT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agent", "expmon_agent.js")

DEVICES = {"local", "usb"}


def load_agent_source(path: Optional[str] = None) -> str:
    with open(path or AGENT_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


class Monitor:
    """Attaches the agent to processes on a device and funnels messages out."""

    def __init__(self, device_kind: str = "local", agent_path: Optional[str] = None,
                 on_event: Optional[Callable[[Dict], None]] = None):
        if device_kind not in DEVICES:
            raise ValueError(f"unknown device {device_kind!r} (use {sorted(DEVICES)})")
        self.device_kind = device_kind
        self.agent_path = agent_path or AGENT_PATH
        self.on_event = on_event
        self._frida = None
        self._device = None
        self._sessions: List = []

    # ---------------------------------------------------------------- device

    def _dev(self):
        if self._device is None:
            try:
                import frida
            except ImportError as e:
                raise RuntimeError(
                    "frida is required to drive live targets — "
                    "pip install expmon-apple[live] (on a macOS/iOS host)") from e
            self._frida = frida
            self._device = (frida.get_usb_device(timeout=10)
                            if self.device_kind == "usb"
                            else frida.get_local_device())
        return self._device

    # ---------------------------------------------------------------- target

    def list_processes(self) -> List[Dict]:
        from . import targets
        out = []
        for proc in self._dev().enumerate_processes():
            name, pid = proc[0] if isinstance(proc, tuple) else (proc.name, proc.pid)
            out.append({"pid": pid, "name": name,
                        "target": targets.matches(name, "ios" if self.device_kind == "usb" else "macos")})
        return out

    # ---------------------------------------------------------------- attach

    def attach(self, proc_name_or_pid, timeout_s: Optional[float] = None) -> "Session":
        dev = self._dev()
        if isinstance(proc_name_or_pid, int):
            pid, name = proc_name_or_pid, None
        else:
            hits = [p for p in dev.enumerate_processes()
                    if (p[0] if isinstance(p, tuple) else p.name) == proc_name_or_pid]
            if not hits:
                raise RuntimeError(f"process not found: {proc_name_or_pid!r}")
            p = hits[0]
            name, pid = (p[0] if isinstance(p, tuple) else p.name), (p[1] if isinstance(p, tuple) else p.pid)
        session = Session(self, dev.attach(pid), pid, name, timeout_s)
        self._sessions.append(session)
        return session

    def spawn(self, argv: List[str], timeout_s: Optional[float] = None) -> "Session":
        dev = self._dev()
        pid = dev.spawn(argv)
        session = Session(self, dev.attach(pid), pid, os.path.basename(argv[0]), timeout_s)
        session.spawned = True
        self._sessions.append(session)
        return session


class Session:
    """A live agent session. Events (dicts) go to monitor.on_event."""

    def __init__(self, monitor: Monitor, frida_session, pid, name, timeout_s):
        self.monitor = monitor
        self._session = frida_session
        self.pid = pid
        self.name = name or ""
        self.timeout_s = timeout_s
        self.spawned = False
        self.script = None
        self._load()

    def _load(self):
        src = load_agent_source(self.monitor.agent_path)
        self.script = self._session.create_script(src)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message, data):
        if message.get("type") == "send":
            payload = dict(message.get("payload") or {})
            payload.setdefault("pid", self.pid)
            payload.setdefault("proc", self.name)
            if self.monitor.on_event:
                self.monitor.on_event(payload)
        elif message.get("type") == "error":
            if self.monitor.on_event:
                self.monitor.on_event({"type": "error", "detail": message})

    def run_until(self, seconds: float, tick: float = 0.5) -> None:
        """Block for `seconds` while messages flow (processes the frida glue)."""
        import time as _t
        deadline = _t.time() + seconds
        # frida's message delivery happens on its own thread; the script
        # context only needs to stay alive. Wait in small ticks so Ctrl-C works.
        while _t.time() < deadline:
            _t.sleep(tick)

    def close(self):
        try:
            if self.spawned:
                self.monitor._dev().kill(self.pid)
        except Exception:
            pass
        try:
            self._session.detach()
        except Exception:
            pass
