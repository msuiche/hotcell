"""Event pipeline: signals -> rule engine (weights, escalation, chains) -> verdict.

Pure-python, no frida dependency — everything here is unit-testable anywhere.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Signal:
    rule: str
    severity: str = "low"
    detail: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    ts: Optional[float] = None
    stack: List[str] = field(default_factory=list)
    proc: Optional[str] = None
    pid: Optional[int] = None

    @classmethod
    def from_payload(cls, payload: Dict[str, Any], proc=None, pid=None) -> "Signal":
        return cls(
            rule=payload.get("rule", "unknown"),
            severity=payload.get("severity", "low"),
            detail=payload.get("detail") or {},
            context=payload.get("context") or {},
            ts=payload.get("ts"),
            stack=payload.get("stack") or [],
            proc=proc,
            pid=payload.get("pid") if pid is None else pid,
        )


@dataclass
class Match:
    signal: Signal
    weight: int
    reason: str


@dataclass
class ChainEvent:
    chain: str
    description: str
    rules_seen: List[str]
    window_s: int
    ts: float
    weight: int


@dataclass
class Verdict:
    label: str
    score: int
    matches: List[Match]
    chains: List[ChainEvent]

    def to_dict(self):
        return {
            "verdict": self.label,
            "score": self.score,
            "matches": [
                {"rule": m.signal.rule, "severity": m.signal.severity,
                 "weight": m.weight, "reason": m.reason, "ts": m.signal.ts,
                 "detail": m.signal.detail, "stack": m.signal.stack}
                for m in self.matches
            ],
            "chains": [asdict(c) for c in self.chains],
        }


class RuleEngine:
    """Loads the YAML rule pack; folds a session's signals into a verdict."""

    def __init__(self, ruleset: Dict[str, Any]):
        self.rules = ruleset.get("rules", {})
        self.chains = ruleset.get("chains", {})
        self.weights = ruleset.get("weights", {})
        self.thresholds = ruleset.get("verdict_thresholds", {"investigate": 35, "exploit-likely": 100})
        self.signals: List[Signal] = []
        self.matches: List[Match] = []
        self.chains_matched: List[ChainEvent] = []
        self.capability: Dict[str, Any] = {}
        self._dedupe: Dict[str, float] = {}

    @classmethod
    def load_yaml(cls, path) -> "RuleEngine":
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh) or {})

    # ---------------------------------------------------------------- intake

    def record_capability(self, caps: Dict[str, Any]) -> None:
        self.capability = caps

    def process(self, sig: Signal) -> Optional[Match]:
        """Fold one signal in; returns the Match (or None for unknown rules)."""
        if sig.ts is None:
            sig.ts = time.time()
        self.signals.append(sig)

        if not self._dedupe_ok(sig):
            return None

        rule = self.rules.get(sig.rule)
        if rule is None:
            # Unknown rule: conservative fallback — give it minimal weight so
            # an agent newer than the rule pack never goes silent.
            w = 1
            m = Match(sig, w, "unknown rule (fallback weight)")
        else:
            w = int(rule.get("weight", self.weights.get(sig.severity, 1)))
            reason = rule.get("description", sig.rule)

            esc = rule.get("escalate") or {}
            if esc.get("detail_gte"):
                g = esc["detail_gte"]
                try:
                    if (sig.detail.get(g["field"]) or 0) >= g["gte"]:
                        w = max(w, int(g["weight"]))
                        reason += f" [escalated: {g['field']}>={g['gte']}]"
                except (TypeError, KeyError):
                    pass
            add_if_ctx = esc.get("add_if_context") or {}
            for tag, bump in add_if_ctx.items():
                if sig.context.get(tag):
                    w += int(bump)
                    reason += f" [+{bump} context:{tag}]"

            m = Match(sig, w, reason)
        self.matches.append(m)
        self._match_chains(sig)
        return m

    # ---------------------------------------------------------------- dedupe

    def _dedupe_ok(self, sig: Signal) -> bool:
        key = sig.rule + "|" + json.dumps(sig.detail, sort_keys=True, default=str)[:160]
        key = hashlib.sha1(key.encode()).hexdigest()[:16]
        ts = sig.ts or time.time()
        last = self._dedupe.get(key, float("-inf"))
        if ts - last < 2.0:      # identical signal inside 2s: collapsed
            return False
        self._dedupe[key] = ts
        return True

    # ---------------------------------------------------------------- chains

    def _match_chains(self, sig: Signal) -> None:
        for name, ch in self.chains.items():
            required = list(ch.get("required_rules", []))
            if sig.rule not in required:
                continue
            window = float(ch.get("window_s", 120))
            seen = {}
            for s in self.signals:
                if (sig.ts - (s.ts or 0)) <= window:
                    seen.setdefault(s.rule, s)
            missing = [r for r in required if r not in seen]
            if missing:
                continue
            tags_any = list(ch.get("required_tags_any", []))
            if tags_any:
                ctx_ok = any(
                    any(s.context.get(tag) for tag in tags_any)
                    for s in seen.values()
                )
                if not ctx_ok:
                    continue
            if any(c.chain == name for c in self.chains_matched):
                continue
            self.chains_matched.append(ChainEvent(
                chain=name,
                description=ch.get("description", name),
                rules_seen=sorted(seen.keys()),
                window_s=int(window),
                ts=sig.ts,
                weight=int(ch.get("weight", self.weights.get(ch.get("severity", "critical"), 100))),
            ))

    # --------------------------------------------------------------- verdict

    def verdict(self) -> Verdict:
        score = sum(m.weight for m in self.matches)
        score += sum(c.weight for c in self.chains_matched)
        label = "log"
        if score >= self.thresholds.get("exploit-likely", 100):
            label = "exploit-likely"
        elif score >= self.thresholds.get("investigate", 35):
            label = "investigate"
        return Verdict(label, score, self.matches, self.chains_matched)

    def session_dict(self, meta: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "meta": meta,
            "capability": self.capability,
            "verdict": self.verdict().to_dict(),
        }
