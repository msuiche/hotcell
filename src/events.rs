//! Signal normalization, process-scoped correlation, and replayable reports.
use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn epoch_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn object() -> Value {
    json!({})
}
fn low() -> String {
    "low".into()
}
fn seconds() -> String {
    "s".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Signal {
    pub rule: String,
    #[serde(default = "low")]
    pub severity: String,
    #[serde(default = "object")]
    pub detail: Value,
    #[serde(default = "object")]
    pub context: Value,
    pub ts: f64,
    #[serde(default = "seconds")]
    pub ts_unit: String,
    #[serde(default)]
    pub stack: Vec<String>,
    #[serde(default)]
    pub proc: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}
impl Signal {
    pub fn from_payload(mut v: Value) -> Result<Self> {
        if !v.is_object() {
            bail!("signal must be a JSON object");
        }
        let mut ts = v
            .get("ts")
            .and_then(Value::as_f64)
            .unwrap_or_else(epoch_seconds);
        if v["ts_unit"] == "ms" || (v["ts_unit"].is_null() && ts > 1e11) {
            ts /= 1000.0;
        }
        if !ts.is_finite() {
            bail!("signal timestamp must be finite");
        }
        v["ts"] = json!(ts);
        v["ts_unit"] = json!("s");
        if v["rule"].is_null() {
            v["rule"] = json!("unknown");
        }
        for key in ["detail", "context"] {
            if v[key].is_null() {
                v[key] = object();
            }
        }
        if v["stack"].is_null() {
            v["stack"] = json!([]);
        }
        serde_json::from_value(v).context("invalid signal payload")
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Rule {
    pub weight: Option<u64>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub escalate: Escalation,
}
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Escalation {
    pub detail_gte: Option<DetailThreshold>,
    #[serde(default)]
    pub add_if_context: IndexMap<String, u64>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct DetailThreshold {
    pub field: String,
    pub gte: f64,
    pub weight: u64,
}
fn window() -> f64 {
    120.0
}
#[derive(Clone, Debug, Deserialize)]
pub struct Chain {
    #[serde(default)]
    pub required_rules: Vec<String>,
    #[serde(default)]
    pub required_tags_any: Vec<String>,
    #[serde(default = "window")]
    pub window_s: f64,
    pub weight: Option<u64>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub description: String,
}
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Ruleset {
    #[serde(default)]
    pub rules: IndexMap<String, Rule>,
    #[serde(default)]
    pub chains: IndexMap<String, Chain>,
    #[serde(default)]
    pub weights: BTreeMap<String, u64>,
    #[serde(default)]
    pub verdict_thresholds: BTreeMap<String, u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Match {
    pub rule: String,
    pub severity: String,
    pub weight: u64,
    pub reason: String,
    pub ts: f64,
    pub detail: Value,
    pub stack: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChainEvent {
    pub chain: String,
    pub description: String,
    pub rules_seen: Vec<String>,
    pub window_s: u64,
    pub ts: f64,
    pub weight: u64,
    pub pid: Option<u32>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    pub verdict: String,
    pub score: u64,
    pub matches: Vec<Match>,
    pub chains: Vec<ChainEvent>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionReport {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default = "object")]
    pub meta: Value,
    // Intentionally required: old reports without raw signals cannot be replayed.
    pub signals: Vec<Value>,
    #[serde(default = "object")]
    pub capability: Value,
    #[serde(default)]
    pub capabilities: Vec<Value>,
    #[serde(default)]
    pub errors: Vec<Value>,
    pub verdict: Verdict,
}
fn schema_version() -> u32 {
    2
}
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(x) => *x,
        Value::Number(x) => x.as_f64() != Some(0.0),
        Value::String(x) => !x.is_empty(),
        Value::Array(x) => !x.is_empty(),
        Value::Object(x) => !x.is_empty(),
    }
}
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        _ => v.clone(),
    }
}

pub struct RuleEngine {
    pub ruleset: Ruleset,
    pub signals: Vec<Signal>,
    pub matches: Vec<Match>,
    pub chains: Vec<ChainEvent>,
    pub capabilities: IndexMap<String, Value>,
    pub errors: Vec<Value>,
    last_capability: Value,
    dedupe: HashMap<String, f64>,
}
impl RuleEngine {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let text = if let Some(p) = path {
            std::fs::read_to_string(p).with_context(|| format!("read rules {}", p.display()))?
        } else {
            crate::DEFAULT_RULES.to_owned()
        };
        Self::from_yaml(&text)
    }
    pub fn from_yaml(text: &str) -> Result<Self> {
        let ruleset: Ruleset = serde_yaml_ng::from_str(text).context("invalid rule pack")?;
        for (name, ch) in &ruleset.chains {
            if !ch.window_s.is_finite() || ch.window_s < 0.0 {
                bail!("invalid window for chain {name}");
            }
        }
        Ok(Self {
            ruleset,
            signals: vec![],
            matches: vec![],
            chains: vec![],
            capabilities: IndexMap::new(),
            errors: vec![],
            last_capability: object(),
            dedupe: HashMap::new(),
        })
    }
    pub fn record_capability(&mut self, cap: Value) {
        let key = cap
            .get("pid")
            .map(Value::to_string)
            .unwrap_or_else(|| "unknown".into());
        self.last_capability = cap.clone();
        self.capabilities.insert(key, cap);
    }
    pub fn error(&mut self, description: impl ToString) {
        self.errors
            .push(json!({"type":"error", "detail":{"description":description.to_string()}}));
    }
    pub fn ingest(&mut self, payload: Value) -> Result<()> {
        match payload["type"].as_str() {
            Some("capability") => self.record_capability(payload),
            Some("signal") => {
                self.process(Signal::from_payload(payload)?);
            }
            Some("error") => self.errors.push(payload),
            Some("detached")
                if !payload["crash"].is_null()
                    || !matches!(
                        payload["reason"].as_str(),
                        Some("process-terminated" | "application-requested")
                    ) =>
            {
                self.error(format!("target detached: {payload}"));
            }
            _ => {}
        }
        Ok(())
    }
    pub fn process(&mut self, sig: Signal) -> Option<&Match> {
        let key = canonical(&json!([sig.pid, sig.rule, sig.detail, sig.context])).to_string();
        let duplicate = self
            .dedupe
            .get(&key)
            .is_some_and(|last| sig.ts - last < 2.0);
        self.signals.push(sig.clone());
        if duplicate {
            return None;
        }
        self.dedupe.insert(key, sig.ts);
        let (weight, reason) = if let Some(rule) = self.ruleset.rules.get(&sig.rule) {
            let mut w = rule
                .weight
                .unwrap_or_else(|| *self.ruleset.weights.get(&sig.severity).unwrap_or(&1));
            let mut reason = if rule.description.is_empty() {
                sig.rule.clone()
            } else {
                rule.description.clone()
            };
            if let Some(g) = &rule.escalate.detail_gte {
                if sig.detail[&g.field].as_f64().unwrap_or(0.0) >= g.gte {
                    w = w.max(g.weight);
                    reason.push_str(&format!(" [escalated: {}>={}]", g.field, g.gte));
                }
            }
            for (tag, bump) in &rule.escalate.add_if_context {
                if truthy(&sig.context[tag]) {
                    w = w.saturating_add(*bump);
                    reason.push_str(&format!(" [+{bump} context:{tag}]"));
                }
            }
            (w, reason)
        } else {
            (1, "unknown rule (fallback weight)".into())
        };
        self.matches.push(Match {
            rule: sig.rule.clone(),
            severity: sig.severity.clone(),
            weight,
            reason,
            ts: sig.ts,
            detail: sig.detail.clone(),
            stack: sig.stack.clone(),
        });
        self.match_chains(&sig);
        self.matches.last()
    }
    fn match_chains(&mut self, sig: &Signal) {
        for (name, ch) in &self.ruleset.chains {
            if !ch.required_rules.contains(&sig.rule)
                || self
                    .chains
                    .iter()
                    .any(|c| c.chain == *name && c.pid == sig.pid)
            {
                continue;
            }
            let mut seen = BTreeMap::new();
            for s in &self.signals {
                let age = sig.ts - s.ts;
                if (s.pid == sig.pid || s.rule == "bouncer-static-hit")
                    && ch.required_rules.contains(&s.rule)
                    && age >= 0.0
                    && age <= ch.window_s
                {
                    seen.insert(s.rule.clone(), s);
                }
            }
            if ch.required_rules.iter().any(|r| !seen.contains_key(r)) {
                continue;
            }
            if !ch.required_tags_any.is_empty()
                && !seen
                    .values()
                    .any(|s| ch.required_tags_any.iter().any(|t| truthy(&s.context[t])))
            {
                continue;
            }
            self.chains.push(ChainEvent {
                chain: name.clone(),
                description: ch.description.clone(),
                rules_seen: seen.keys().cloned().collect(),
                window_s: ch.window_s as u64,
                ts: sig.ts,
                pid: sig.pid,
                weight: ch
                    .weight
                    .unwrap_or_else(|| *self.ruleset.weights.get(&ch.severity).unwrap_or(&100)),
            });
        }
    }
    pub fn verdict(&self) -> Verdict {
        let score = self
            .matches
            .iter()
            .map(|m| m.weight)
            .chain(self.chains.iter().map(|c| c.weight))
            .fold(0u64, u64::saturating_add);
        let thresholds = &self.ruleset.verdict_thresholds;
        let label = if !self.chains.is_empty()
            && score >= *thresholds.get("exploit-likely").unwrap_or(&100)
        {
            "exploit-likely"
        } else if score >= *thresholds.get("investigate").unwrap_or(&35) {
            "investigate"
        } else {
            "log"
        };
        Verdict {
            verdict: label.into(),
            score,
            matches: self.matches.clone(),
            chains: self.chains.clone(),
        }
    }
    pub fn session(&self, meta: Value) -> SessionReport {
        SessionReport {
            schema_version: 2,
            meta,
            signals: self.signals.iter().map(|s| json!(s)).collect(),
            capability: self.last_capability.clone(),
            capabilities: self.capabilities.values().cloned().collect(),
            errors: self.errors.clone(),
            verdict: self.verdict(),
        }
    }
    pub fn replay(&mut self, saved: &SessionReport) -> Result<()> {
        for s in &saved.signals {
            self.process(Signal::from_payload(s.clone())?);
        }
        if saved.capabilities.is_empty() {
            if saved.capability.as_object().is_some_and(|m| !m.is_empty()) {
                self.record_capability(saved.capability.clone());
            }
        } else {
            for cap in &saved.capabilities {
                self.record_capability(cap.clone());
            }
        }
        self.errors.clone_from(&saved.errors);
        Ok(())
    }
}
