use hotcell::{
    events::{RuleEngine, SessionReport, Signal},
    report,
};
use serde_json::{json, Value};

fn engine() -> RuleEngine {
    RuleEngine::load(None).unwrap()
}
fn signal(e: &mut RuleEngine, value: Value) {
    e.process(Signal::from_payload(value).unwrap());
}

#[test]
fn single_high_signal_is_investigate() {
    let mut e = engine();
    signal(&mut e, json!({"rule":"rwx-transition","ts":0}));
    assert_eq!(e.verdict().verdict, "investigate");
    assert_eq!(e.verdict().score, 45);
}
#[test]
fn clean_session_is_log() {
    let mut e = engine();
    signal(&mut e, json!({"rule":"pdf-opened","ts":0}));
    signal(&mut e, json!({"rule":"quicklook-render","ts":1}));
    assert_eq!(e.verdict().verdict, "log");
}
#[test]
fn glyph_and_font_chains_require_document_context() {
    let mut e = engine();
    signal(
        &mut e,
        json!({"rule":"pdf-embedded-font","pid":1,"ts":1,"context":{"pdf_open_recent":true}}),
    );
    signal(
        &mut e,
        json!({"rule":"glyph-path-anomaly","pid":1,"ts":2,"context":{"quicklook_recent":true}}),
    );
    assert_eq!(e.verdict().verdict, "exploit-likely");
    assert_eq!(e.chains.len(), 2);
    assert!(e.chains.iter().any(|c| c.chain == "font-crossing"));
    assert!(e.chains.iter().any(|c| c.chain == "glyph-grift-chain"));
}
#[test]
fn isolated_glyph_anomaly_has_no_chain() {
    let mut e = engine();
    signal(&mut e, json!({"rule":"glyph-path-anomaly","pid":1,"ts":2}));
    assert!(e.chains.is_empty());
    assert_eq!(e.verdict().verdict, "investigate");
}
#[test]
fn dedupe_preserves_raw_events_and_expires_in_seconds() {
    for start in [0., 1700000000.] {
        let mut e = engine();
        for dt in [0., 0.5, 1.] {
            signal(&mut e, json!({"rule":"rwx-transition","ts":start+dt}));
        }
        assert_eq!(e.matches.len(), 1);
        assert_eq!(e.signals.len(), 3);
        signal(&mut e, json!({"rule":"rwx-transition","ts":start+2.}));
        assert_eq!(e.matches.len(), 2);
    }
}
#[test]
fn dedupe_ignores_json_key_order() {
    let mut e = engine();
    signal(
        &mut e,
        serde_json::from_str(r#"{"rule":"rwx-transition","ts":0,"detail":{"a":1,"b":2}}"#).unwrap(),
    );
    signal(
        &mut e,
        serde_json::from_str(r#"{"rule":"rwx-transition","ts":0.5,"detail":{"b":2,"a":1}}"#)
            .unwrap(),
    );
    assert_eq!(e.matches.len(), 1);
}
#[test]
fn large_mapping_escalates_without_32bit_truncation() {
    let mut e = engine();
    signal(
        &mut e,
        json!({"rule":"big-anon-map","ts":0,"detail":{"bytes":2147483648u64}}),
    );
    assert_eq!(e.matches[0].weight, 45);
}
#[test]
fn unknown_rule_uses_fallback_weight() {
    let mut e = engine();
    signal(
        &mut e,
        json!({"rule":"future-rule","severity":"critical","ts":0}),
    );
    assert_eq!(e.verdict().score, 1);
}
#[test]
fn seconds_and_legacy_milliseconds_correlate() {
    for (ts, unit) in [
        (1700000001u64, json!("s")),
        (1700000001000, json!("ms")),
        (1700000001000, Value::Null),
    ] {
        let mut e = engine();
        signal(&mut e, json!({"rule":"bouncer-static-hit","ts":1700000000}));
        signal(
            &mut e,
            json!({"rule":"image-bomb","ts":ts,"ts_unit":unit,"pid":20,"proc":"renderer"}),
        );
        assert_eq!(e.verdict().verdict, "exploit-likely");
        assert_eq!(e.signals[1].ts, 1700000001.);
        assert_eq!(e.signals[1].proc.as_deref(), Some("renderer"));
    }
}
#[test]
fn stale_and_future_signals_do_not_form_chains() {
    for (first, second) in [(1, 302), (100, 99)] {
        let mut e = engine();
        signal(&mut e, json!({"rule":"bouncer-static-hit","ts":first}));
        signal(&mut e, json!({"rule":"image-bomb","ts":second}));
        assert!(e.chains.is_empty());
    }
}
#[test]
fn processes_do_not_dedupe_or_cross_correlate() {
    let mut e = engine();
    for pid in [10, 11] {
        signal(&mut e, json!({"rule":"rwx-transition","ts":0,"pid":pid}));
    }
    assert_eq!(e.matches.len(), 2);
    signal(
        &mut e,
        json!({"rule":"pdf-embedded-font","pid":10,"ts":1,"context":{"pdf_open_recent":true}}),
    );
    signal(&mut e, json!({"rule":"glyph-path-anomaly","pid":11,"ts":2}));
    assert!(e.chains.is_empty());
}
#[test]
fn chains_are_deduplicated_per_process() {
    let mut e = engine();
    for (pid, ts) in [(10, 0), (10, 4), (11, 5)] {
        signal(
            &mut e,
            json!({"rule":"glyph-path-anomaly","pid":pid,"ts":ts,"context":{"pdf_open_recent":true}}),
        );
    }
    assert_eq!(e.chains.len(), 2);
}
#[test]
fn informational_signals_cannot_alone_be_exploit_likely() {
    let mut e = engine();
    for i in 0..120 {
        signal(
            &mut e,
            json!({"rule":"pdf-opened","ts":i*3,"detail":{"document":i}}),
        );
    }
    assert_eq!(e.verdict().verdict, "investigate");
}
#[test]
fn static_findings_corroborate_runtime() {
    for rule in ["image-bomb", "glyph-path-anomaly"] {
        let mut e = engine();
        signal(&mut e, json!({"rule":"bouncer-static-hit","ts":0}));
        assert_eq!(e.verdict().verdict, "investigate");
        signal(&mut e, json!({"rule":rule,"pid":20,"ts":1}));
        assert_eq!(e.verdict().verdict, "exploit-likely");
    }
}
#[test]
fn python_v02_report_replays_with_identical_verdict() {
    let saved: SessionReport =
        serde_json::from_str(include_str!("fixtures/python-v0.2.session.json")).unwrap();
    let mut e = engine();
    e.replay(&saved).unwrap();
    let rebuilt = e.session(saved.meta.clone());
    assert_eq!(rebuilt.verdict, saved.verdict);
    let signals = |values: Vec<Value>| {
        values
            .into_iter()
            .map(|v| Signal::from_payload(v).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(signals(rebuilt.signals), signals(saved.signals));
    assert_eq!(rebuilt.capabilities, saved.capabilities);
}
#[test]
fn replay_preserves_capabilities_and_errors() {
    let mut e = engine();
    e.record_capability(json!({"pid":1,"hooks":["bbox"]}));
    e.record_capability(json!({"pid":2,"hooks":["mmap"]}));
    e.error("renderer failed");
    let original = e.session(json!({"status":"incomplete"}));
    let mut replay = engine();
    replay.replay(&original).unwrap();
    assert_eq!(
        serde_json::to_value(replay.session(original.meta.clone())).unwrap(),
        serde_json::to_value(original).unwrap()
    );
}
#[test]
fn legacy_reports_without_signals_are_rejected() {
    assert!(serde_json::from_value::<SessionReport>(
        json!({"verdict":{"score":120,"verdict":"exploit-likely"}})
    )
    .is_err());
}
#[test]
fn markdown_contains_verdict_chains_capabilities_and_errors() {
    let mut e = engine();
    e.record_capability(json!({"pid":1,"hooks":["CGPathGetBoundingBox"],"missing":["aa_cache_render (not exported)"]}));
    signal(
        &mut e,
        json!({"rule":"glyph-path-anomaly","pid":1,"ts":0,"context":{"quicklook_recent":true}}),
    );
    e.error("test incomplete");
    let md = report::render_markdown(&e.session(json!({"status":"incomplete"})));
    for part in [
        "EXPLOIT-LIKELY",
        "glyph-grift-chain",
        "aa_cache_render (not exported)",
        "test incomplete",
        "incomplete",
    ] {
        assert!(md.contains(part), "missing {part}");
    }
}
#[test]
fn abnormal_detach_is_an_error() {
    for (reason, crash, error) in [
        ("process-terminated", Value::Null, false),
        ("application-requested", Value::Null, false),
        ("device-lost", Value::Null, true),
        ("process-terminated", json!("crash"), true),
    ] {
        let mut e = engine();
        e.ingest(json!({"type":"detached","reason":reason,"crash":crash}))
            .unwrap();
        assert_eq!(!e.errors.is_empty(), error);
    }
}
#[test]
fn invalid_rules_and_payloads_fail_explicitly() {
    assert!(RuleEngine::from_yaml("chains:\n  bad:\n    window_s: -1").is_err());
    assert!(Signal::from_payload(json!([])).is_err());
    assert!(Signal::from_payload(json!({"rule":1})).is_err());
}
#[test]
fn malformed_timestamps_and_units_are_rejected() {
    for ts in [json!("1700000000"), json!(false), json!([]), json!({})] {
        assert!(Signal::from_payload(json!({"rule":"image-bomb", "ts":ts})).is_err());
    }
    for unit in [json!("minutes"), json!(1), json!(false), json!([])] {
        assert!(Signal::from_payload(json!({"ts":1700000000, "ts_unit":unit})).is_err());
    }
}
#[test]
fn absent_live_timestamps_use_current_seconds_even_with_millisecond_unit() {
    let before = hotcell::events::epoch_seconds();
    for unit in [Value::Null, json!("s"), json!("ms")] {
        let signal = Signal::from_payload(json!({"ts_unit":unit})).unwrap();
        assert!(signal.ts >= before && signal.ts <= hotcell::events::epoch_seconds());
        assert_eq!(signal.ts_unit, "s");
    }
}
