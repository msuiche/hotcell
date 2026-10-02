use hotcell::{
    events::RuleEngine,
    report,
    static_scan::{parse_output, scan_with_binary},
};
use serde_json::json;
use std::{path::Path, time::Duration};

#[test]
fn summary_is_parsed_and_deduplicated() {
    let result = parse_output("THREAT found: BLASTPASS\n│ name │ cve_ids │ description │ detected │\n│ BLASTPASS │ CVE-2023-4863, CVE-2023-41064 │ test │ \x1b[31mYes\x1b[0m │\n│ FORCEDENTRY │ CVE-2021-30860 │ test │ No │\n╰────╯", "", 0);
    assert!(result.error.is_none());
    assert_eq!(result.threats.len(), 1);
    assert_eq!(result.threats[0].cves, ["CVE-2023-4863", "CVE-2023-41064"]);
}
#[test]
fn clean_summary_is_recognized() {
    let result = parse_output(
        "| name | cve_ids | description | detected |\n| BLASTPASS | CVE-2023-4863 | test | No |",
        "",
        0,
    );
    assert!(result.error.is_none());
    assert!(result.threats.is_empty());
}
#[test]
fn legacy_threat_lines_are_recognized() {
    let result = parse_output(
        "THREAT found: FORCEDENTRY\nTHREAT found: BLASTPASS\n",
        "",
        0,
    );
    assert!(result.error.is_none());
    assert_eq!(result.threats.len(), 2);
    assert_eq!(result.threats[1].cves, ["CVE-2021-30860"]);
}
#[test]
fn unknown_output_is_incomplete() {
    assert!(parse_output("Usage: scanner", "", 0)
        .error
        .unwrap()
        .contains("no recognizable scan results"));
}
#[test]
fn scanner_failure_preserves_findings_in_report() {
    let result = parse_output("THREAT found: BLASTPASS", "failed", 2);
    assert!(result.error.as_ref().unwrap().contains("status 2"));
    let md = report::render_markdown(
        &RuleEngine::load(None)
            .unwrap()
            .session(json!({"static":result})),
    );
    assert!(md.contains("incomplete"));
    assert!(md.contains("THREAT: **BLASTPASS**"));
    assert!(!md.contains("no static findings"));
}
#[test]
fn missing_binary_is_explicit() {
    let result = scan_with_binary(
        Path::new("/missing-hotcell-scanner"),
        Path::new("x.pdf"),
        Duration::from_secs(1),
    );
    assert!(!result.available);
    assert!(result.error.unwrap().contains("failed to run"));
}
#[cfg(unix)]
#[test]
fn existing_scanner_that_cannot_start_is_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("scanner");
    std::fs::write(&script, "#!/missing-hotcell-interpreter\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = scan_with_binary(&script, Path::new("x.pdf"), Duration::from_secs(1));
    assert!(result.available);
    assert!(result.error.unwrap().contains("failed to run"));
}
#[cfg(unix)]
#[test]
fn scanner_timeout_kills_and_reaps_child() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("scanner");
    std::fs::write(&script, "#!/bin/sh\nexec /bin/sleep 10\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let start = std::time::Instant::now();
    let result = scan_with_binary(&script, Path::new("x.pdf"), Duration::from_millis(30));
    assert!(result.available);
    assert!(result.error.unwrap().contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(2));
}
