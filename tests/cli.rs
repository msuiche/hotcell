use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Command, Output},
};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hotcell"))
}
fn report(out: &Path) -> Value {
    let file = std::fs::read_dir(out)
        .unwrap()
        .map(|p| p.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with(".session.json"))
        .unwrap();
    serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
}
fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn version_and_help() {
    let output = cli().arg("--version").output().unwrap();
    assert_code(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
    let output = cli().arg("--help").output().unwrap();
    assert_code(&output, 0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("__render"));
}
#[test]
fn disabling_both_stages_is_rejected() {
    assert_code(
        &cli()
            .args(["scan", "--file", "x.pdf", "--static-only", "--no-static"])
            .output()
            .unwrap(),
        2,
    );
}
#[test]
fn invalid_durations_are_rejected() {
    for value in ["0", "-1", "nan", "inf", "1e300"] {
        assert_code(
            &cli()
                .args(["watch", "--target", "1", &format!("--minutes={value}")])
                .output()
                .unwrap(),
            2,
        );
    }
}
#[test]
fn missing_input_is_rejected() {
    assert_code(
        &cli()
            .args(["scan", "--file", "/no-such-hotcell-input", "--static-only"])
            .output()
            .unwrap(),
        2,
    );
}
#[test]
fn missing_static_scanner_is_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("x.pdf");
    std::fs::write(&input, b"stub").unwrap();
    let out = temp.path().join("report");
    let output = cli()
        .env("HOTCELL_BOUNCER", "/missing-hotcell-scanner")
        .args(["scan", "--static-only", "--file"])
        .arg(input)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert_eq!(report(&out)["meta"]["status"], "incomplete");
}
#[cfg(unix)]
#[test]
fn static_only_findings_and_errors_have_distinct_exit_codes() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("x.pdf");
    std::fs::write(&input, b"stub").unwrap();
    for exit in [0, 2] {
        let scanner = temp.path().join(format!("scanner{exit}"));
        std::fs::write(
            &scanner,
            format!("#!/bin/sh\nprintf 'THREAT found: BLASTPASS\\n'\nexit {exit}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&scanner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = temp.path().join(format!("out{exit}"));
        let output = cli()
            .env("HOTCELL_BOUNCER", scanner)
            .args(["scan", "--static-only", "--file"])
            .arg(&input)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        assert_code(&output, exit);
        let saved = report(&out);
        assert_eq!(saved["verdict"]["verdict"], "investigate");
        assert_eq!(
            saved["meta"]["status"],
            if exit == 0 { "complete" } else { "incomplete" }
        );
        assert_eq!(saved["meta"]["static"]["threats"][0]["name"], "BLASTPASS");
    }
}
#[test]
fn replay_preserves_python_report_and_supports_rule_override() {
    let temp = tempfile::tempdir().unwrap();
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/python-v0.2.session.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&source).unwrap()).unwrap();
    let out = temp.path().join("original-rules");
    assert_code(
        &cli()
            .args(["report", "--session"])
            .arg(&source)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap(),
        0,
    );
    let replay = report(&out);
    let saved: hotcell::events::SessionReport = serde_json::from_value(original).unwrap();
    let rebuilt: hotcell::events::SessionReport = serde_json::from_value(replay).unwrap();
    assert_eq!(rebuilt.verdict, saved.verdict);
    let signals = |values: Vec<Value>| {
        values
            .into_iter()
            .map(|v| hotcell::events::Signal::from_payload(v).unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(signals(rebuilt.signals), signals(saved.signals));
    let rules = temp.path().join("rules.yaml");
    std::fs::write(&rules, "rules: {}\nchains: {}\n").unwrap();
    let out = temp.path().join("new-rules");
    assert_code(
        &cli()
            .args(["report", "--session"])
            .arg(&source)
            .arg("--rules")
            .arg(rules)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(report(&out)["verdict"]["verdict"], "log");
}
#[test]
fn legacy_report_is_rejected_without_writing_output() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("legacy.json");
    std::fs::write(
        &source,
        json!({"verdict":{"score":120,"verdict":"exploit-likely"}}).to_string(),
    )
    .unwrap();
    let out = temp.path().join("out");
    let output = cli()
        .args(["report", "--session"])
        .arg(source)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("no raw signals"));
    assert!(!out.exists());
}
#[cfg(not(feature = "live"))]
#[test]
fn disabled_live_feature_still_writes_incomplete_report() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("x.pdf");
    std::fs::write(&file, b"stub").unwrap();
    let out = temp.path().join("out");
    assert_code(
        &cli()
            .args(["scan", "--no-static", "--file"])
            .arg(file)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap(),
        2,
    );
    assert_eq!(report(&out)["meta"]["status"], "incomplete");
}
