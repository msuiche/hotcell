#![cfg(all(target_os = "macos", feature = "live"))]

use hotcell::{events::RuleEngine, live::Monitor, report};
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

struct Fixture {
    root: tempfile::TempDir,
    pdf: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let pdf = root.path().join("clean.pdf");
        let objects: &[&[u8]] = &[
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
            b"<< /Length 28 >>\nstream\n1 0 0 rg 20 20 160 160 re f\nendstream",
        ];
        let mut data = b"%PDF-1.4\n".to_vec();
        let mut offsets = vec![];
        for (i, object) in objects.iter().enumerate() {
            offsets.push(data.len());
            data.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            data.extend_from_slice(object);
            data.extend_from_slice(b"\nendobj\n");
        }
        let xref = data.len();
        data.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
        for offset in offsets {
            data.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        data.extend_from_slice(
            format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        std::fs::write(&pdf, data).unwrap();
        Self { root, pdf }
    }
    fn scan(&self, input: &Path, name: &str) -> (Output, Value, PathBuf) {
        let out = self.root.path().join(name);
        let output = cli()
            .args(["scan", "--no-static", "--minutes", ".2", "--file"])
            .arg(input)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap();
        let (report, path) = read_report(&out);
        (output, report, path)
    }
    fn probe(&self) -> PathBuf {
        let probe = self.root.path().join("probe");
        let output = Command::new("clang")
            .arg("-O0")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.m"))
            .args([
                "-framework",
                "CoreGraphics",
                "-framework",
                "CoreText",
                "-framework",
                "CoreFoundation",
                "-framework",
                "Foundation",
                "-framework",
                "PDFKit",
                "-o",
            ])
            .arg(&probe)
            .output()
            .unwrap();
        assert_code(&output, 0);
        probe
    }
    fn probe_run(&self, size: u32, allocation: bool) -> (Vec<Value>, Value) {
        let bbox = self.root.path().join("bbox.json");
        let argv: Vec<OsString> = vec![
            self.probe().into(),
            self.pdf.clone().into(),
            bbox.clone().into(),
            size.to_string().into(),
            u8::from(allocation).to_string().into(),
        ];
        let monitor = Monitor::new("local").unwrap();
        let mut session = monitor.spawn(&argv).unwrap();
        let mut events = monitor.drain();
        assert!(
            events.iter().any(|e| e["type"] == "capability"),
            "boot capabilities must be buffered before resume"
        );
        let start = Instant::now();
        while !session.detached() && start.elapsed() < Duration::from_secs(10) {
            events.extend(monitor.drain());
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(session.detached(), "probe did not finish");
        let cap = session.capability().unwrap();
        assert!(!cap["hooks"].as_array().unwrap().is_empty());
        session.close();
        session.close(); // cleanup is idempotent
        events.extend(monitor.drain());
        assert!(!events.iter().any(|e| e["type"] == "error"), "{events:#?}");
        assert!(
            events.iter().any(|e| e["rule"] == "pdf-opened-url"),
            "Objective-C PDF hook did not fire"
        );
        (
            events,
            serde_json::from_slice(&std::fs::read(bbox).unwrap()).unwrap(),
        )
    }
}
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hotcell"))
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
fn read_report(out: &Path) -> (Value, PathBuf) {
    let path = std::fs::read_dir(out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with(".session.json"))
        .unwrap();
    (
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
        path,
    )
}

#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn pdf_image_and_replay() {
    let f = Fixture::new();
    let (output, pdf, source) = f.scan(&f.pdf, "pdf-report");
    assert_code(&output, 0);
    assert_eq!(pdf["meta"]["status"], "complete");
    assert_eq!(pdf["verdict"]["verdict"], "log");
    assert_eq!(pdf["errors"], json!([]));
    assert!(pdf["signals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["rule"] == "pdf-rendered"));
    let preview = Path::new(pdf["meta"]["preview"].as_str().unwrap());
    assert!(std::fs::read(preview).unwrap().starts_with(b"\x89PNG"));
    let (output, image, _) = f.scan(preview, "image-report");
    assert_code(&output, 0);
    assert!(image["signals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["rule"] == "image-decoded"));
    let replay_dir = f.root.path().join("replay");
    assert_code(
        &cli()
            .args(["report", "--session"])
            .arg(source)
            .arg("--out")
            .arg(&replay_dir)
            .output()
            .unwrap(),
        0,
    );
    let (replay, _) = read_report(&replay_dir);
    assert_eq!(replay["verdict"], pdf["verdict"]);
    assert_eq!(replay["signals"], pdf["signals"]);
}
#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn malformed_document_is_incomplete() {
    let f = Fixture::new();
    let bad = f.root.path().join("malformed.pdf");
    std::fs::write(&bad, b"%PDF-1.4\nnot a document").unwrap();
    let (output, saved, _) = f.scan(&bad, "bad-report");
    assert_code(&output, 2);
    assert_eq!(saved["meta"]["status"], "incomplete");
    assert!(!saved["errors"].as_array().unwrap().is_empty());
    assert!(saved["signals"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["rule"] == "render-complete" && s["detail"]["status"] == 2));
}
#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn native_glyph_bounds_and_positive_replay() {
    let f = Fixture::new();
    let (events, bounds) = f.probe_run(4096, false);
    let anomalies: Vec<_> = events
        .iter()
        .filter(|e| e["rule"] == "glyph-path-anomaly")
        .collect();
    assert!(!anomalies.is_empty());
    assert!(bounds["w"].as_f64().unwrap() > 1024.);
    for anomaly in anomalies {
        assert_eq!(anomaly["detail"]["bbox"], bounds);
    }
    let mut engine = RuleEngine::load(None).unwrap();
    for event in events {
        engine.ingest(event).unwrap();
    }
    assert_eq!(engine.verdict().verdict, "exploit-likely");
    let saved = engine.session(json!({"status":"complete"}));
    let (path, _) = report::write_report(&saved, f.root.path(), "positive").unwrap();
    let out = f.root.path().join("replayed");
    assert_code(
        &cli()
            .args(["report", "--session"])
            .arg(path)
            .arg("--out")
            .arg(&out)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(
        read_report(&out).0["verdict"],
        serde_json::to_value(&saved.verdict).unwrap()
    );
}
#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn ordinary_glyph_generic_art_and_64bit_mapping() {
    let f = Fixture::new();
    let (events, bounds) = f.probe_run(12, true);
    assert!(bounds["w"].as_f64().unwrap() < 1024.);
    assert!(!events.iter().any(|e| e["rule"] == "glyph-path-anomaly"));
    assert!(events
        .iter()
        .any(|e| e["rule"] == "big-anon-map" && e["detail"]["bytes"] == 2147483648u64));
}
#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn watch_cli_attaches_to_its_probe() {
    let f = Fixture::new();
    let mut process = Command::new(f.probe())
        .arg(&f.pdf)
        .arg(f.root.path().join("bbox.json"))
        .args(["4096", "0", "wait"])
        .spawn()
        .unwrap();
    let pid = process.id();
    let out = f.root.path().join("watch");
    let output = cli()
        .args([
            "watch",
            "--target",
            &pid.to_string(),
            "--minutes",
            ".1",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    let _ = process.kill();
    let _ = process.wait();
    assert_code(&output, 0);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("[signal] glyph-path-anomaly"),
        "watch must display observed signals while monitoring: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let (saved, _) = read_report(&out);
    assert_eq!(saved["verdict"]["verdict"], "exploit-likely");
    assert!(!saved["capabilities"].as_array().unwrap().is_empty());
    assert!(saved["signals"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["pid"] == pid));
}
#[test]
#[ignore = "requires local macOS Frida instrumentation"]
fn close_kills_only_owned_spawn_and_preserves_attached_process() {
    // /bin/sleep may be protected; use the locally compiled benign probe.
    let f = Fixture::new();
    let argv: Vec<OsString> = vec![
        f.probe().into(),
        f.pdf.clone().into(),
        f.root.path().join("bbox.json").into(),
        "12".into(),
        "0".into(),
        "wait".into(),
    ];
    let monitor = Monitor::new("local").unwrap();
    let mut spawned = monitor.spawn(&argv).unwrap();
    let spawned_pid = spawned.pid;
    spawned.close();
    assert!(!monitor
        .processes()
        .unwrap()
        .iter()
        .any(|p| p.pid == spawned_pid));
    let mut process = Command::new(&argv[0]).args(&argv[1..]).spawn().unwrap();
    let result = monitor.attach(&process.id().to_string());
    if let Ok(mut attached) = result {
        attached.close();
    } else {
        let _ = process.kill();
        let _ = process.wait();
        panic!("attach failed");
    }
    let still_running = process.try_wait().unwrap().is_none();
    let _ = process.kill();
    let _ = process.wait();
    assert!(
        still_running,
        "closing an attached session must not kill its target"
    );
}
