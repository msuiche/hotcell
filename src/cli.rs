use crate::{
    events::{RuleEngine, SessionReport, Signal},
    report, static_scan,
};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Parser)]
#[command(
    version,
    about = "Runtime monitor for Apple document and image pipelines"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// List candidate renderer processes.
    List(Common),
    /// Attach to live processes (does not follow child or XPC processes).
    Watch {
        #[arg(long, required = true)]
        target: Vec<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Run a static and/or monitored native rendering scan.
    Scan {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, conflicts_with = "no_static")]
        static_only: bool,
        #[arg(long)]
        no_static: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Recalculate a saved session's verdict from its raw signals.
    Report {
        #[arg(long)]
        session: PathBuf,
        #[command(flatten)]
        common: Common,
    },
    #[command(name = "__render", hide = true)]
    Render { input: PathBuf, output: PathBuf },
}
#[derive(Clone, Copy, ValueEnum)]
enum Device {
    Local,
    Usb,
}
impl Device {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Usb => "usb",
        }
    }
}
#[derive(Args)]
struct Common {
    #[arg(long, value_enum, default_value = "local")]
    device: Device,
    /// Override the embedded YAML rule pack.
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long, default_value = "report")]
    out: PathBuf,
    /// Maximum monitoring duration in minutes.
    #[arg(long, default_value = "10", value_parser = minutes)]
    minutes: Duration,
    #[arg(long)]
    notify: bool,
}
fn minutes(value: &str) -> std::result::Result<Duration, String> {
    let n: f64 = value
        .parse()
        .map_err(|_| "minutes must be a positive finite number")?;
    if !n.is_finite() || n <= 0.0 {
        return Err("minutes must be a positive finite number".into());
    }
    let duration = Duration::try_from_secs_f64(n * 60.0).map_err(|_| "minutes is too large")?;
    if duration.is_zero() {
        return Err("minutes is too small".into());
    }
    Ok(duration)
}
pub fn run() -> Result<i32> {
    match Cli::parse().command {
        Command::List(common) => list(&common),
        Command::Watch { target, common } => watch(&target, &common),
        Command::Scan {
            file,
            static_only,
            no_static,
            common,
        } => scan(&file, static_only, no_static, &common),
        Command::Report { session, common } => replay(&session, &common),
        Command::Render { input, output } => Ok(crate::renderer::run(&input, &output)),
    }
}
fn error(engine: &mut RuleEngine, description: impl ToString) {
    eprintln!("error: {}", description.to_string());
    engine.error(description);
}
fn meta(kind: &str, target: &str, common: &Common) -> Value {
    json!({"session":report::stem(kind), "target":target, "pid":"-", "device":common.device.as_str(), "started":report::timestamp()})
}
fn finish(engine: &RuleEngine, mut meta: Value, common: &Common) -> Result<i32> {
    meta["ended"] = json!(report::timestamp());
    meta["signals"] = json!(engine.signals.len());
    meta["status"] = json!(if engine.errors.is_empty() {
        "complete"
    } else {
        "incomplete"
    });
    let session = engine.session(meta);
    let (_, md) = report::write_report(
        &session,
        &common.out,
        session.meta["session"]
            .as_str()
            .context("missing session name")?,
    )?;
    println!(
        "[*] status: {}; verdict: {} (score {})",
        session.meta["status"].as_str().unwrap(),
        session.verdict.verdict.to_uppercase(),
        session.verdict.score
    );
    for chain in &session.verdict.chains {
        println!(
            "    chain: {} (+{}) — {}",
            chain.chain, chain.weight, chain.description
        );
    }
    println!("[*] report: {}", md.display());
    if common.notify {
        report::notify(
            &format!(
                "hotcell: {} / {}",
                session.meta["status"].as_str().unwrap(),
                session.verdict.verdict
            ),
            &format!(
                "score {} — {}",
                session.verdict.score,
                session.meta["target"].as_str().unwrap_or("")
            ),
        );
    }
    Ok(if engine.errors.is_empty() { 0 } else { 2 })
}
fn replay(path: &Path, common: &Common) -> Result<i32> {
    let saved: Value = serde_json::from_slice(&std::fs::read(path).context("read session")?)
        .context("parse session JSON")?;
    if saved.get("signals").is_none() {
        bail!("session has no raw signals; this legacy report cannot be replayed faithfully");
    }
    let saved: SessionReport = serde_json::from_value(saved).context("invalid session report")?;
    let mut engine = RuleEngine::load(common.rules.as_deref())?;
    engine.replay(&saved)?;
    let report = engine.session(saved.meta);
    let (_, md) = report::write_report(&report, &common.out, &report::stem("replay"))?;
    println!(
        "verdict: {} (score {}) → {}",
        report.verdict.verdict.to_uppercase(),
        report.verdict.score,
        md.display()
    );
    Ok(if engine.errors.is_empty() { 0 } else { 2 })
}
fn scan(file: &Path, static_only: bool, no_static: bool, common: &Common) -> Result<i32> {
    if !file.is_file() {
        bail!("no such file: {}", file.display());
    }
    if !static_only && matches!(common.device, Device::Usb) {
        bail!("file scanning runs on macOS; use watch --device usb for iOS");
    }
    let file = file.canonicalize()?;
    let mut engine = RuleEngine::load(common.rules.as_deref())?;
    let mut meta = meta(
        "scan",
        &format!(
            "scan:{}",
            file.file_name().unwrap_or_default().to_string_lossy()
        ),
        common,
    );
    let result = if no_static {
        static_scan::StaticResult {
            skipped: true,
            ..Default::default()
        }
    } else {
        static_scan::scan(&file, Duration::from_secs(120))
    };
    for threat in &result.threats {
        engine.process(Signal::from_payload(
            json!({"rule":"bouncer-static-hit", "severity":"high",
            "detail":{"threat":threat.name, "cves":threat.cves, "stage":"static"}}),
        )?);
        println!("  [static] THREAT found: {}", threat.name);
    }
    if let Some(message) = &result.error {
        println!(
            "[*] static stage: {} — {message}",
            if result.available {
                "incomplete"
            } else {
                "unavailable"
            }
        );
        if result.available || static_only {
            error(&mut engine, message);
        }
    } else if !result.skipped {
        println!(
            "[*] static stage: {}",
            if result.threats.is_empty() {
                "no findings reported"
            } else {
                "threats found"
            }
        );
    }
    meta["static"] = json!(result);
    if static_only {
        return finish(&engine, meta, common);
    }
    runtime_scan(&file, engine, meta, common)
}

#[cfg(feature = "live")]
fn list(common: &Common) -> Result<i32> {
    let monitor = crate::live::Monitor::new(common.device.as_str())?;
    let processes = monitor.processes()?;
    println!("{:>7}  {:38} TARGET", "PID", "NAME");
    for p in &processes {
        if crate::targets::matches(&p.name, matches!(common.device, Device::Usb)) {
            println!(
                "{:>7}  {:38} ★",
                p.pid,
                p.name.chars().take(38).collect::<String>()
            );
        }
    }
    println!("({} processes total)", processes.len());
    Ok(0)
}
#[cfg(not(feature = "live"))]
fn list(_: &Common) -> Result<i32> {
    bail!("live monitoring is disabled; rebuild with the default live feature")
}

#[cfg(feature = "live")]
fn drain(monitor: &crate::live::Monitor, engine: &mut RuleEngine) {
    for payload in monitor.drain() {
        let matches_before = engine.matches.len();
        let errors_before = engine.errors.len();
        if let Err(e) = engine.ingest(payload) {
            error(engine, e);
            continue;
        }
        for matched in &engine.matches[matches_before..] {
            println!(
                "  [signal] {} (+{}) — {}",
                matched.rule, matched.weight, matched.reason
            );
        }
        for failure in &engine.errors[errors_before..] {
            eprintln!(
                "  [agent-error] {}",
                failure
                    .pointer("/detail/description")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown agent error")
            );
        }
    }
}
#[cfg(feature = "live")]
fn watch(targets: &[String], common: &Common) -> Result<i32> {
    let mut engine = RuleEngine::load(common.rules.as_deref())?;
    let mut meta = meta("watch", &targets.join(","), common);
    let monitor = match crate::live::Monitor::new(common.device.as_str()) {
        Ok(m) => m,
        Err(e) => {
            error(&mut engine, e);
            return finish(&engine, meta, common);
        }
    };
    let mut sessions = vec![];
    for target in targets {
        match monitor.attach(target) {
            Ok(s) => sessions.push(s),
            Err(e) => {
                for s in &mut sessions {
                    s.close();
                }
                drain(&monitor, &mut engine);
                error(&mut engine, e);
                return finish(&engine, meta, common);
            }
        }
    }
    meta["pid"] = json!(sessions.iter().map(|s| s.pid).collect::<Vec<_>>());
    monitor_sessions(&monitor, &mut sessions, engine, meta, false, common)
}
#[cfg(not(feature = "live"))]
fn watch(targets: &[String], common: &Common) -> Result<i32> {
    let mut engine = RuleEngine::load(common.rules.as_deref())?;
    error(
        &mut engine,
        "live monitoring is disabled; rebuild with the default live feature",
    );
    finish(&engine, meta("watch", &targets.join(","), common), common)
}
#[cfg(feature = "live")]
fn runtime_scan(
    file: &Path,
    mut engine: RuleEngine,
    mut meta: Value,
    common: &Common,
) -> Result<i32> {
    if !cfg!(target_os = "macos") {
        error(
            &mut engine,
            "runtime file scans require macOS; use --static-only",
        );
        return finish(&engine, meta, common);
    }
    std::fs::create_dir_all(&common.out)?;
    let preview = common
        .out
        .canonicalize()?
        .join(format!("{}.png", meta["session"].as_str().unwrap()));
    meta["renderer"] = json!("CoreGraphics/ImageIO in-process Rust helper");
    meta["preview"] = json!(preview);
    let monitor = match crate::live::Monitor::new(common.device.as_str()) {
        Ok(m) => m,
        Err(e) => {
            error(&mut engine, format!("cannot start renderer: {e:#}"));
            return finish(&engine, meta, common);
        }
    };
    let argv = [
        std::env::current_exe()?.into_os_string(),
        "__render".into(),
        file.as_os_str().into(),
        preview.into_os_string(),
    ];
    let session = match monitor.spawn(&argv) {
        Ok(s) => s,
        Err(e) => {
            drain(&monitor, &mut engine);
            error(&mut engine, format!("cannot start renderer: {e:#}"));
            return finish(&engine, meta, common);
        }
    };
    meta["pid"] = json!(session.pid);
    monitor_sessions(&monitor, &mut [session], engine, meta, true, common)
}
#[cfg(not(feature = "live"))]
fn runtime_scan(_: &Path, mut engine: RuleEngine, meta: Value, common: &Common) -> Result<i32> {
    error(
        &mut engine,
        "live monitoring is disabled; rebuild with the default live feature",
    );
    finish(&engine, meta, common)
}
#[cfg(feature = "live")]
fn monitor_sessions(
    monitor: &crate::live::Monitor,
    sessions: &mut [crate::live::Session],
    mut engine: RuleEngine,
    mut meta: Value,
    scan: bool,
    common: &Common,
) -> Result<i32> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let interrupted = Arc::new(AtomicBool::new(false));
    let stop = interrupted.clone();
    ctrlc::set_handler(move || {
        stop.store(true, Ordering::Relaxed);
    })
    .context("install interrupt handler")?;
    println!(
        "[*] monitoring for up to {} min — Ctrl-C to stop early",
        common.minutes.as_secs_f64() / 60.0
    );
    let start = std::time::Instant::now();
    loop {
        drain(monitor, &mut engine);
        if sessions.iter().all(|s| s.detached())
            || start.elapsed() >= common.minutes
            || interrupted.load(Ordering::Relaxed)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    for s in sessions.iter() {
        match s.capability() {
            Ok(cap) => engine.record_capability(cap),
            Err(e) => error(&mut engine, e),
        }
    }
    drain(monitor, &mut engine);
    if scan {
        if interrupted.load(Ordering::Relaxed) {
            error(&mut engine, "scan interrupted before completion");
        }
        if !sessions.iter().all(|s| s.detached()) {
            error(
                &mut engine,
                "renderer did not finish before the scan deadline",
            );
        }
        if !engine
            .signals
            .iter()
            .any(|s| matches!(s.rule.as_str(), "pdf-rendered" | "image-decoded"))
        {
            error(
                &mut engine,
                "no document rendering observed in the instrumented process",
            );
        }
        if !engine.signals.iter().any(|s| {
            s.rule == "render-complete"
                && s.detail["status"] == 0
                && s.detail["count"].as_u64().unwrap_or(0) > 0
        }) {
            error(
                &mut engine,
                "renderer did not confirm successful completion",
            );
        }
    } else if interrupted.load(Ordering::Relaxed) {
        meta["stopped_by_user"] = json!(true);
    }
    for s in sessions {
        s.close();
    }
    drain(monitor, &mut engine);
    finish(&engine, meta, common)
}
