use crate::{
    events::SessionReport,
    static_scan::{tail, StaticResult},
};
use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

pub fn timestamp() -> String {
    Utc::now().to_rfc3339()
}
pub fn stem(kind: &str) -> String {
    format!(
        "{kind}-{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S-%6f"),
        std::process::id()
    )
}
fn display(v: &Value) -> String {
    v.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| v.to_string())
}

pub fn write_report(report: &SessionReport, out: &Path, stem: &str) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out)?;
    let json = out.join(format!("{stem}.session.json"));
    let md = out.join(format!("{stem}.md"));
    std::fs::write(&json, serde_json::to_vec_pretty(report)?)?;
    std::fs::write(&md, render_markdown(report))?;
    Ok((json, md))
}
pub fn render_markdown(report: &SessionReport) -> String {
    let meta = &report.meta;
    let v = &report.verdict;
    let mut md = format!("# hotcell — session {}\n\n**verdict: {}** (score {})\n\n- target: {} (pid {}, device {})\n- window: {} → {}\n- scan status: **{}** (a log verdict is not proof of safety)\n\n## matched signals\n",
        display(&meta["session"]),v.verdict.to_uppercase(),v.score,display(&meta["target"]),display(&meta["pid"]),display(&meta["device"]),
        display(&meta["started"]),display(&meta["ended"]),display(&meta["status"]));
    for m in &v.matches {
        let _ = writeln!(
            md,
            "- `{}` [{}, +{}] — {}",
            m.rule, m.severity, m.weight, m.reason
        );
        if m.detail != serde_json::json!({}) {
            let _ = writeln!(
                md,
                "  - detail: `{}`",
                m.detail.to_string().chars().take(300).collect::<String>()
            );
        }
        if !m.stack.is_empty() {
            let _ = writeln!(
                md,
                "  - stack: {}",
                m.stack
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" → ")
            );
        }
    }
    if !v.chains.is_empty() {
        md.push_str("\n## chains\n");
        for c in &v.chains {
            let _ = writeln!(
                md,
                "- `{}` (+{}): {} (rules: {}, window {}s)",
                c.chain,
                c.weight,
                c.description,
                c.rules_seen.join(", "),
                c.window_s
            );
        }
    }
    if let Some(value) = meta.get("static") {
        md.push_str("\n## static stage (elegant-bouncer)\n");
        if let Ok(s) = serde_json::from_value::<StaticResult>(value.clone()) {
            if s.skipped {
                md.push_str("skipped (--no-static)\n");
            } else if let Some(error) = &s.error {
                let _ = writeln!(
                    md,
                    "{} — {error}",
                    if s.available {
                        "incomplete"
                    } else {
                        "unavailable"
                    }
                );
            } else if s.threats.is_empty() {
                md.push_str("no static findings reported\n");
            }
            for t in &s.threats {
                let _ = writeln!(
                    md,
                    "- THREAT: **{}** ({})",
                    t.name,
                    if t.cves.is_empty() {
                        "n/a".into()
                    } else {
                        t.cves.join(", ")
                    }
                );
            }
            if !s.stdout_tail.is_empty() {
                let _ = writeln!(md, "\n```\n{}\n```", tail(&s.stdout_tail, 1200).trim_end());
            }
        }
    }
    if !report.errors.is_empty() {
        md.push_str("\n## errors\n");
        for e in &report.errors {
            let _ = writeln!(
                md,
                "- {}",
                display(e.pointer("/detail/description").unwrap_or(e))
            );
        }
    }
    md.push_str("\n## capability (hooks resolved)\n");
    let caps = if report.capabilities.is_empty() && report.capability != serde_json::json!({}) {
        vec![&report.capability]
    } else {
        report.capabilities.iter().collect::<Vec<_>>()
    };
    if caps.is_empty() {
        md.push_str("_No runtime capability report received._\n");
    }
    for cap in caps {
        let _ = writeln!(
            md,
            "- process: {} (pid {})",
            display(&cap["proc"]),
            display(&cap["pid"])
        );
        if let Some(hooks) = cap["hooks"].as_array() {
            for h in hooks {
                let name = h.as_str().unwrap_or("?");
                let _ = writeln!(md, "- ok: {name} (calls: {})", display(&cap["hits"][name]));
            }
        }
        if let Some(missing) = cap["missing"].as_array() {
            for m in missing {
                let _ = writeln!(md, "- missing: {}", display(m));
            }
        }
    }
    md
}
pub fn notify(title: &str, body: &str) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let script =
        "on run argv\ndisplay notification (item 1 of argv) with title (item 2 of argv)\nend run";
    std::process::Command::new("osascript")
        .args(["-e", script, body, title])
        .output()
        .is_ok_and(|o| o.status.success())
}
