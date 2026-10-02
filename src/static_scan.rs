//! ELEGANTBOUNCER subprocess contract, including incomplete scans.
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Threat {
    pub name: String,
    pub cves: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StaticResult {
    pub available: bool,
    pub threats: Vec<Threat>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returncode: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub stdout_tail: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub stderr_tail: String,
}
fn known_cves(name: &str) -> Vec<String> {
    let values: &[&str] = match name {
        "FORCEDENTRY" => &["CVE-2021-30860"],
        "BLASTPASS" => &["CVE-2023-4863", "CVE-2023-41064"],
        "TRIANGULATION" => &["CVE-2023-41990"],
        "CVE-2026-32882" => &["CVE-2026-32882", "CVE-2025-68431"],
        "HEIF mask underfill" => &["libheif <= 1.21.2"],
        _ if name.starts_with("CVE-") => return vec![name.into()],
        _ => &[],
    };
    values.iter().map(|s| (*s).into()).collect()
}
pub fn parse_output(stdout: &str, stderr: &str, code: i32) -> StaticResult {
    let ansi = Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").expect("constant regex");
    let cve = Regex::new(r"CVE-\d{4}-\d+").expect("constant regex");
    let mut findings = BTreeMap::new();
    let mut in_summary = false;
    let mut rows = 0;
    for line in ansi.replace_all(stdout, "").lines() {
        if let Some((_, name)) = line.split_once("THREAT found:") {
            let name = name.trim();
            if !name.is_empty() {
                findings.insert(
                    name.to_string(),
                    Threat {
                        name: name.into(),
                        cves: known_cves(name),
                    },
                );
            }
        }
        let parts: Vec<_> = line.trim().split(['│', '|']).map(str::trim).collect();
        let cells = if parts.len() >= 2 {
            &parts[1..parts.len() - 1]
        } else {
            &[]
        };
        if cells == ["name", "cve_ids", "description", "detected"] {
            in_summary = true;
        } else if in_summary && cells.len() == 4 && matches!(cells[3], "Yes" | "No") {
            rows += 1;
            if cells[3] == "Yes" {
                let mut cves: Vec<String> =
                    cve.find_iter(cells[1]).map(|m| m.as_str().into()).collect();
                if cves.is_empty() {
                    cves = known_cves(cells[0]);
                }
                findings.insert(
                    cells[0].to_owned(),
                    Threat {
                        name: cells[0].into(),
                        cves,
                    },
                );
            }
        } else if in_summary && line.trim().starts_with(['╰', '└']) {
            in_summary = false;
        }
    }
    let error = if code != 0 {
        Some(format!("elegantbouncer exited with status {code}"))
    } else if rows == 0 && findings.is_empty() {
        Some("elegantbouncer output contained no recognizable scan results".into())
    } else {
        None
    };
    StaticResult {
        available: true,
        threats: findings.into_values().collect(),
        error,
        returncode: Some(code),
        stdout_tail: tail(stdout, 2000),
        stderr_tail: tail(stderr, 2000),
        ..Default::default()
    }
}
pub fn tail(s: &str, count: usize) -> String {
    s.chars()
        .skip(s.chars().count().saturating_sub(count))
        .collect()
}
pub fn scan(path: &Path, timeout: Duration) -> StaticResult {
    let configured = std::env::var_os("HOTCELL_BOUNCER").filter(|s| !s.is_empty());
    let candidate = configured
        .as_deref()
        .unwrap_or_else(|| "elegantbouncer".as_ref());
    let binary = match which::which(candidate) {
        Ok(p) => p,
        Err(_) => {
            return StaticResult {
                error: Some(if configured.is_some() {
                    format!(
                        "HOTCELL_BOUNCER is not an executable: {}",
                        candidate.to_string_lossy()
                    )
                } else {
                    "elegantbouncer not found on PATH (set HOTCELL_BOUNCER to enable the static stage)".into()
                }),
                ..Default::default()
            }
        }
    };
    scan_with_binary(&binary, path, timeout)
}
pub fn scan_with_binary(binary: &Path, path: &Path, timeout: Duration) -> StaticResult {
    // File-backed capture avoids pipe deadlocks and bounds in-memory output.
    let run = || -> anyhow::Result<StaticResult> {
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        let mut child = Command::new(binary)
            .arg("--scan")
            .arg(path)
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?))
            .spawn()?;
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait()?;
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
        };
        // Summary tables are at the end of output; retain the last 4 MiB.
        fn capture(f: &mut std::fs::File) -> std::io::Result<String> {
            let len = f.metadata()?.len();
            f.seek(SeekFrom::Start(len.saturating_sub(4 * 1024 * 1024)))?;
            let mut bytes = vec![];
            f.read_to_end(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
        let mut result = parse_output(
            &capture(&mut stdout)?,
            &capture(&mut stderr)?,
            status.code().unwrap_or(-1),
        );
        if timed_out {
            result.error = Some(format!(
                "elegantbouncer timed out after {}s",
                timeout.as_secs_f64()
            ));
        }
        Ok(result)
    };
    run().unwrap_or_else(|e| StaticResult {
        available: binary.is_file(),
        error: Some(format!("elegantbouncer failed to run: {e:#}")),
        ..Default::default()
    })
}
