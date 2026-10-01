"""Static analysis stage — optional integration with msuiche/elegant-bouncer.

Layer split:
  - elegant-bouncer: static structural detection — what the FILE is
    (FORCEDENTRY, BLASTPASS, TRIANGULATION, DNG/libheif shapes...). No
    execution required; works on backups and archives.
  - hotcell: runtime behavioral detection — what the PROCESS does with the
    file (zero-day behavior, in-process Frida agent).

`hotcell scan` fuses both: stage 1 static (this module, if the binary is
available), stage 2 dynamic (qlmanage under the agent). The binary is
optional — without it the static stage is skipped and the capability is
reported honestly, matching the project's fail-open/noise-aware philosophy.

elegant-bouncer v0.2 has no JSON output yet; this adapter parses the stable
`THREAT found: <NAME>` lines and falls back to the known name→CVE table.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Dict, List, Union

BOUNCER_ENV = "HOTCELL_BOUNCER"
DEFAULT_TIMEOUT_S = 120

THREAT_LINE = re.compile(r"THREAT found:\s*(.+?)\s*$")

# name → CVE table from the bouncer README (support table, 2026-09)
KNOWN_CVES: Dict[str, List[str]] = {
    "FORCEDENTRY": ["CVE-2021-30860"],
    "BLASTPASS": ["CVE-2023-4863", "CVE-2023-41064"],
    "TRIANGULATION": ["CVE-2023-41990"],
    "CVE-2025-43300": ["CVE-2025-43300"],
    "CVE-2025-21043": ["CVE-2025-21043"],
    "CVE-2026-32741": ["CVE-2026-32741"],
    "HEIF mask underfill": ["libheif <= 1.21.2"],
    "CVE-2026-32882": ["CVE-2026-32882", "CVE-2025-68431"],
    "CVE-2026-84383": ["CVE-2026-84383"],
}


def find_binary() -> Union[str, None]:
    """Locate the elegantbouncer binary (HOTCELL_BOUNCER overrides PATH)."""
    cand = os.environ.get(BOUNCER_ENV) or "elegantbouncer"
    return shutil.which(cand)


def scan_file(path: Union[str, os.PathLike], timeout_s: int = DEFAULT_TIMEOUT_S) -> Dict:
    """Run `elegantbouncer --scan <file>`. Never raises; degrades gracefully.

    Returns {"available": bool, "threats": [{"name", "cves"}...],
             optional "error", "returncode", "stdout_tail"}.
    """
    out: Dict = {"available": False, "threats": []}
    binary = find_binary()
    if not binary:
        out["error"] = ("elegantbouncer not found on PATH "
                        f"(set {BOUNCER_ENV} to the binary to enable the static stage)")
        return out
    try:
        proc = subprocess.run(
            [binary, "--scan", str(path)],
            capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        out["available"] = True
        out["error"] = f"elegantbouncer timed out after {timeout_s}s"
        return out
    except OSError as e:
        out["error"] = f"elegantbouncer failed to run: {e}"
        return out

    out["available"] = True
    out["returncode"] = proc.returncode
    if proc.stdout:
        out["stdout_tail"] = proc.stdout[-2000:]
    for line in proc.stdout.splitlines():
        m = THREAT_LINE.search(line)
        if m:
            name = m.group(1).strip()
            out["threats"].append({"name": name, "cves": KNOWN_CVES.get(name, [])})
    return out
