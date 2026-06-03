"""
Explicit command-line and process-context features for LOLBin ML (no training).

Author:  Daniel Jeremiah
GitHub:  https://github.com/daniyyell-dev
LinkedIn: https://www.linkedin.com/in/daniel-jeremiah/
Project: WinLOLBIN-GT — https://github.com/daniyyell-dev/WinLOLBIN-GT-dataset

Normalization and flags follow common practice in LOLBin / cmdline detection literature:
hand-crafted structure stats, suspicious-token booleans, parent-child context.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, Mapping, Optional

# --- Normalization (mask volatile tokens before counting / dedup) ---

_RE_WINDOWS_PATH = re.compile(
    r"(?i)([a-z]:\\(?:[^\\/\s\"'|;&]+\\)*[^\\/\s\"'|;&]*)"
)
_RE_UNC_PATH = re.compile(r"\\\\[^\s\"'|;&]+")
_RE_URL = re.compile(
    r"(?i)\b(?:https?|ftp|ms-appinstaller|script):[^\s\"'|;&]+"
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_RE_USER = re.compile(r"(?i)\b[a-z0-9_.-]+\\[a-z0-9_.$-]+\b")
_RE_GUID = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
_RE_HEX_HASH = re.compile(r"\b[0-9a-f]{32,64}\b", re.I)

# Suspicious substrings (case-insensitive search on lowercased cmdline)
_SUSPICIOUS_FLAGS: tuple[tuple[str, str], ...] = (
    ("flag_enc", r"-enc\b|-encodedcommand\b|-ec\b"),
    ("flag_ep_bypass", r"-ep\s+bypass|-executionpolicy\s+bypass"),
    ("flag_hidden_window", r"-w\s+hidden|-windowstyle\s+hidden"),
    ("flag_nop", r"-nop\b|-noni\b"),
    ("flag_iex", r"\biex\b|invoke-expression"),
    ("flag_downloadstring", r"downloadstring"),
    ("flag_invoke_expression", r"invoke-expression"),
    ("flag_frombase64", r"frombase64string|::frombase64"),
    ("flag_regsvr32_script", r"regsvr32.*(/i:|scrobj)"),
    ("flag_mshta", r"\bmshta\b|mshta\.exe"),
    ("flag_certutil_urlcache", r"certutil.*-urlcache"),
    ("flag_certutil_encode", r"certutil.*(-encode|-decode)"),
    ("flag_bitsadmin", r"\bbitsadmin\b"),
    ("flag_mimikatz", r"mimikatz|invoke-mimikatz"),
    ("flag_remote_file", r"downloadstring|iwr\s|invoke-webrequest|wget\s|curl\s"),
    ("flag_schtasks_remote", r"schtasks.*/s\s"),
    ("flag_wmic_remote", r"wmic.*/node:|winrm\s"),
    ("flag_rundll32_js", r"rundll32.*javascript:"),
    ("flag_msbuild", r"\bmsbuild\.exe\b"),
    ("flag_cmstp", r"\bcmstp\.exe\b"),
    ("flag_adsi", r"script:\s*https?://"),
    ("flag_cmd_slash_c", r"\bcmd(\.exe)?\s+/c\b"),
)

_SUSPICIOUS_COMPILED = tuple(
    (name, re.compile(pat, re.I)) for name, pat in _SUSPICIOUS_FLAGS
)

_INTEGRITY_ORDINAL = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "system": 3,
}

# Office / script parents often seen in LOLBin chains
_SUSPICIOUS_PARENTS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
    }
)

FEATURE_COLUMN_NAMES: tuple[str, ...] = (
    "cmd_len",
    "cmd_token_count",
    "cmd_entropy",
    "cmd_avg_token_len",
    "cmd_pipe_count",
    "cmd_amp_count",
    "cmd_semicolon_count",
    "cmd_redirect_count",
    "cmd_backtick_count",
    "cmd_quote_count",
    "cmd_percent_count",
    "cmd_dash_count",
    "cmd_url_token_count",
    "cmd_path_token_count",
    "cmd_ip_token_count",
    "cmd_b64_token_count",
    "flag_enc",
    "flag_ep_bypass",
    "flag_hidden_window",
    "flag_nop",
    "flag_iex",
    "flag_downloadstring",
    "flag_invoke_expression",
    "flag_frombase64",
    "flag_regsvr32_script",
    "flag_mshta",
    "flag_certutil_urlcache",
    "flag_certutil_encode",
    "flag_bitsadmin",
    "flag_mimikatz",
    "flag_remote_file",
    "flag_schtasks_remote",
    "flag_wmic_remote",
    "flag_rundll32_js",
    "flag_msbuild",
    "flag_cmstp",
    "flag_adsi",
    "flag_cmd_slash_c",
    "process_is_powershell",
    "process_is_cmd",
    "process_is_script_host",
    "process_is_rundll32",
    "path_in_system32",
    "path_in_syswow64",
    "path_in_temp",
    "path_in_users",
    "path_in_programdata",
    "parent_known",
    "parent_is_office",
    "parent_is_explorer",
    "parent_child_suspicious",
    "signed_true",
    "network_connection_true",
    "has_destination",
    "integrity_ordinal",
)


def basename_exe(name: str) -> str:
    s = (name or "").strip().strip('"').replace("/", "\\")
    if "\\" in s:
        s = s.rsplit("\\", 1)[-1]
    return s.lower() if s else ""


def infer_process_name(command_line: str, lolbin_binary: str = "") -> str:
    if lolbin_binary:
        b = basename_exe(lolbin_binary)
        if b:
            return b
    cmd = (command_line or "").strip()
    if not cmd:
        return "unknown.exe"
    first = cmd.split(maxsplit=1)[0].strip('"') if cmd.split() else ""
    if re.search(r"\.(exe|bat|cmd|ps1|vbs|js|msc|msi|dll|com)\b", first, re.I):
        return basename_exe(first)
    if "\\" in first or "/" in first:
        return basename_exe(first)
    return first.lower() if first else "unknown.exe"


def normalize_command_line(command_line: str) -> str:
    """Mask paths, URLs, IPs, users, long base64 for stable features and dedup."""
    s = (command_line or "").strip()
    if not s:
        return ""
    s = _RE_URL.sub("<URL>", s)
    s = _RE_UNC_PATH.sub("<PATH>", s)
    s = _RE_WINDOWS_PATH.sub("<PATH>", s)
    s = _RE_IPV4.sub("<IP>", s)
    s = _RE_B64_RUN.sub("<B64>", s)
    s = _RE_USER.sub("<USER>", s)
    s = _RE_GUID.sub("<GUID>", s)
    s = _RE_HEX_HASH.sub("<HASH>", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 6)


def build_model_text(
    process_name: str,
    parent_process: str,
    command_line: str,
    *,
    normalized: bool = True,
) -> str:
    cmd = normalize_command_line(command_line) if normalized else (command_line or "")
    proc = basename_exe(process_name) or "unknown.exe"
    parent = basename_exe(parent_process) if parent_process else ""
    if parent:
        return f"proc={proc} | parent={parent} | cmd={cmd}"
    return f"proc={proc} | cmd={cmd}"


def dedup_key(label: int, process_name: str, command_line: str) -> str:
    proc = basename_exe(process_name) or "unknown.exe"
    norm = normalize_command_line(command_line).lower()
    raw = f"{label}|{proc}|{norm}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def record_id_from_key(key: str) -> str:
    return key[:16]


def _count_char(text: str, ch: str) -> int:
    return text.count(ch)


def _count_tokens_after_norm(normalized: str) -> Dict[str, int]:
    return {
        "cmd_url_token_count": normalized.count("<URL>"),
        "cmd_path_token_count": normalized.count("<PATH>"),
        "cmd_ip_token_count": normalized.count("<IP>"),
        "cmd_b64_token_count": normalized.count("<B64>"),
    }


def extract_features(row: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Build ML-ready feature dict from a canonical row mapping.

    Expected keys (all optional except command_line + label):
      command_line, process_name, parent_process, process_path,
      signed, network_connection, destination, integrity_level
    """
    cmd_raw = str(row.get("command_line") or "")
    cmd_norm = normalize_command_line(cmd_raw)
    cmd_lower = cmd_norm.lower()
    cmd_raw_lower = cmd_raw.lower()

    tokens = cmd_norm.split() if cmd_norm else []
    token_count = len(tokens)
    avg_tok = (sum(len(t) for t in tokens) / token_count) if token_count else 0.0

    proc = basename_exe(str(row.get("process_name") or "")) or infer_process_name(
        cmd_raw, str(row.get("lolbin_binary") or "")
    )
    parent = basename_exe(str(row.get("parent_process") or ""))
    path = str(row.get("process_path") or "").lower()

    counts = _count_tokens_after_norm(cmd_norm)
    feats: Dict[str, Any] = {
        "cmd_len": len(cmd_norm),
        "cmd_token_count": token_count,
        "cmd_entropy": shannon_entropy(cmd_norm),
        "cmd_avg_token_len": round(avg_tok, 4),
        "cmd_pipe_count": _count_char(cmd_raw, "|"),
        "cmd_amp_count": _count_char(cmd_raw, "&"),
        "cmd_semicolon_count": _count_char(cmd_raw, ";"),
        "cmd_redirect_count": _count_char(cmd_raw, ">") + _count_char(cmd_raw, "<"),
        "cmd_backtick_count": _count_char(cmd_raw, "`"),
        "cmd_quote_count": _count_char(cmd_raw, '"') + _count_char(cmd_raw, "'"),
        "cmd_percent_count": _count_char(cmd_raw, "%"),
        "cmd_dash_count": _count_char(cmd_raw, "-"),
        **counts,
    }

    for name, rx in _SUSPICIOUS_COMPILED:
        feats[name] = int(bool(rx.search(cmd_raw_lower) or rx.search(cmd_lower)))

    feats["process_is_powershell"] = int(proc in ("powershell.exe", "pwsh.exe"))
    feats["process_is_cmd"] = int(proc in ("cmd.exe",))
    feats["process_is_script_host"] = int(proc in ("wscript.exe", "cscript.exe", "mshta.exe"))
    feats["process_is_rundll32"] = int(proc == "rundll32.exe")

    feats["path_in_system32"] = int("system32" in path or "\\system32\\" in cmd_raw_lower)
    feats["path_in_syswow64"] = int("syswow64" in path or "syswow64" in cmd_raw_lower)
    feats["path_in_temp"] = int(
        any(x in path or x in cmd_raw_lower for x in ("\\temp\\", "\\tmp\\", "appdata\\local\\temp"))
    )
    feats["path_in_users"] = int("\\users\\" in path or "\\users\\" in cmd_raw_lower)
    feats["path_in_programdata"] = int("programdata" in path or "programdata" in cmd_raw_lower)

    feats["parent_known"] = int(bool(parent))
    feats["parent_is_office"] = int(parent in _SUSPICIOUS_PARENTS)
    feats["parent_is_explorer"] = int(parent == "explorer.exe")
    office_to_shell = parent in _SUSPICIOUS_PARENTS and proc in (
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    )
    feats["parent_child_suspicious"] = int(office_to_shell)

    signed = str(row.get("signed") or "").strip().lower()
    feats["signed_true"] = int(signed in ("true", "1", "yes"))

    net = str(row.get("network_connection") or "").strip().lower()
    feats["network_connection_true"] = int(net in ("true", "1", "yes"))

    dest = str(row.get("destination") or "").strip()
    feats["has_destination"] = int(bool(dest))

    integrity = str(row.get("integrity_level") or "medium").strip().lower()
    feats["integrity_ordinal"] = _INTEGRITY_ORDINAL.get(integrity, 1)

    return feats


def features_to_csv_cells(feats: Mapping[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in FEATURE_COLUMN_NAMES:
        v = feats.get(name, 0)
        if isinstance(v, float):
            out[name] = f"{v:.6f}".rstrip("0").rstrip(".")
        else:
            out[name] = str(int(v) if isinstance(v, bool) else v)
    return out


def enrich_row(row: Mapping[str, Any]) -> Dict[str, str]:
    """Full ML-ready record: metadata + text fields + feature columns."""
    label = int(row.get("label") if row.get("label") is not None else 0)
    cmd = str(row.get("command_line") or "")
    proc = str(row.get("process_name") or "") or infer_process_name(
        cmd, str(row.get("lolbin_binary") or "")
    )
    parent = str(row.get("parent_process") or "")
    key = dedup_key(label, proc, cmd)

    feats = extract_features(row)
    feat_cells = features_to_csv_cells(feats)

    out: Dict[str, str] = {
        "record_id": record_id_from_key(key),
        "dedup_key": key,
        "dataset_origin": str(row.get("dataset_origin") or ""),
        "process_name": basename_exe(proc) or proc,
        "parent_process": basename_exe(parent),
        "command_line": cmd[:8192],
        "cmd_normalized": normalize_command_line(cmd)[:8192],
        "model_text": build_model_text(proc, parent, cmd)[:8192],
        "mitre_technique": str(row.get("mitre_technique") or ""),
        "command_source": str(row.get("command_source") or ""),
        "rule_category": str(row.get("rule_category") or ""),
    }
    out.update(feat_cells)
    out["label"] = str(label)
    return out


ML_FEATURE_CSV_COLUMNS: tuple[str, ...] = (
    "record_id",
    "dedup_key",
    "dataset_origin",
    "process_name",
    "parent_process",
    "command_line",
    "cmd_normalized",
    "model_text",
    "mitre_technique",
    "command_source",
    "rule_category",
    *FEATURE_COLUMN_NAMES,
    "label",
)
