import re
from pathlib import Path

from app.config import settings

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{5,}")
_URL = re.compile(rb"https?://[\x21-\x7e]{4,200}")
_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUSPICIOUS_PATTERNS = [
    (re.compile(rb"powershell(\.exe)?\s+-(enc|e|nop|w hidden|windowstyle hidden)", re.I), "Obfuscated PowerShell invocation"),
    (re.compile(rb"-EncodedCommand", re.I), "PowerShell encoded command"),
    (re.compile(rb"cmd(\.exe)?\s*/c", re.I), "Command shell spawn (cmd /c)"),
    (re.compile(rb"wscript\.shell", re.I), "WScript.Shell automation object"),
    (re.compile(rb"CreateRemoteThread", re.I), "Remote thread injection API"),
    (re.compile(rb"VirtualAlloc(Ex)?", re.I), "Dynamic memory allocation API often used by shellcode loaders"),
    (re.compile(rb"WriteProcessMemory", re.I), "Cross-process memory write API"),
    (re.compile(rb"SetWindowsHookEx", re.I), "Global hook installation (often keylogging)"),
    (re.compile(rb"GetAsyncKeyState", re.I), "Keystroke polling API (keylogger indicator)"),
    (re.compile(rb"RegOpenKey|RegSetValue", re.I), "Registry persistence API"),
    (re.compile(rb"schtasks(\.exe)?\s*/create", re.I), "Scheduled task persistence"),
    (re.compile(rb"reg(\.exe)?\s+add.+\\run", re.I), "Registry Run-key persistence"),
    (re.compile(rb"certutil(\.exe)?\s+-decode", re.I), "Certutil abused as a file decoder"),
    (re.compile(rb"bitsadmin", re.I), "BITS job abused for stealthy downloads"),
    (re.compile(rb"mimikatz", re.I), "Credential-dumping tool reference"),
    (re.compile(rb"vbaProject", re.I), "Embedded VBA macro project"),
    (re.compile(rb"AutoOpen|Document_Open|AutoExec", re.I), "Auto-executing macro entry point"),
    (re.compile(rb"Shell\(", re.I), "Macro/script shell-out call"),
    (re.compile(rb"eval\s*\(", re.I), "Dynamic code evaluation (eval)"),
    (re.compile(rb"base64_decode", re.I), "Base64 decode call (common in obfuscated payloads)"),
    (re.compile(rb"FromBase64String", re.I), ".NET Base64 decode call"),
    (re.compile(rb"DownloadString|DownloadFile|Net\.WebClient", re.I), "Remote payload download primitive"),
    (re.compile(rb"InstallUtil\.exe|regsvr32(\.exe)?\s+/s|rundll32", re.I), "Living-off-the-land binary (LOLBin) reference"),
    (re.compile(rb"taskkill\s+/f", re.I), "Forceful process termination (often disables security tools)"),
    (re.compile(rb"vssadmin\s+delete\s+shadows", re.I), "Volume shadow copy deletion (ransomware indicator)"),
    (re.compile(rb"(curl|wget)\s+.{0,80}\|\s*(sh|bash)", re.I), "Remote script piped directly into a shell interpreter"),
    (re.compile(rb"chmod\s+\+x\s+/tmp", re.I), "Makes a file in /tmp executable, a common dropper pattern"),
    (re.compile(rb"/dev/tcp/", re.I), "Bash TCP device reference, commonly used for reverse shells"),
    (re.compile(rb"nc\s+-e\s+/bin/(sh|bash)", re.I), "Netcat reverse-shell invocation"),
]


def scan_strings(path: Path, max_bytes: int = None) -> dict:
    limit = max_bytes or settings.STRINGS_SCAN_LIMIT_BYTES
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
    except OSError:
        return {"truncated": False, "matches": [], "urls": [], "ips": [], "sample_strings": []}

    truncated = path.stat().st_size > len(data)

    matches = []
    for pattern, description in SUSPICIOUS_PATTERNS:
        m = pattern.search(data)
        if m:
            matches.append({
                "description": description,
                "matched_text": _safe_decode(m.group(0))[:80],
            })

    urls = sorted({_safe_decode(m.group(0)) for m in _URL.finditer(data)})[:15]
    ips = sorted({_safe_decode(m.group(0)) for m in _IPV4.finditer(data)
                  if not m.group(0).startswith((b"0.", b"127.", b"255."))})[:15]

    sample_strings = []
    for m in _PRINTABLE_RUN.finditer(data):
        s = _safe_decode(m.group(0))
        if len(s) >= 6:
            sample_strings.append(s)
        if len(sample_strings) >= 40:
            break

    return {
        "truncated": truncated,
        "matches": matches,
        "urls": urls,
        "ips": ips,
        "sample_strings": sample_strings[:25],
    }


def _safe_decode(b: bytes) -> str:
    return b.decode("ascii", errors="replace")
