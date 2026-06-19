"""
Heuristic, fully static risk scoring. Every signal here comes from data
already gathered by the other services (hashing, entropy, signature
detection, metadata extraction) — the engine itself never touches the
file again, and nothing it does involves running the sample.

This is intentionally explainable: every point added carries a
human-readable reason that gets surfaced to the analyst, rather than an
opaque single number.
"""
from app.utils.security import looks_like_double_extension

SUSPICIOUS_FILENAME_KEYWORDS = [
    "invoice", "receipt", "payment", "urgent", "free", "gift", "winner",
    "password", "unlock", "crack", "keygen", "patch", "loader", "setup",
    "update_required", "click", "verify_account", "resume", "cv_",
]

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "dll", "com", "pif", "msi", "bat", "cmd", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "ps1", "jar", "lnk", "hta", "sys",
}

MACRO_CAPABLE_EXTENSIONS = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "dotm", "xlsm", "pptm"}


class RiskAssessment:
    def __init__(self):
        self.score = 0
        self.reasons = []  # list of {points, text, severity}

    def add(self, points: int, text: str, severity: str = "medium"):
        if points <= 0:
            return
        self.score += points
        self.reasons.append({"points": points, "text": text, "severity": severity})

    def finalize(self):
        self.score = max(0, min(100, self.score))
        # Highest-impact reasons first.
        self.reasons.sort(key=lambda r: r["points"], reverse=True)
        return self.score


def level_for_score(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def assess(
    *,
    original_filename: str,
    claimed_extension: str,
    category: str,
    mime_type: str,
    file_size: int,
    entropy: float,
    extension_mismatch: bool,
    metadata: dict,
    string_findings: dict,
) -> dict:
    risk = RiskAssessment()
    fname_lower = original_filename.lower()

    # --- Entropy -----------------------------------------------------
    if entropy >= 7.5:
        risk.add(25, f"Very high Shannon entropy ({entropy}/8.0) — consistent with packed, "
                      f"encrypted, or compressed payload data.", "high")
    elif entropy >= 7.0:
        risk.add(15, f"Elevated entropy ({entropy}/8.0), above what plain text or typical "
                      f"uncompressed data exhibits.", "medium")
    elif entropy >= 6.5:
        risk.add(6, f"Mildly elevated entropy ({entropy}/8.0).", "low")

    # --- Extension / naming tricks ------------------------------------
    if extension_mismatch:
        risk.add(30, f"File extension '.{claimed_extension}' does not match the actual "
                      f"detected file type ({mime_type}). This is a common disguise tactic.", "high")

    if looks_like_double_extension(original_filename):
        risk.add(25, "Filename uses a double extension pattern (e.g. 'name.pdf.exe') often "
                      "used to disguise an executable as a document.", "high")

    if any(kw in fname_lower for kw in SUSPICIOUS_FILENAME_KEYWORDS):
        risk.add(8, "Filename contains wording commonly used in social-engineering lures "
                     "(e.g. invoice, urgent, free, crack).", "low")

    if claimed_extension in DANGEROUS_EXTENSIONS:
        risk.add(10, f"File extension '.{claimed_extension}' belongs to a category of "
                      f"extensions Windows will execute directly.", "medium")

    # --- Category baseline --------------------------------------------
    if category == "executable":
        risk.add(12, "File is a native executable/library format.", "low")

    # --- PE-specific -----------------------------------------------------
    pe = metadata.get("pe")
    if pe:
        if not pe.get("has_digital_signature"):
            risk.add(10, "Executable is not digitally signed — unsigned binaries cannot be "
                          "attributed to a verified publisher.", "medium")
        max_sect_entropy = pe.get("max_section_entropy")
        if max_sect_entropy and max_sect_entropy >= 7.4:
            risk.add(20, f"A PE section has very high internal entropy ({max_sect_entropy}/8.0), "
                          f"a strong indicator of runtime packing/obfuscation (e.g. UPX, custom "
                          f"crypters).", "high")
        section_names = {s["name"].strip("\x00").lower() for s in pe.get("sections", [])}
        if section_names & {"upx0", "upx1", "upx2", ".aspack", ".petite"}:
            risk.add(20, "PE section names match known executable packers.", "high")
        if pe.get("number_of_sections", 0) <= 2 and file_size > 4096:
            risk.add(8, "Unusually low section count for a Windows PE file.", "low")

    elf = metadata.get("elf")
    if elf:
        risk.add(5, f"Native {elf.get('format')} binary targeting {elf.get('machine')}.", "low")

    # --- Office macros ---------------------------------------------------
    office_ole = metadata.get("office_legacy")
    office_ooxml = metadata.get("office_ooxml")
    has_macro = (office_ole or {}).get("has_macros") or (office_ooxml or {}).get("has_macros")
    if has_macro:
        risk.add(30, "Document contains embedded VBA macro code. Macros are one of the most "
                      "common initial-access vectors in phishing campaigns.", "high")
    elif claimed_extension in MACRO_CAPABLE_EXTENSIONS and claimed_extension.endswith("m"):
        risk.add(10, "Macro-enabled Office extension used.", "low")

    # --- PDF active content -----------------------------------------------
    pdf = metadata.get("pdf")
    if pdf:
        if pdf.get("has_javascript"):
            risk.add(25, "PDF embeds JavaScript — a frequent vector for exploit delivery or "
                          "redirect chains.", "high")
        if pdf.get("has_launch_action"):
            risk.add(25, "PDF defines a /Launch action capable of spawning external programs "
                          "on open.", "high")
        if pdf.get("has_openaction"):
            risk.add(10, "PDF defines an automatic /OpenAction triggered on document open.", "medium")

    # --- Archive risk -------------------------------------------------
    archive = metadata.get("archive")
    if archive and not archive.get("error"):
        if archive.get("dangerous_members"):
            risk.add(25, f"Archive contains {len(archive['dangerous_members'])} executable/script "
                          f"member(s): {', '.join(archive['dangerous_members'][:3])}.", "high")
        if archive.get("compression_ratio", 1) >= 100:
            risk.add(20, f"Extreme compression ratio ({archive['compression_ratio']}x) — "
                          f"characteristic of decompression-bomb style archives.", "high")
        if archive.get("is_encrypted"):
            risk.add(12, "Archive contents are password-protected, preventing content "
                          "inspection and frequently used to evade scanners.", "medium")
        if archive.get("nested_archives"):
            risk.add(8, "Archive contains nested archive(s), a common evasion layering technique.", "low")

    # --- Suspicious strings ------------------------------------------
    matches = string_findings.get("matches", [])
    if matches:
        points = min(25, 6 * len(matches))
        sample = "; ".join(m["description"] for m in matches[:3])
        risk.add(points, f"Static string scan matched {len(matches)} known attacker-tooling "
                          f"pattern(s): {sample}.", "high" if points >= 15 else "medium")

    # --- Size extremes --------------------------------------------------
    if category == "executable" and 0 < file_size < 1024:
        risk.add(10, "Executable is implausibly small for legitimate compiled code, "
                      "consistent with a dropper/stub.", "medium")
    if file_size == 0:
        risk.add(5, "File is empty (0 bytes).", "low")
    if file_size > 500 * 1024 * 1024:
        risk.add(5, "File is unusually large (>500 MB), which can be used to evade size-limited "
                     "scanning pipelines.", "low")

    score = risk.finalize()
    level = level_for_score(score)

    recommendations = _build_recommendations(level, risk.reasons, category, metadata)

    return {
        "score": score,
        "level": level,
        "reasons": risk.reasons or [{"points": 0, "text": "No heuristic risk indicators were triggered.", "severity": "low"}],
        "recommendations": recommendations,
    }


def _build_recommendations(level: str, reasons: list, category: str, metadata: dict) -> list:
    recs = []

    if level in ("Critical", "High"):
        recs.append("Do not open or execute this file on any production or unisolated system.")
        recs.append("Detonate in an isolated sandbox (e.g. CAPEv2, Joe Sandbox, ANY.RUN) before "
                     "drawing further conclusions.")
    elif level == "Medium":
        recs.append("Treat with caution — verify provenance with the sender/source before opening.")
    else:
        recs.append("No strong static indicators were found, but static analysis cannot prove a "
                     "file is benign.")

    recs.append("Cross-reference the SHA-256 hash against threat intelligence sources "
                "(VirusTotal, Hybrid Analysis, AlienVault OTX).")

    if any("macro" in r["text"].lower() for r in reasons):
        recs.append("Do not enable macros/editing when opening this document.")
    if any("javascript" in r["text"].lower() or "launch" in r["text"].lower() for r in reasons):
        recs.append("Open PDF only in a reader with JavaScript and external actions disabled.")
    if category == "executable":
        recs.append("Verify the digital signature (if present) and check the publisher against "
                     "an allow-list before deployment.")
    if metadata.get("archive", {}).get("dangerous_members"):
        recs.append("Do not extract this archive on a host that will auto-run its contents.")

    recs.append("Retain this report and the original sample hash for incident-response records.")
    return recs
