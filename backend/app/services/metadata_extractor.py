"""
Category-aware metadata extraction. Every branch here is read-only static
parsing (struct unpacking, zip central-directory listing, regex over raw
bytes, library-assisted header parsing) — nothing is ever executed,
imported as code, or rendered.
"""
import re
import zipfile
from pathlib import Path
from typing import Any, Dict

from app.services import binary_analyzer

OLE2_MACRO_MARKERS = (b"vbaProject", b"VBA", b"Macros")
PDF_JS_PATTERN = re.compile(rb"/JavaScript|/JS\b")
PDF_OPENACTION_PATTERN = re.compile(rb"/OpenAction")
PDF_LAUNCH_PATTERN = re.compile(rb"/Launch")
PDF_AA_PATTERN = re.compile(rb"/AA\b")

DANGEROUS_ARCHIVE_EXTENSIONS = {
    "exe", "scr", "dll", "com", "pif", "msi", "bat", "cmd", "vbs", "js",
    "ps1", "jar", "lnk", "hta", "wsf",
}


def extract(file_path: Path, category: str, mime_type: str, header: bytes) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}

    if category == "executable":
        if header[:2] == b"MZ":
            data = _read_bounded(file_path, 8 * 1024 * 1024)
            pe = binary_analyzer.parse_pe(data)
            if pe:
                meta["pe"] = pe
        elif header[:4] == b"\x7fELF":
            data = _read_bounded(file_path, 1024 * 1024)
            elf = binary_analyzer.parse_elf(data)
            if elf:
                meta["elf"] = elf

    elif mime_type == "application/x-ole-storage":
        meta["office_legacy"] = _scan_ole2_macros(file_path)

    elif zipfile.is_zipfile(file_path):
        if "officedocument" in mime_type or "ms-word" in mime_type:
            meta["office_ooxml"] = _scan_ooxml_macros(file_path)
        meta["archive"] = _inspect_zip(file_path)

    elif mime_type == "application/pdf":
        meta["pdf"] = _inspect_pdf(file_path)

    elif category == "image":
        meta["image"] = _inspect_image(file_path)

    elif category == "script":
        meta["script"] = _inspect_script(file_path)

    return meta


def _read_bounded(path: Path, limit: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit)


def _scan_ole2_macros(path: Path) -> Dict[str, Any]:
    data = _read_bounded(path, 4 * 1024 * 1024)
    found = [m.decode() for m in OLE2_MACRO_MARKERS if m in data]
    return {
        "has_macros": bool(found),
        "indicators": found,
        "note": "Heuristic byte-pattern match against the OLE2 macro storage; not a full CFB parse.",
    }


def _scan_ooxml_macros(path: Path) -> Dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            macro_files = [n for n in names if "vbaproject" in n.lower() or n.lower().endswith(".bin") and "macro" in n.lower()]
            return {"has_macros": bool(macro_files), "macro_entries": macro_files[:10]}
    except (zipfile.BadZipFile, OSError):
        return {"has_macros": False, "macro_entries": []}


def _inspect_zip(path: Path) -> Dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            total_compressed = sum(i.compress_size for i in infos) or 1
            total_uncompressed = sum(i.file_size for i in infos)
            dangerous_members = [
                i.filename for i in infos
                if i.filename.rsplit(".", 1)[-1].lower() in DANGEROUS_ARCHIVE_EXTENSIONS
            ]
            nested_archives = [
                i.filename for i in infos
                if i.filename.rsplit(".", 1)[-1].lower() in ("zip", "rar", "7z", "jar")
            ]
            return {
                "entry_count": len(infos),
                "compression_ratio": round(total_uncompressed / total_compressed, 1),
                "uncompressed_size": total_uncompressed,
                "dangerous_members": dangerous_members[:15],
                "nested_archives": nested_archives[:10],
                "is_encrypted": any(i.flag_bits & 0x1 for i in infos),
            }
    except (zipfile.BadZipFile, OSError) as e:
        return {"error": str(e)}


def _inspect_pdf(path: Path) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    data = _read_bounded(path, 20 * 1024 * 1024)
    result["has_javascript"] = bool(PDF_JS_PATTERN.search(data))
    result["has_openaction"] = bool(PDF_OPENACTION_PATTERN.search(data))
    result["has_launch_action"] = bool(PDF_LAUNCH_PATTERN.search(data))
    result["has_additional_actions"] = bool(PDF_AA_PATTERN.search(data))
    result["is_encrypted"] = b"/Encrypt" in data

    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=False)
        result["page_count"] = len(reader.pages)
        info = reader.metadata or {}
        result["title"] = str(info.title) if getattr(info, "title", None) else None
        result["author"] = str(info.author) if getattr(info, "author", None) else None
        result["creator"] = str(info.creator) if getattr(info, "creator", None) else None
        result["producer"] = str(info.producer) if getattr(info, "producer", None) else None
    except Exception:
        result["page_count"] = None

    return result


def _inspect_image(path: Path) -> Dict[str, Any]:
    try:
        from PIL import Image
        with Image.open(path) as img:
            width, height = img.size
            exif_present = False
            try:
                exif_present = bool(img.getexif())
            except Exception:
                pass
            return {
                "width": width,
                "height": height,
                "format": img.format,
                "mode": img.mode,
                "has_exif": exif_present,
            }
    except Exception as e:
        return {"error": f"Could not parse image headers: {e}"}


def _inspect_script(path: Path) -> Dict[str, Any]:
    data = _read_bounded(path, 2 * 1024 * 1024)
    line_count = data.count(b"\n") + 1
    first_line = data.split(b"\n", 1)[0][:200].decode("utf-8", errors="replace")
    return {
        "line_count": line_count,
        "first_line": first_line,
        "byte_length": len(data),
    }
