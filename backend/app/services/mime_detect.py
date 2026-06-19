"""
Pure-Python file type sniffing via magic-byte signatures. Deliberately
avoids any dependency on system libmagic so the app behaves identically
on any host. Detection is read-only: it inspects header bytes and, for
zip-based containers, the archive's central directory — it never
extracts, runs, or interprets file contents as code.
"""
import zipfile
from pathlib import Path
from typing import Tuple

# (signature bytes, offset, mime, category, label)
SIGNATURES = [
    (b"MZ", 0, "application/x-msdownload", "executable", "Windows PE (EXE/DLL)"),
    (b"\x7fELF", 0, "application/x-elf", "executable", "ELF binary"),
    (b"\xfe\xed\xfa\xce", 0, "application/x-mach-binary", "executable", "Mach-O binary (32-bit)"),
    (b"\xfe\xed\xfa\xcf", 0, "application/x-mach-binary", "executable", "Mach-O binary (64-bit)"),
    (b"\xcf\xfa\xed\xfe", 0, "application/x-mach-binary", "executable", "Mach-O binary"),
    (b"%PDF-", 0, "application/pdf", "document", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage", "document", "Legacy MS Office (OLE2)"),
    (b"Rar!\x1a\x07", 0, "application/x-rar-compressed", "archive", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed", "archive", "7-Zip archive"),
    (b"\x1f\x8b", 0, "application/gzip", "archive", "GZIP archive"),
    (b"BZh", 0, "application/x-bzip2", "archive", "BZIP2 archive"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png", "image", "PNG image"),
    (b"\xff\xd8\xff", 0, "image/jpeg", "image", "JPEG image"),
    (b"GIF87a", 0, "image/gif", "image", "GIF image"),
    (b"GIF89a", 0, "image/gif", "image", "GIF image"),
    (b"BM", 0, "image/bmp", "image", "BMP image"),
    (b"\x00\x00\x01\x00", 0, "image/x-icon", "image", "ICO icon"),
    (b"%!PS", 0, "application/postscript", "document", "PostScript document"),
    (b"ID3", 0, "audio/mpeg", "other", "MP3 audio (ID3 tag)"),
    (b"\x49\x44\x33", 0, "audio/mpeg", "other", "MP3 audio"),
]

ZIP_SIG = b"PK\x03\x04"
ZIP_EMPTY_SIG = b"PK\x05\x06"

SCRIPT_SHEBANGS = {
    b"#!/bin/sh": "text/x-shellscript",
    b"#!/bin/bash": "text/x-shellscript",
    b"#!/usr/bin/env python": "text/x-python",
    b"#!/usr/bin/python": "text/x-python",
    b"#!/usr/bin/perl": "text/x-perl",
    b"#!/usr/bin/env node": "application/javascript",
}

SCRIPT_EXTENSIONS = {
    "sh": "text/x-shellscript", "bash": "text/x-shellscript",
    "py": "text/x-python", "rb": "text/x-ruby", "pl": "text/x-perl",
    "js": "application/javascript", "vbs": "text/vbscript",
    "ps1": "text/x-powershell", "bat": "application/x-bat",
    "cmd": "application/x-bat", "php": "application/x-httpd-php",
}

OFFICE_OOXML_MARKERS = {
    "word/": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "DOCX (Word)"),
    "xl/": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "XLSX (Excel)"),
    "ppt/": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "PPTX (PowerPoint)"),
}

DANGEROUS_EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "dll", "com", "pif", "msi", "bat", "cmd", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "ps1", "jar", "lnk", "hta", "sys", "drv",
}


def _detect_zip_subtype(path: Path) -> Tuple[str, str, str]:
    """Zip-based containers (Office OOXML, JAR, APK) are told apart by
    listing — never extracting — their central directory entries."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            name_set = set(names)
            if "[Content_Types].xml" in name_set:
                for prefix, (mime, label) in OFFICE_OOXML_MARKERS.items():
                    if any(n.startswith(prefix) for n in names):
                        return mime, "document", label
                return (
                    "application/vnd.openxmlformats-officedocument",
                    "document",
                    "Office Open XML document",
                )
            if "META-INF/MANIFEST.MF" in name_set:
                return "application/java-archive", "archive", "Java archive (JAR)"
            if "AndroidManifest.xml" in name_set:
                return "application/vnd.android.package-archive", "archive", "Android package (APK)"
    except (zipfile.BadZipFile, OSError):
        pass
    return "application/zip", "archive", "ZIP archive"


def detect(header: bytes, file_path: Path, original_filename: str) -> dict:
    """
    Returns: {mime_type, category, label, claimed_extension,
              extension_mismatch (bool)}
    """
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""

    mime, category, label = "application/octet-stream", "other", "Unknown binary data"

    if header[:4] == ZIP_SIG or header[:4] == ZIP_EMPTY_SIG:
        mime, category, label = _detect_zip_subtype(file_path)
    else:
        for sig, offset, sig_mime, sig_cat, sig_label in SIGNATURES:
            if header[offset:offset + len(sig)] == sig:
                mime, category, label = sig_mime, sig_cat, sig_label
                break
        else:
            for shebang, sig_mime in SCRIPT_SHEBANGS.items():
                if header.startswith(shebang):
                    mime, category, label = sig_mime, "script", "Script (shebang detected)"
                    break
            else:
                if _looks_textual(header):
                    if ext in SCRIPT_EXTENSIONS:
                        mime, category = SCRIPT_EXTENSIONS[ext], "script"
                        label = f"Script ({ext})"
                    elif header.lstrip().startswith((b"<?xml", b"<html", b"<!DOCTYPE")):
                        mime, category, label = "text/html", "document", "Markup document"
                    else:
                        mime, category, label = "text/plain", "document", "Plain text"

    extension_mismatch = _check_mismatch(ext, category, mime)

    return {
        "mime_type": mime,
        "category": category,
        "label": label,
        "claimed_extension": ext,
        "extension_mismatch": extension_mismatch,
    }


def _looks_textual(sample: bytes, sample_size: int = 512) -> bool:
    if not sample:
        return False
    chunk = sample[:sample_size]
    if b"\x00" in chunk:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(chunk) > 0.85


_EXT_TO_EXPECTED_CATEGORY = {
    "exe": "executable", "dll": "executable", "scr": "executable", "sys": "executable",
    "pdf": "document", "doc": "document", "docx": "document", "xls": "document",
    "xlsx": "document", "ppt": "document", "pptx": "document", "rtf": "document",
    "zip": "archive", "rar": "archive", "7z": "archive", "gz": "archive", "tar": "archive",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "bmp": "image", "ico": "image",
    "py": "script", "sh": "script", "js": "script", "vbs": "script", "ps1": "script",
    "bat": "script", "cmd": "script", "php": "script",
}


def _check_mismatch(ext: str, detected_category: str, mime: str) -> bool:
    if not ext or ext not in _EXT_TO_EXPECTED_CATEGORY:
        return False
    expected = _EXT_TO_EXPECTED_CATEGORY[ext]
    if expected == detected_category:
        return False
    # text/plain content with a document-ish extension isn't really a mismatch
    if expected == "document" and mime in ("text/plain", "text/html"):
        return False
    return True
