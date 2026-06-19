"""
Security helpers. Nothing in this module ever executes, parses-as-code, or
shells out to uploaded content — it only ever touches bytes and filenames.
"""
import re
import unicodedata
import uuid

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._\-]")


def sanitize_filename(raw_name: str, max_length: int = 180) -> str:
    """
    Produce a filename that is safe to display and safe to (separately)
    derive a storage path from. Strips directory components, normalizes
    unicode, removes control / unsafe characters, and bounds the length.
    This value is used for DISPLAY ONLY — actual disk storage uses a
    random UUID name (see build_storage_name) so directory traversal or
    collision tricks in the original name can never reach the filesystem.
    """
    if not raw_name:
        return "unnamed_file"

    # Drop any path component a malicious client might smuggle in
    # (handles both / and \ separators, and leading ../ sequences).
    name = raw_name.replace("\\", "/").split("/")[-1]

    # Normalize unicode and strip control characters.
    name = unicodedata.normalize("NFKC", name)
    name = "".join(ch for ch in name if ch.isprintable())

    name = name.strip().strip(".")
    if not name:
        return "unnamed_file"

    if len(name) > max_length:
        # Preserve the extension when truncating.
        if "." in name:
            stem, ext = name.rsplit(".", 1)
            ext = ext[:16]
            name = stem[: max_length - len(ext) - 1] + "." + ext
        else:
            name = name[:max_length]

    return name


def safe_extension(filename: str) -> str:
    """Return a lower-cased, bounded extension with no path/format trickery."""
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].lower()
    ext = _UNSAFE_CHARS.sub("", ext)
    return ext[:16]


def build_storage_name(extension: str) -> str:
    """
    Random, collision-free name used ON DISK. Never derived from
    user input, which eliminates path traversal / overwrite tricks
    entirely regardless of what the client sends as a filename.
    """
    ext = _UNSAFE_CHARS.sub("", extension.lower())[:16]
    token = uuid.uuid4().hex
    return f"{token}.{ext}" if ext else token


def looks_like_double_extension(original_filename: str) -> bool:
    """
    Heuristic for the classic 'invoice.pdf.exe' social-engineering trick:
    a benign-looking extension immediately followed by an executable one.
    """
    parts = original_filename.lower().split(".")
    if len(parts) < 3:
        return False
    dangerous = {
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "ps1", "msi", "jar", "lnk", "dll", "hta",
    }
    benign = {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
        "png", "gif", "txt", "csv", "zip", "mp3", "mp4", "rar",
    }
    last, second_last = parts[-1], parts[-2]
    return last in dangerous and second_last in benign
