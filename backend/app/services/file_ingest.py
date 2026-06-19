"""
Single-pass file ingestion: streams an upload to disk in fixed-size chunks
while simultaneously feeding SHA-256 / SHA-1 / MD5 digests and a byte
frequency table (for Shannon entropy). The file is never read fully into
memory and never executed, imported, or shelled out to.
"""
import hashlib
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024  # 1 MB


class UploadTooLarge(Exception):
    pass


@dataclass
class IngestResult:
    sha256: str
    sha1: str
    md5: str
    size: int
    entropy: float
    header: bytes  # first chunk, used for signature-based MIME sniffing
    byte_histogram: list = field(default_factory=list)


def shannon_entropy(histogram: list, total: int) -> float:
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in histogram:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def ingest_to_disk(source: BinaryIO, dest_path: Path, max_bytes: int) -> IngestResult:
    """
    Reads `source` in chunks, writes it verbatim to `dest_path`, and
    computes hashes + entropy along the way. Raises UploadTooLarge and
    deletes the partial file if `max_bytes` is exceeded.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    histogram = [0] * 256
    total = 0
    header = b""

    dest_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(dest_path, "wb") as out:
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise UploadTooLarge(
                        f"Upload exceeds the {max_bytes} byte limit"
                    )
                if not header:
                    header = chunk[:8192]
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
                for b in chunk:
                    histogram[b] += 1
                out.write(chunk)
    except UploadTooLarge:
        dest_path.unlink(missing_ok=True)
        raise

    return IngestResult(
        sha256=sha256.hexdigest(),
        sha1=sha1.hexdigest(),
        md5=md5.hexdigest(),
        size=total,
        entropy=shannon_entropy(histogram, total),
        header=header,
        byte_histogram=histogram,
    )
