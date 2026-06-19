"""
Minimal PE (Portable Executable) header parser built directly on `struct`.
This only ever reads bytes already loaded in memory — it does not load,
map, relocate, or execute the binary in any way. Malformed input simply
yields fewer fields; it never raises into caller code paths that matter.
"""
import struct
from typing import Optional

MACHINE_TYPES = {
    0x014c: "x86 (32-bit)", 0x0200: "Itanium", 0x8664: "x64 (AMD64)",
    0x01c0: "ARM", 0xaa64: "ARM64", 0x01c4: "ARMv7 Thumb",
}

SUBSYSTEMS = {
    1: "Native", 2: "Windows GUI", 3: "Windows CUI (console)",
    5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
    10: "EFI Application", 14: "Xbox",
}

CHARACTERISTIC_FLAGS = [
    (0x0002, "Executable image"),
    (0x2000, "DLL"),
    (0x0001, "Relocations stripped"),
    (0x0020, "Large address aware"),
    (0x4000, "Terminal server aware"),
    (0x0200, "Debug info stripped"),
]


def parse_pe(data: bytes) -> Optional[dict]:
    try:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            return None
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        coff_off = e_lfanew + 4
        machine, n_sections, timestamp = struct.unpack_from("<HHI", data, coff_off)[0:3]
        size_opt_hdr, characteristics = struct.unpack_from("<HH", data, coff_off + 16)

        opt_off = coff_off + 20
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is_pe32_plus = magic == 0x20b

        entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
        subsystem_off = opt_off + (68 if is_pe32_plus else 68)
        subsystem = struct.unpack_from("<H", data, subsystem_off)[0]

        # Security (certificate table) directory is data directory #4.
        # Each data directory entry is 8 bytes (RVA + size).
        dir_table_off = opt_off + (112 if is_pe32_plus else 96)
        has_signature = False
        try:
            sec_dir_off = dir_table_off + 4 * 8
            sec_size = struct.unpack_from("<I", data, sec_dir_off + 4)[0]
            has_signature = sec_size > 0
        except struct.error:
            pass

        section_table_off = opt_off + size_opt_hdr
        sections = []
        for i in range(min(n_sections, 96)):
            base = section_table_off + i * 40
            if base + 40 > len(data):
                break
            raw = data[base:base + 8]
            name = raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
            virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
            sect_entropy = None
            if raw_ptr and raw_size and raw_ptr + raw_size <= len(data):
                sect_entropy = _entropy(data[raw_ptr:raw_ptr + min(raw_size, 2_000_000)])
            sections.append({
                "name": name or "(unnamed)",
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "entropy": sect_entropy,
            })

        flags = [label for bit, label in CHARACTERISTIC_FLAGS if characteristics & bit]

        return {
            "format": "PE32+" if is_pe32_plus else "PE32",
            "machine": MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04x})"),
            "subsystem": SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})"),
            "compile_timestamp": timestamp,
            "entry_point": hex(entry_point),
            "number_of_sections": n_sections,
            "characteristics": flags,
            "has_digital_signature": has_signature,
            "sections": sections,
            "is_dll": bool(characteristics & 0x2000),
            "max_section_entropy": max(
                (s["entropy"] for s in sections if s["entropy"] is not None), default=None
            ),
        }
    except (struct.error, IndexError):
        return None


def parse_elf(data: bytes) -> Optional[dict]:
    try:
        if data[:4] != b"\x7fELF" or len(data) < 20:
            return None
        ei_class = data[4]
        ei_data = data[5]
        is_64 = ei_class == 2
        endian = "<" if ei_data == 1 else ">"

        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        e_entry = struct.unpack_from(
            endian + ("Q" if is_64 else "I"), data, 24
        )[0]

        types = {1: "Relocatable", 2: "Executable", 3: "Shared object", 4: "Core dump"}
        machines = {3: "x86", 40: "ARM", 62: "x86-64", 183: "ARM64", 8: "MIPS"}

        return {
            "format": "ELF64" if is_64 else "ELF32",
            "endianness": "Little-endian" if ei_data == 1 else "Big-endian",
            "type": types.get(e_type, f"Unknown ({e_type})"),
            "machine": machines.get(e_machine, f"Unknown ({e_machine})"),
            "entry_point": hex(e_entry),
        }
    except (struct.error, IndexError):
        return None


def _entropy(buf: bytes) -> float:
    import math
    if not buf:
        return 0.0
    hist = [0] * 256
    for b in buf:
        hist[b] += 1
    total = len(buf)
    ent = 0.0
    for c in hist:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 3)
