"""Cheap toolchain / runtime detection from strings and ELF notes."""
import re
from elftools.elf.elffile import ELFFile

MARKERS = {
    "glibc": [rb"GLIBC_TUNABLES", rb"glibc\.malloc\.", rb"FATAL: kernel too old", rb"__libc_start_main"],
    "musl": [rb"No error information", rb"Illegal byte sequence\x00Domain error"],
    "go": [rb"\xff Go buildinf:", rb"runtime\.gopanic", rb"go1\.\d+"],
    "rust": [rb"/rustc/[0-9a-f]{40}", rb"rust_panic", rb"RUST_BACKTRACE"],
}


def detect(path):
    with open(path, "rb") as _fh:
        data = _fh.read()
    found = {k: sum(bool(re.search(p, data)) for p in v) for k, v in MARKERS.items()}
    info = {"runtimes": [k for k, v in found.items() if v], "scores": found}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        info["static"] = not any(s["p_type"] == "PT_INTERP" for s in elf.iter_segments())
        info["stripped"] = elf.get_section_by_name(".symtab") is None
        c = elf.get_section_by_name(".comment")
        info["compiler"] = sorted({x.decode(errors="replace") for x in c.data().split(b"\0") if x}) if c else []
        info["arch"] = elf["e_machine"]
    m = re.search(rb"GNU C Library[^\n\0]*?release version (\d+\.\d+)", data)
    if m:
        info["glibc_version"] = m.group(1).decode()
    return info
