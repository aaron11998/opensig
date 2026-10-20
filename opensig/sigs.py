"""Generate masked byte signatures from static archives (.a) of ELF x86-64 objects."""
import gzip, io, json, os, subprocess, tempfile
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

# x86-64 relocation types -> (bytes masked before offset, bytes masked from offset)
R = {1: (0, 8), 2: (0, 4), 4: (0, 4), 9: (2, 4), 10: (0, 4), 11: (0, 4), 24: (0, 8),
     19: (4, 12), 20: (4, 12), 21: (0, 4), 22: (3, 4), 23: (0, 4), 26: (0, 4),
     41: (2, 4), 42: (3, 4), 25: (0, 8), 34: (3, 4), 35: (0, 4)}
CALL_TYPES = {2, 4}  # PC32 / PLT32 -> candidate call/jump target for call-graph checks


def _objects(archive):
    tmp = tempfile.mkdtemp(prefix="opensig_")
    names = subprocess.run(["ar", "t", archive], capture_output=True, text=True, check=True).stdout.split()
    # members can repeat names; extract each by count
    seen = {}
    for n in names:
        seen[n] = seen.get(n, 0) + 1
        sub = os.path.join(tmp, str(len(seen)) + "_" + str(seen[n]))
        os.makedirs(sub, exist_ok=True)
        subprocess.run(["ar", "xN", str(seen[n]), os.path.abspath(archive), n], cwd=sub, check=True)
        yield os.path.join(sub, n)
    subprocess.run(["rm", "-rf", tmp])


def object_sigs(path, lib):
    out = []
    with open(path, "rb") as fh:
        try:
            elf = ELFFile(fh)
        except Exception:
            return out
        if elf["e_machine"] != "EM_X86_64":
            return out
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return out
        syms = list(symtab.iter_symbols())
        relsec = {}
        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                relsec[s["sh_info"]] = s
        by_sec = {}
        for s in syms:
            sh = s["st_shndx"]
            if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] > 0 and isinstance(sh, int):
                by_sec.setdefault(sh, []).append(s)
        for idx, fs in by_sec.items():
            sec = elf.get_section(idx)
            data = sec.data()
            mask = bytearray(len(data))
            calls = []
            if idx in relsec:
                for r in relsec[idx].iter_relocations():
                    t = r["r_info_type"]; off = r["r_offset"]
                    pre, ln = R.get(t, (0, 4))
                    for i in range(max(0, off - pre), min(len(data), off + ln)):
                        mask[i] = 1
                    if t in CALL_TYPES:
                        tgt = syms[r["r_info_sym"]]
                        if tgt.name and tgt["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE", "STT_GNU_IFUNC"):
                            calls.append((off, tgt.name, r["r_addend"]))
            groups = {}
            for s in fs:
                groups.setdefault((s["st_value"], s["st_size"]), []).append(s.name)
            for (start, size), names in groups.items():
                body = data[start:start + size]; m = mask[start:start + size]
                if len(body) != size:
                    continue
                pat = "".join("??" if m[i] else "%02x" % body[i] for i in range(size))
                fixed = size - sum(m)
                names = sorted(set(names), key=lambda n: (n.startswith("_"), len(n), n))
                c = [(o - start, n, a) for (o, n, a) in calls if start <= o < start + size]
                out.append({"n": names[0], "aliases": names, "lib": lib, "len": size,
                            "fixed": fixed, "pat": pat, "calls": c,
                            "obj": os.path.basename(path)})
    return out


def build(archive, lib, outpath):
    seen = set(); n = 0
    with gzip.open(outpath, "wt") as w:
        for obj in _objects(archive):
            for s in object_sigs(obj, lib):
                k = (s["pat"], s["n"])
                if k in seen:
                    continue
                seen.add(k); n += 1
                w.write(json.dumps(s) + "\n")
    return n


def load(paths):
    sigs = []
    for p in paths:
        with gzip.open(p, "rt") as f:
            sigs.extend(json.loads(l) for l in f)
    return sigs
