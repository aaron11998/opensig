"""Scan executable segments of a binary for signature matches and score them."""
from elftools.elf.elffile import ELFFile

MIN_FIXED = 12   # below this a match needs call-graph confirmation


def _compile(s):
    b = bytes.fromhex(s["pat"].replace("??", "00"))
    m = [c == "?" for c in s["pat"][::2]]
    chunks = []; i = 0; L = len(m)
    while i < L:
        if m[i]:
            i += 1; continue
        j = i
        while j < L and not m[j]:
            j += 1
        chunks.append((i, b[i:j])); i = j
    prefix = 0
    while prefix < L and not m[prefix]:
        prefix += 1
    return b, chunks, prefix


def segments(path):
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        segs = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & 1:
                segs.append((seg["p_vaddr"], seg.data()))
        return segs


def scan(path, sigs):
    idx8, idx4 = {}, {}
    comp = []
    for i, s in enumerate(sigs):
        b, chunks, prefix = _compile(s)
        comp.append(chunks)
        if prefix >= 8:
            idx8.setdefault(b[:8], []).append(i)
        elif prefix >= 4:
            idx4.setdefault(b[:4], []).append(i)
    hits = {}  # addr -> list of sig idx
    for base, data in segments(path):
        L = len(data)
        for off in range(L - 4):
            c = idx8.get(data[off:off + 8])
            c4 = idx4.get(data[off:off + 4])
            for cand in (c, c4):
                if not cand:
                    continue
                for i in cand:
                    s = sigs[i]
                    if off + s["len"] > L:
                        continue
                    if all(data[off + o:off + o + len(ch)] == ch for o, ch in comp[i]):
                        hits.setdefault(base + off, []).append(i)
    return hits


def score(path, sigs, hits):
    segs = segments(path)

    def rel32(addr):
        for base, data in segs:
            if base <= addr < base + len(data) - 4:
                return int.from_bytes(data[addr - base:addr - base + 4], "little", signed=True)
        return None

    # names possibly at each address
    cand_names = {a: {n for i in v for n in sigs[i]["aliases"]} for a, v in hits.items()}
    results = {}
    for a, v in hits.items():
        best = None
        for i in v:
            s = sigs[i]
            ok = tot = 0
            for off, callee, addend in s["calls"]:
                r = rel32(a + off)
                if r is None:
                    continue
                tgt = a + off + r - addend  # S = value - A + P
                if tgt in cand_names:
                    tot += 1
                    ok += callee in cand_names[tgt] or callee.lstrip("_") in {n.lstrip("_") for n in cand_names[tgt]}
            cg = ok / tot if tot else None
            base_conf = min(1.0, s["fixed"] / 64)
            conf = base_conf if cg is None else min(1.0, 0.5 * base_conf + 0.5 * cg + (0.2 if cg == 1 else 0))
            key = (conf, s["fixed"], s["len"])
            if best is None or key > best[0]:
                best = (key, i, cg, tot)
        (conf, fixed, ln), i, cg, tot = best
        s = sigs[i]
        idents = {sigs[j]["n"] for j in v if sigs[j]["fixed"] == fixed}
        ambiguous = len(idents) > 1
        if ambiguous:
            conf *= 0.5
        if fixed < MIN_FIXED and not (cg == 1 and tot > 0):
            continue
        results[a] = {"addr": a, "name": s["n"], "aliases": s["aliases"], "lib": s["lib"],
                      "len": s["len"], "fixed": fixed, "confidence": round(conf, 3),
                      "callgraph": None if cg is None else round(cg, 2), "ambiguous": sorted(idents) if ambiguous else None}
    # drop matches fully inside a stronger, longer match
    acc = []; taken = []
    for r in sorted(results.values(), key=lambda r: (-r["fixed"], r["addr"])):
        if any(s < r["addr"] < e for s, e in taken):
            continue
        acc.append(r); taken.append((r["addr"], r["addr"] + r["len"]))
    return sorted(acc, key=lambda r: r["addr"])
