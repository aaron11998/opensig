"""opensig command line: build-sigs | detect | match | apply | check"""
import argparse, glob, json, os, subprocess, sys, tempfile, time
from . import sigs as S, match as M, detect as D

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGDIR = os.path.join(ROOT, "sigs")


def packs_for(info):
    allp = sorted(glob.glob(os.path.join(SIGDIR, "*.jsonl.gz")))
    rt = info["runtimes"]
    want = [p for p in allp if any(os.path.basename(p).startswith(r) for r in rt)]
    return want or allp


def do_match(binary, packs):
    sigs = S.load(packs)
    t = time.time(); hits = M.scan(binary, sigs); res = M.score(binary, sigs, hits)
    return res, len(sigs), time.time() - t


def ghidra(binary, tsv):
    gh = os.environ.get("GHIDRA_INSTALL_DIR")
    if not gh:
        sys.exit("GHIDRA_INSTALL_DIR not set")
    proj = tempfile.mkdtemp(prefix="opensig_gh_")
    cmd = [os.path.join(gh, "support", "analyzeHeadless"), proj, "p", "-import", binary,
           "-scriptPath", os.path.join(ROOT, "scripts"), "-postScript", "ApplyOpenSig.java", tsv, "-deleteProject"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rep = {}
    for line in out.splitlines():
        for tag in ("OPENSIG_BEFORE", "OPENSIG_APPLIED", "OPENSIG_AFTER"):
            if tag in line:
                kv = line.split(tag, 1)[1].split("(")[0].split()
                rep[tag.split("_")[1].lower()] = {k: int(v) for k, v in (x.split("=") for x in kv)}
    return rep


def main():
    ap = argparse.ArgumentParser(prog="opensig")
    sp = ap.add_subparsers(dest="cmd", required=True)
    b = sp.add_parser("build-sigs"); b.add_argument("archive"); b.add_argument("tag")
    d = sp.add_parser("detect"); d.add_argument("binary")
    for name in ("match", "apply"):
        p = sp.add_parser(name); p.add_argument("binary"); p.add_argument("--packs", nargs="*")
        p.add_argument("--min-confidence", type=float, default=0.0); p.add_argument("--json", action="store_true")
        p.add_argument("--out")
    c = sp.add_parser("check", help="false-positive check vs unstripped twin")
    c.add_argument("matches_json"); c.add_argument("unstripped")
    a = ap.parse_args()

    if a.cmd == "build-sigs":
        os.makedirs(SIGDIR, exist_ok=True)
        n = S.build(a.archive, a.tag, os.path.join(SIGDIR, a.tag + ".jsonl.gz"))
        print(f"{a.tag}: {n} signatures"); return
    if a.cmd == "detect":
        print(json.dumps(D.detect(a.binary), indent=1)); return
    if a.cmd == "check":
        return check(a.matches_json, a.unstripped)

    info = D.detect(a.binary)
    packs = a.packs or packs_for(info)
    res, nsig, dt = do_match(a.binary, packs)
    res = [r for r in res if r["confidence"] >= a.min_confidence]
    report = {"binary": a.binary, "detect": info, "packs": [os.path.basename(p) for p in packs],
              "signatures": nsig, "match_seconds": round(dt, 1), "matched": len(res), "matches": res}
    if a.cmd == "apply":
        tsv = tempfile.mktemp(suffix=".tsv")
        with open(tsv, "w") as f:
            for r in res:
                f.write("%x\t%s\t%s\t%s\n" % (r["addr"], r["name"], r["confidence"], r["lib"]))
        report["ghidra"] = ghidra(a.binary, tsv)
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1)
    if a.json:
        print(json.dumps(report, indent=1)); return
    print(f"detected: {info['runtimes']} static={info['static']} stripped={info['stripped']} compiler={info['compiler']}")
    print(f"packs: {report['packs']}  signatures: {nsig}  match time: {report['match_seconds']}s")
    hi = sum(r['confidence'] >= 0.8 for r in res); mid = sum(0.4 <= r['confidence'] < 0.8 for r in res)
    print(f"matched: {len(res)}  (conf>=0.8: {hi}, 0.4-0.8: {mid}, <0.4: {len(res)-hi-mid})")
    if "ghidra" in report:
        g = report["ghidra"]
        print(f"ghidra before: {g.get('before')}  after: {g.get('after')}  applied: {g.get('applied')}")


def check(mj, unstripped):
    from elftools.elf.elffile import ELFFile
    rep = json.load(open(mj))
    truth = {}
    with open(unstripped, "rb") as fh:
        e = ELFFile(fh)
        for s in e.get_section_by_name(".symtab").iter_symbols():
            if s["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC") and s["st_value"]:
                truth.setdefault(s["st_value"], set()).add(s.name)
    norm = lambda n: n.lstrip("_")
    okaddr = set()
    tp = fp_wrong = fp_none = 0; bad = []
    buckets = {}
    for r in rep["matches"]:
        names = truth.get(r["addr"])
        b = "hi" if r["confidence"] >= 0.8 else "mid" if r["confidence"] >= 0.4 else "lo"
        st = buckets.setdefault(b, [0, 0])
        if names and ({norm(x) for x in r["aliases"]} & {norm(x) for x in names}):
            tp += 1; st[0] += 1; okaddr.add(r["addr"])
        else:
            st[1] += 1
            if names: fp_wrong += 1
            else: fp_none += 1
            bad.append((hex(r["addr"]), r["name"], sorted(names)[:3] if names else None, r["confidence"]))
    print(f"truth functions: {len(truth)}  matches: {len(rep['matches'])}  correct: {tp}  "
          f"wrong-name: {fp_wrong}  no-symbol-at-addr: {fp_none}  precision: {tp/max(1,len(rep['matches'])):.3f}  recall: {tp/max(1,len(truth)):.3f}")
    known = {norm(n) for sg in S.load([os.path.join(SIGDIR, x) for x in rep["packs"]]) for n in sg["aliases"]}
    lib_truth = [a for a, ns in truth.items() if {norm(x) for x in ns} & known]
    got = okaddr
    lt = sum(1 for a in lib_truth if a in got)
    print(f"library functions present (name in packs): {len(lib_truth)}  correctly named: {lt}  library recall: {lt/max(1,len(lib_truth)):.3f}")
    for k, (g, w) in sorted(buckets.items()):
        print(f"  confidence {k}: correct={g} wrong={w}")
    for x in bad[:15]:
        print("  FP", x)


if __name__ == "__main__":
    main()
