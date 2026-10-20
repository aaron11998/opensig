# opensig

**Open, clean-room library signatures for stripped static binaries.**

opensig recognises glibc/musl functions in stripped ELF binaries and names them in [Ghidra](https://ghidra-sre.org/) — no IDA FLIRT, Lumina, Binary Ninja, or other proprietary signature data involved. Signatures are built only from open-source code we compile ourselves, or from distro `.a` archives.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/aaron11998/opensig)](https://github.com/aaron11998/opensig/releases)

## Why

On a stripped, statically linked gcc binary, Ghidra 12.1.4 named **38 of 1,085** functions (3.5%). After `opensig apply` with the Debian glibc 2.41 pack: **855 of 1,109** named, with **97.3%** precision against the unstripped twin and **100%** precision on matches with confidence ≥ 0.8.

## Benchmarks

x86-64, Debian 13, Ghidra 12.1.4. Precision/recall measured against the unstripped twin's `.symtab`. *Library recall* = correctly named / truth functions whose name exists in the selected packs (application code is out of scope).

| Binary (stripped, static) | Ghidra named before | after opensig | Precision | Library recall | conf ≥ 0.8 precision |
|---|---|---|---|---|---|
| Gap-analysis test `ts` (glibc, gcc -O2) | **38 / 1085** | **855 / 1109** | **97.3%** (795/817) | 80.8% | **100%** (688/688) |
| Lua 5.4.7 + glibc (gcc -O2) | 57 / 2094 | 1059 / 2125 | 96.3% (965/1002) | 82.4% | 100% (819/819) |
| Lua 5.4.7 + musl 1.2.5 (gcc -O2) | 13 / 961 | 249 / 977 | 94.9% (224/236) | 82.5% | 100% (186/186) |
| `ts` with our own glibc source build only (different CFLAGS) | 38 / 1085 | 541 matched | 95.6% | 52.6% | 100% (409/409) |

Matching takes under 1 s; Ghidra headless apply takes about a minute. False positives cluster below 0.8 confidence (gcc `.cold` fragments, IFUNC twins, tiny tunables). **Recommendation: auto-apply at ≥ 0.8; below that, review.**

## Quick start

```bash
# needs: Python 3.11+, pyelftools, Ghidra (for apply), JAVA_HOME
git clone https://github.com/aaron11998/opensig.git && cd opensig
python3 -m venv .venv && . .venv/bin/activate
pip install pyelftools
export GHIDRA_INSTALL_DIR=/path/to/ghidra   # for apply
export JAVA_HOME=/path/to/jdk               # 21+ recommended
ln -sf "$PWD/opensig.sh" ~/.local/bin/opensig

opensig detect  ./stripped-static-bin
opensig match   ./stripped-static-bin --out m.json
opensig apply   ./stripped-static-bin --out m.json   # Ghidra headless
opensig check   m.json ./unstripped-twin             # false-positive audit
```

Signature packs ship in `sigs/` and as release assets. Rebuild the corpus with `scripts/build_corpus.sh` then `opensig build-sigs <lib.a> <tag>`.

## How it works

1. **Corpus** — build musl / glibc static archives at several `-O` levels (and copy the distro `libc.a`).
2. **Signatures** — every `STT_FUNC` in every `.a` member becomes a relocation-masked byte pattern, with call-graph edges (PC32/PLT32 → callee) kept for scoring. Output: `sigs/<tag>.jsonl.gz`.
3. **Match** — scan every executable `PT_LOAD` (independent of the disassembler's function starts). Index on the unmasked 8-byte (or 4-byte) prefix, then full masked compare.
4. **Score** — `confidence = f(fixed bytes, call-graph agreement, ambiguity)`. Matches with &lt; 12 fixed bytes need a confirming call graph; nested hits under a stronger match are dropped.
5. **Apply** — detect toolchain (glibc/musl/Go/Rust markers, static/stripped, `.comment`), pick packs, run Ghidra headless (`scripts/ApplyOpenSig.java`): create missing functions, set names (`SourceType.IMPORTED`) with a confidence comment, report before/after counts.

```
binary ──detect──► packs ──match──► scored hits ──apply──► Ghidra names
                                      │
                                      └──check──► precision vs unstripped
```

## Clean-room statement

opensig is an **original implementation**. Signatures are generated only from:

- Open-source libc we compile ourselves (musl 1.2.5, glibc 2.41), and
- Distro-provided static archives (e.g. Debian `libc6-dev` `libc.a`).

**We do not use, convert, or redistribute** IDA FLIRT / Lumina databases, Binary Ninja WARP/SigKit packs, Hopper signatures, JEB, or any other proprietary signature corpus or binary. Matching and scoring algorithms were designed from first principles (ELF relocation masking + call-graph agreement), not reverse-engineered from commercial tools.

## Roadmap

- [ ] More libc versions (Ubuntu/Alpine/Fedora) and companion libs (`libstdc++`, `libgcc`, OpenSSL, zlib)
- [ ] Flag variants (`-fcf-protection`, `-fPIE`, LTO) and a call-graph *propagation* pass for short unmatched functions
- [ ] Go runtime packs (pclntab-aware) and Rust `std`/`core`/`alloc` per rustc version
- [ ] ARM64 / ARM / RISC-V / MIPS cross-compiled packs; PE/MSVC CRT
- [ ] Export Ghidra FunctionID `.fidb` and Rizin zignatures
- [ ] REA / MCP integration: `apply_library_signatures` returning auditable Evidence

## CLI reference

| Command | Purpose |
|---|---|
| `opensig detect <bin>` | Toolchain / runtime / static / stripped heuristics (JSON) |
| `opensig build-sigs <lib.a> <tag>` | Build a pack into `sigs/<tag>.jsonl.gz` |
| `opensig match <bin> [--packs …] [--min-confidence N] [--out m.json]` | Score matches without touching Ghidra |
| `opensig apply <bin> …` | Match + Ghidra headless rename |
| `opensig check m.json <unstripped>` | Precision / library-recall audit |

## License

MIT — see [LICENSE](LICENSE). Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
