# opensig: open library-signature corpus + auto-applier

opensig is an original, clean-room implementation that recognises statically linked library functions in stripped binaries and names them in Ghidra. Signatures are generated **only from open-source code we compile ourselves, or from distro `.a` archives**. No IDA FLIRT/Lumina, Binary Ninja or other proprietary signature data or binaries were used.

## How it works
1. **Corpus** (`scripts/build_corpus.sh`): builds musl 1.2.5 (gcc -O0/-O2/-O3, clang -O2) and glibc 2.41 (gcc -O2/-O3; glibc cannot be built at -O0), and copies the Debian `libc.a` (2.41-12+deb13u4).
2. **Signatures** (`opensig build-sigs <lib.a> <tag>`): every `STT_FUNC` in every archive member becomes a byte pattern. Bytes covered by relocations are masked, including linker-relaxation windows (GOTPCRELX, TLS). Aliases at the same address are kept, as are call relocations (offset → callee) for call-graph checks. Output is `sigs/<tag>.jsonl.gz`.
3. **Match** (`opensig match <bin>`): scans every executable PT_LOAD byte, so it does not depend on the disassembler's function starts. The index uses the 8-byte (or 4-byte) unmasked prefix, followed by a full masked compare.
4. **Score**: `confidence = f(fixed bytes, call-graph agreement, ambiguity)`.
   - The call-graph check verifies that each call/jump displacement in the matched function lands on a function matched with the expected callee name.
   - Matches with fewer than 12 fixed bytes are dropped unless the call graph confirms them.
   - Identical bodies with different names are flagged `ambiguous` and their confidence is halved.
   - Matches nested inside a stronger match are discarded.
5. **Apply** (`opensig apply <bin>`): detects the toolchain (glibc/musl/Go/Rust markers, static or stripped, `.comment` compiler), picks packs, and runs Ghidra headless with `scripts/ApplyOpenSig.java`. The script creates any missing functions, sets names (source IMPORTED) with a confidence comment, and reports named counts before and after.
6. **Check** (`opensig check <matches.json> <unstripped>`): false-positive and recall check against the symbol table of an unstripped twin.

## Usage
```bash
. ~/.rea-env                      # GHIDRA_INSTALL_DIR, JAVA_HOME
opensig detect  ./bin
opensig match   ./bin --out m.json [--packs sigs/x.jsonl.gz] [--min-confidence 0.8]
opensig apply   ./bin --out m.json            # Ghidra headless; prints before/after
opensig check   m.json ./bin.unstripped
opensig build-sigs /path/libfoo.a foo-1.2-gcc-O2
scripts/build_corpus.sh                        # rebuild musl/glibc archives
```
Setup: `uv venv .venv && VIRTUAL_ENV=.venv uv pip install pyelftools`, then symlink `opensig.sh` as `opensig`.

## Benchmarks (x86-64, Debian 13, Ghidra 12.1.4)
| Binary (stripped, static) | Ghidra named before | after opensig | Precision vs unstripped | Library recall | conf ≥ 0.8 precision |
|---|---|---|---|---|---|
| gap-analysis test `ts` (glibc, gcc -O2) | 38 / 1085 | **855 / 1109** | 97.3% (795/817) | 80.8% | 100% (688/688) |
| Lua 5.4.7 + glibc (gcc -O2) | 57 / 2094 | **1059 / 2125** | 96.3% (965/1002) | 82.4% | 100% (819/819) |
| Lua 5.4.7 + musl 1.2.5 (gcc -O2) | 13 / 961 | **249 / 977** | 94.9% (224/236) | 82.5% | 100% (186/186) |
| `ts` using only our own glibc source build (-O2, different CFLAGS from Debian) | 38 / 1085 | 541 matched | 95.6% | 52.6% | 100% (409/409) |

Library recall = correctly named / truth functions whose name exists in the selected packs. Application functions (Lua's own code) are out of scope. Matching takes under 1 s; Ghidra headless takes about 1 min.

**Known false-positive classes (all with confidence < 0.8):** gcc `.cold` split fragments that share bodies, same-body glibc IFUNC variants (`memcpy_chk` / `mempcpy_chk` / `memset_chk`), tiny tunables setters, and musl `iswxdigit`/`isxdigit`-style tail calls. **Recommendation: auto-apply at ≥ 0.8. Below that, apply as comments or labels for review.**

## Next steps
- **Recall:** add Debian/Ubuntu/Alpine/Fedora `libc.a` and other glibc versions; libstdc++/libgcc/libm/OpenSSL/zlib; more flag variants (`-fcf-protection`, `-fPIE`, LTO); and a call-graph *propagation* pass that names unmatched short functions from their matched callers and callees.
- **Go runtime:** recovery is mostly symbolic (pclntab/moduledata); add a Go-version pack to cover stripped-pclntab and garbled builds.
- **Rust:** build `std` / `core` / `alloc` per rustc version (`-Zbuild-std`), demangle v0/legacy names, and key on the `/rustc/<hash>` marker for version selection.
- **Other targets:** ARM64/ARM/MIPS/RISC-V (cross-compile the same corpus) and PE/MSVC (Windows SDK CRT via mingw and clang-cl).
- **Formats:** also export Ghidra FunctionID `.fidb` and Rizin zignatures for interoperability.
- **REA integration:** expose `rea apply-library-signatures` / MCP tool `apply_library_signatures`, returning REA Evidence (subject digest, packs plus SHA-256, per-function confidence) and applying via REA's Ghidra provider instead of a separate headless run.
