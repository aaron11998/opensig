# Contributing to opensig

Thanks for helping grow an open, clean-room signature corpus.

## Ground rules

1. **Clean-room only.** Do not submit signatures, patterns, or code derived from IDA FLIRT/Lumina, Binary Ninja WARP/SigKit, Hopper, JEB, or other proprietary tools or their databases. Packs must come from source you can point at (upstream tarball + build flags, or a public distro `.a` with package version).
2. **Reproducible packs.** Document the exact source URL, commit/tag, compiler, and `CFLAGS` used to build an archive. Prefer `scripts/build_corpus.sh` extensions over one-off binaries.
3. **No license laundering.** Only ship signature data for libraries whose licences allow redistribution of object code / derived indexes (glibc LGPL with corresponding source available, musl MIT, etc.). Note provenance in the PR.
4. **Honest benchmarks.** If you claim precision/recall, include an unstripped twin and the `opensig check` output.

## Dev setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pyelftools
python -m unittest discover -s tests -v
```

Ghidra is optional for unit tests; required only for `opensig apply`.

## Pull requests

- Keep PRs focused (one pack family, or one matcher change).
- Add/extend a unit test when changing `opensig/match.py` or `opensig/sigs.py`.
- Do not commit `build/`, `.venv/`, or large unrelated binaries.
- Sign-off is appreciated but not required.

## Reporting issues

Use the issue templates. For false positives, attach `opensig check` output and (if possible) a minimal repro binary.
