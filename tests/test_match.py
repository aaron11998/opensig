"""Unit tests that need only pyelftools + a tiny hand-built ELF — no Ghidra."""
import gzip, json, os, struct, tempfile, unittest
from opensig import match as M, detect as D, sigs as S

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _elf_exec(code: bytes, vaddr=0x400000):
    """Minimal 64-bit LE ELF with one RX LOAD containing `code`."""
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"; ehdr[4], ehdr[5], ehdr[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     2, 62, 1, vaddr, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, vaddr, vaddr, 64 + 56 + len(code), 64 + 56 + len(code), 0x1000)
    # put code right after headers
    return bytes(ehdr) + phdr + code


class DetectTest(unittest.TestCase):
    def test_glibc_marker(self):
        blob = _elf_exec(b"\x90" * 32 + b"GLIBC_TUNABLES\x00__libc_start_main\x00")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob); path = f.name
        try:
            info = D.detect(path)
            self.assertIn("glibc", info["runtimes"])
            self.assertTrue(info["static"])
        finally:
            os.unlink(path)


class MatchTest(unittest.TestCase):
    def test_masked_hit_and_score(self):
        # body: mov eax,imm32 ; ret   with imm32 masked as reloc
        body = bytes.fromhex("b8") + b"\x00\x00\x00\x00" + bytes.fromhex("c3")
        sig = {"n": "demo_fn", "aliases": ["demo_fn"], "lib": "test", "len": 6,
               "fixed": 2, "pat": "b8????????c3", "calls": [], "obj": "t.o"}
        # bump fixed artificially so MIN_FIXED doesn't drop it — use a longer unique body
        long = bytes.fromhex("554889e54883ec10") + body + bytes.fromhex("4883c4105dc3")
        # 55 48 89 e5 48 83 ec 10 | b8 ?? ?? ?? ?? c3 | 48 83 c4 10 5d c3
        pat = "554889e54883ec10" + "b8????????c3" + "4883c4105dc3"
        sig = {"n": "demo_fn", "aliases": ["demo_fn"], "lib": "test", "len": len(long),
               "fixed": len(long) - 4, "pat": pat, "calls": [], "obj": "t.o"}
        blob = _elf_exec(b"\x90" * 16 + long + b"\x90" * 16)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob); path = f.name
        try:
            hits = M.scan(path, [sig])
            self.assertTrue(hits, "expected at least one hit")
            res = M.score(path, [sig], hits)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["name"], "demo_fn")
            self.assertGreaterEqual(res[0]["confidence"], 0.2)
        finally:
            os.unlink(path)

    def test_pack_loads(self):
        packs = [os.path.join(ROOT, "sigs", n) for n in os.listdir(os.path.join(ROOT, "sigs"))
                 if n.endswith(".jsonl.gz")]
        self.assertTrue(packs, "signature packs should be present in repo")
        sample = S.load(packs[:1])
        self.assertGreater(len(sample), 100)
        self.assertIn("pat", sample[0])


if __name__ == "__main__":
    unittest.main()
