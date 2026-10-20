// Applies opensig matches (TSV: addr name confidence lib) inside Ghidra headless and reports counts.
// @category OpenSig
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.file.*;

public class ApplyOpenSig extends GhidraScript {
    private int[] count() {
        int n = 0, named = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            n++;
            if (!f.getName().startsWith("FUN_")) named++;
        }
        return new int[]{n, named};
    }
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        int[] before = count();
        println("OPENSIG_BEFORE total=" + before[0] + " named=" + before[1]);
        if (a.length == 0 || a[0].equals("-")) return;
        int applied = 0, created = 0, failed = 0;
        for (String line : Files.readAllLines(Paths.get(a[0]))) {
            String[] p = line.split("\t");
            if (p.length < 3 || p[0].startsWith("#")) continue;
            Address ad = toAddr(Long.parseUnsignedLong(p[0], 16));
            try {
                Function f = getFunctionAt(ad);
                if (f == null) {
                    disassemble(ad);
                    f = createFunction(ad, null);
                    if (f == null) { failed++; continue; }
                    created++;
                }
                f.setName(p[1], SourceType.IMPORTED);
                f.setComment("opensig: " + p[1] + " confidence=" + p[2] + " lib=" + (p.length > 3 ? p[3] : "?"));
                applied++;
            } catch (Exception e) {
                failed++;
            }
        }
        int[] after = count();
        println("OPENSIG_APPLIED applied=" + applied + " created=" + created + " failed=" + failed);
        println("OPENSIG_AFTER total=" + after[0] + " named=" + after[1]);
    }
}
