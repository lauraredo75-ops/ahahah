// DecompileExport.java — script post-analyse Ghidra (Java) pour analyzeHeadless.
// Exporte le pseudo-C de toutes les fonctions vers un fichier unique.
//
// Pourquoi Java et non Python : Ghidra 12 n'exécute les scripts .py que via PyGhidra
// (CPython + jep). Un script .java est compilé nativement par Ghidra, sans dépendance.
//
// Usage (agent native/go) :
//   analyzeHeadless <projDir> <projName> -import <bin> \
//     -scriptPath D:\mze\lib\ghidra_scripts -postScript DecompileExport.java <outfile.c>
//
// Honnêteté : reconstruit de la LOGIQUE en pseudo-C. Ce n'est PAS le source d'origine.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = (args != null && args.length > 0)
                ? args[0]
                : new File(System.getProperty("user.dir"), "decompiled.c").getPath();

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        int count = 0;
        PrintWriter w = new PrintWriter(new FileWriter(out));
        try {
            w.println("/* Pseudo-C reconstruit par Ghidra (analyzeHeadless). NON source d'origine. */");
            w.println();
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                try {
                    DecompileResults r = di.decompileFunction(f, 60, monitor);
                    if (r != null && r.decompileCompleted()) {
                        w.println("/* ---- " + f.getName() + " @ " + f.getEntryPoint() + " ---- */");
                        w.println(r.getDecompiledFunction().getC());
                        w.println();
                        count++;
                    }
                } catch (Exception e) {
                    // fonction non décompilable : on continue
                }
            }
        } finally {
            w.close();
        }
        println("[DecompileExport] " + count + " fonctions -> " + out);
    }
}
