// Headless Ghidra post-script for PatchPivot.
// Usage:
//   analyzeHeadless <projectDir> <projectName> -import <binary> \
//     -scriptPath scripts/ghidra -postScript ExportPatchPivotSummary.java <outputDir>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class ExportPatchPivotSummary extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output directory argument required");
        }

        File outputDir = new File(args[0]);
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            throw new IllegalStateException("failed to create output directory: " + outputDir);
        }

        Program program = currentProgram;
        writeMetadata(program, new File(outputDir, "program-metadata.json"));
        writeFunctions(program, new File(outputDir, "functions.jsonl"));
        writeSymbols(program, new File(outputDir, "symbols.jsonl"));
        writeStrings(program, new File(outputDir, "strings.txt"));
    }

    private void writeMetadata(Program program, File file) throws Exception {
        try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            out.write("{\n");
            out.write("  \"name\": \"" + esc(program.getName()) + "\",\n");
            out.write("  \"executablePath\": \"" + esc(program.getExecutablePath()) + "\",\n");
            out.write("  \"executableFormat\": \"" + esc(program.getExecutableFormat()) + "\",\n");
            out.write("  \"languageId\": \"" + esc(program.getLanguageID().toString()) + "\",\n");
            out.write("  \"compilerSpecId\": \"" + esc(program.getCompilerSpec().getCompilerSpecID().toString()) + "\",\n");
            out.write("  \"imageBase\": \"" + esc(program.getImageBase().toString()) + "\",\n");
            out.write("  \"minAddress\": \"" + esc(program.getMinAddress().toString()) + "\",\n");
            out.write("  \"maxAddress\": \"" + esc(program.getMaxAddress().toString()) + "\",\n");
            out.write("  \"functionCount\": " + program.getFunctionManager().getFunctionCount() + "\n");
            out.write("}\n");
        }
    }

    private void writeFunctions(Program program, File file) throws Exception {
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function fn = functions.next();
                out.write("{");
                out.write("\"name\":\"" + esc(fn.getName()) + "\",");
                out.write("\"entry\":\"" + esc(fn.getEntryPoint().toString()) + "\",");
                out.write("\"bodyBytes\":" + fn.getBody().getNumAddresses() + ",");
                out.write("\"signature\":\"" + esc(fn.getSignature().getPrototypeString()) + "\",");
                out.write("\"callingConvention\":\"" + esc(String.valueOf(fn.getCallingConventionName())) + "\",");
                out.write("\"external\":" + fn.isExternal());
                out.write("}\n");
            }
        }
    }

    private void writeSymbols(Program program, File file) throws Exception {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            while (symbols.hasNext() && !monitor.isCancelled()) {
                Symbol symbol = symbols.next();
                out.write("{");
                out.write("\"name\":\"" + esc(symbol.getName(true)) + "\",");
                out.write("\"address\":\"" + esc(symbol.getAddress().toString()) + "\",");
                out.write("\"type\":\"" + esc(symbol.getSymbolType().toString()) + "\",");
                out.write("\"source\":\"" + esc(symbol.getSource().toString()) + "\"");
                out.write("}\n");
            }
        }
    }

    private void writeStrings(Program program, File file) throws Exception {
        DataIterator dataIterator = program.getListing().getDefinedData(true);
        try (BufferedWriter out = new BufferedWriter(new FileWriter(file))) {
            while (dataIterator.hasNext() && !monitor.isCancelled()) {
                Data data = dataIterator.next();
                try {
                    if (data.hasStringValue()) {
                        out.write(data.getAddress().toString());
                        out.write(" ");
                        out.write(data.getDataType().getName());
                        out.write(" ");
                        out.write(String.valueOf(data.getValue()).replace('\n', ' ').replace('\r', ' '));
                        out.write("\n");
                    }
                } catch (Exception ignored) {
                    // Keep export best-effort; corrupt data should not fail the whole headless run.
                }
            }
        }
    }

    private String esc(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
