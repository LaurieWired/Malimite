import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.symbol.Namespace;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.*;

import org.json.JSONObject;
import org.json.JSONArray;

public class DumpDecompilation extends GhidraScript {

    private int getPort() {
        String[] args = getScriptArgs();
        if (args.length > 1) {
            return Integer.parseInt(args[1]);
        }
        println("No port provided. Exiting script.");
        return -1;
    }

    private String formatNamespaceName(String namespaceName) {
        if ("<global>".equals(namespaceName)) {
            return "Global";
        } else if ("<EXTERNAL>".equals(namespaceName)) {
            return "External";
        }
        return namespaceName;
    }

    private void listFunctionsAndNamespaces(Program program, int port) {
        DecompInterface decompInterface = new DecompInterface();
        try (Socket socket = new Socket("localhost", port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            decompInterface.openProgram(program);
            FunctionManager functionManager = program.getFunctionManager();
            Map<String, List<Function>> namespaceFunctionsMap = new HashMap<>();
            JSONArray jsonOutput = new JSONArray();

            // Collect functions for each namespace
            for (Function function : functionManager.getFunctions(true)) { // true for forward direction
                Namespace namespace = function.getParentNamespace();
                String namespaceName = formatNamespaceName(namespace != null ? namespace.getName() : "<global>");
                
                // Add function to namespace map
                namespaceFunctionsMap.computeIfAbsent(namespaceName, k -> new ArrayList<>()).add(function);
            }

            // Populate JSON data
            for (Map.Entry<String, List<Function>> entry : namespaceFunctionsMap.entrySet()) {
                String namespace = entry.getKey();
                List<Function> functions = entry.getValue();

                for (Function function : functions) {
                    var decompiledFunction = decompInterface.decompileFunction(function, 0, new ConsoleTaskMonitor());
                    if (decompiledFunction.decompileCompleted()) {
                        String decompiledCode = decompiledFunction.getDecompiledFunction().getC();

                        // Add JSON entry
                        JSONObject jsonEntry = new JSONObject();
                        jsonEntry.put("FunctionName", function.getName());
                        jsonEntry.put("ClassName", namespace);
                        jsonEntry.put("DecompiledCode", decompiledCode);
                        jsonOutput.put(jsonEntry);
                    }
                }
            }

            // Send JSON data over the socket
            out.println(jsonOutput.toString(4));
            out.println("END_DATA");

        } catch (Exception e) {
            printerr("Error during function/namespace processing: " + e.getMessage());
        } finally {
            decompInterface.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        int port = getPort();
        if (port == -1) return;

        listFunctionsAndNamespaces(currentProgram, port);
    }
}
