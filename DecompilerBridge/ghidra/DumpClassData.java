import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.*;
import org.json.JSONObject;
import org.json.JSONArray;

public class DumpClassData extends GhidraScript {

    private int port;
    private List<String> libraryPrefixes;

    private void parseArgs() {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Insufficient arguments. Expected: <port> <libraries>");
            return;
        }
        this.port = Integer.parseInt(args[0]);
        // Parse libraries from comma-separated string
        this.libraryPrefixes = Arrays.asList(args[1].split(","));
    }

    private boolean isLibraryNamespace(String namespace) {
        return libraryPrefixes.stream()
            .anyMatch(prefix -> namespace.startsWith(prefix));
    }

    private int getPort() {
        String[] args = getScriptArgs();
        if (args.length > 0) {
            return Integer.parseInt(args[0]);
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

    private JSONArray extractClassFunctionData(Program program) {
        FunctionManager functionManager = program.getFunctionManager();
        List<JSONObject> classFunctionData = new ArrayList<>();

        Map<String, List<String>> namespaceFunctionData = new HashMap<>();

        for (Function function : functionManager.getFunctions(true)) {
            Namespace namespace = function.getParentNamespace();
            String namespaceName = formatNamespaceName(namespace != null ? namespace.getName() : "<global>");

            namespaceFunctionData.computeIfAbsent(namespaceName, k -> new ArrayList<>()).add(function.getName());
        }

        for (Map.Entry<String, List<String>> entry : namespaceFunctionData.entrySet()) {
            JSONObject classObject = new JSONObject();
            classObject.put("ClassName", entry.getKey());
            classObject.put("Functions", new JSONArray(entry.getValue()));
            classFunctionData.add(classObject);
        }

        return new JSONArray(classFunctionData);
    }

    private JSONObject listDefinedDataInAllSegments(Program program) {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        Map<String, JSONObject> dataStructure = new HashMap<>();

        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            Address end = block.getEnd();
            String name = block.getName();

            JSONObject segmentData = new JSONObject();
            segmentData.put("start", start.toString());
            segmentData.put("end", end.toString());
            JSONArray dataArray = new JSONArray();

            DataIterator dataIterator = listing.getDefinedData(start, true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (!block.contains(data.getAddress())) {
                    continue;
                }

                String label = data.getLabel();
                String value = data.getDefaultValueRepresentation();
                String address = data.getAddress().toString();

                JSONObject dataEntry = new JSONObject();
                dataEntry.put("label", label != null ? label : "Unnamed");
                dataEntry.put("value", value);
                dataEntry.put("address", address);
                dataArray.put(dataEntry);
            }

            segmentData.put("data", dataArray);
            dataStructure.put(name, segmentData);
        }

        return new JSONObject(dataStructure);
    }

    private JSONArray listFunctionsAndNamespaces(Program program) {
        DecompInterface decompInterface = new DecompInterface();
        FunctionManager functionManager = program.getFunctionManager();
        Map<String, List<Function>> namespaceFunctionsMap = new HashMap<>();
        JSONArray jsonOutput = new JSONArray();

        decompInterface.openProgram(program);

        // Collect functions for each namespace
        for (Function function : functionManager.getFunctions(true)) {
            Namespace namespace = function.getParentNamespace();
            String namespaceName = formatNamespaceName(namespace != null ? namespace.getName() : "<global>");
            
            // Skip decompilation if namespace is a library
            if (isLibraryNamespace(namespaceName)) {
                // Add basic function info without decompilation
                JSONObject jsonEntry = new JSONObject();
                jsonEntry.put("FunctionName", function.getName());
                jsonEntry.put("ClassName", namespaceName);
                jsonEntry.put("DecompiledCode", ""); // Empty string for library functions
                jsonOutput.put(jsonEntry);
                continue;
            }

            // Add function to namespace map for non-library functions
            namespaceFunctionsMap.computeIfAbsent(namespaceName, k -> new ArrayList<>()).add(function);
        }

        // Decompile non-library functions
        for (Map.Entry<String, List<Function>> entry : namespaceFunctionsMap.entrySet()) {
            String namespace = entry.getKey();
            List<Function> functions = entry.getValue();

            for (Function function : functions) {
                var decompiledFunction = decompInterface.decompileFunction(function, 0, new ConsoleTaskMonitor());
                if (decompiledFunction.decompileCompleted()) {
                    String decompiledCode = decompiledFunction.getDecompiledFunction().getC();

                    JSONObject jsonEntry = new JSONObject();
                    jsonEntry.put("FunctionName", function.getName());
                    jsonEntry.put("ClassName", namespace);
                    jsonEntry.put("DecompiledCode", decompiledCode);
                    jsonOutput.put(jsonEntry);
                }
            }
        }

        decompInterface.dispose();
        return jsonOutput;
    }

    private JSONArray extractStrings(Program program) {
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        JSONArray stringsArray = new JSONArray();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            
            DataIterator dataIterator = listing.getDefinedData(block.getStart(), true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (!block.contains(data.getAddress())) continue;
                
                // Check if the data type is a string
                DataType dataType = data.getDataType();
                if (dataType instanceof StringDataType) {
                    String value = data.getDefaultValueRepresentation(); // Retrieves the string value
                    // Only include strings of length 5 or more
                    if (value.length() >= 5) {
                        JSONObject stringObj = new JSONObject();
                        stringObj.put("address", data.getAddress().toString());
                        stringObj.put("value", value);
                        stringObj.put("segment", block.getName());
                        stringObj.put("label", data.getLabel() != null ? data.getLabel() : "");
                        stringsArray.put(stringObj);
                    }
                }
            }
        }
        return stringsArray;
    }

    private void sendDataViaSocket(JSONArray classData, JSONObject machoData, JSONArray functionData) {
        int port = getPort();
        if (port == -1) return;

        try (Socket socket = new Socket("localhost", port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            out.println("CONNECTED");
            println("Beginning analysis...");
            
            // Send class data
            out.println(classData.toString(4));
            out.println("END_CLASS_DATA");

            // Send Macho data
            out.println(machoData.toString(4));
            out.println("END_MACHO_DATA");

            // Send function decompilation data
            out.println(functionData.toString(4));
            out.println("END_DATA");

            // Send string data
            JSONArray stringData = extractStrings(currentProgram);
            out.println(stringData.toString(4));
            out.println("END_STRING_DATA");

        } catch (IOException e) {
            printerr("Error sending data via socket: " + e.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        System.err.println("Running DumpCombinedData script");
        parseArgs();
        
        if (port == -1) {
            return;
        }

        // Perform heartbeat check first
        try (Socket heartbeatSocket = new Socket("localhost", port);
             PrintWriter heartbeatOut = new PrintWriter(heartbeatSocket.getOutputStream(), true)) {
            
            heartbeatOut.println("HEARTBEAT");
            println("Heartbeat sent successfully, proceeding with analysis...");
        } catch (IOException e) {
            printerr("Failed to establish initial connection: " + e.getMessage());
            return;
        }

        // Continue with analysis after successful heartbeat
        JSONArray classData = extractClassFunctionData(currentProgram);
        JSONObject machoData = listDefinedDataInAllSegments(currentProgram);
        JSONArray functionData = listFunctionsAndNamespaces(currentProgram);

        sendDataViaSocket(classData, machoData, functionData);
    }
}
