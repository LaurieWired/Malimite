package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.configuration.LibraryDefinitions;
import com.lauriewired.malimite.database.SQLiteDBHandler;

import java.nio.file.Paths;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.util.function.Consumer;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

public class GhidraProject {
    private static final Logger LOGGER = Logger.getLogger(GhidraProject.class.getName());
    private String ghidraProjectName;
    private Config config;
    private String scriptPath;
    private SQLiteDBHandler dbHandler;
    private static final int PORT = 8765;
    private Consumer<String> consoleOutputCallback;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath, Config config, SQLiteDBHandler dbHandler, Consumer<String> consoleOutputCallback) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_malimite";
        this.config = config;
        this.dbHandler = dbHandler;
        this.consoleOutputCallback = consoleOutputCallback;
        // Set script path based on current directory and OS
        String currentDir = System.getProperty("user.dir");
        this.scriptPath = Paths.get(currentDir, "DecompilerBridge", "ghidra").toString();

        LOGGER.info("Initializing GhidraProject with executable: " + infoPlistBundleExecutable);
        LOGGER.info("Script path: " + scriptPath);
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho) {
        LOGGER.info("Starting Ghidra decompilation for: " + executableFilePath);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            serverSocket.setSoTimeout(300000); // 5 minute timeout for initial connection

            String analyzeHeadless = getAnalyzeHeadlessPath();
            
            ProcessBuilder builder = new ProcessBuilder(    
                analyzeHeadless,
                projectDirectoryPath,
                this.ghidraProjectName,
                "-import",
                executableFilePath,
                "-scriptPath",
                scriptPath,
                "-postScript",
                "DumpClassData.java",
                String.valueOf(PORT),
                "-deleteProject"
            );
            
            // Redirect Ghidra's output and error streams
            builder.redirectErrorStream(true);
            Process process = builder.start();

            // Read Ghidra's output in a separate thread
            Thread outputThread = new Thread(() -> {
                try (BufferedReader ghidraOutput = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = ghidraOutput.readLine()) != null) {
                        final String outputLine = line;
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept("Ghidra: " + outputLine);
                        }
                        System.out.println("Ghidra Output: " + line);
                    }
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error reading Ghidra output", e);
                }
            });
            outputThread.start();

            LOGGER.info("Starting Ghidra headless analyzer with command: " + String.join(" ", builder.command()));
            LOGGER.info("Waiting for Ghidra script connection on port " + PORT);
            
            Socket socket = serverSocket.accept();
            socket.setSoTimeout(0);
            LOGGER.info("Connection established with Ghidra script");

            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                // Wait for initial connection confirmation
                String connectionConfirmation = in.readLine();
                if (!"CONNECTED".equals(connectionConfirmation)) {
                    throw new RuntimeException("Did not receive proper connection confirmation from Ghidra script");
                }
                LOGGER.info("Ghidra script confirmed connection, beginning analysis");

                LOGGER.info("Reading class data from Ghidra script");
                String line;
                StringBuilder classDataBuilder = new StringBuilder();
                while (!(line = in.readLine()).equals("END_CLASS_DATA")) {
                    classDataBuilder.append(line).append("\n");
                }

                LOGGER.info("Reading Mach-O data from Ghidra script");
                StringBuilder machoDataBuilder = new StringBuilder();
                while (!(line = in.readLine()).equals("END_MACHO_DATA")) {
                    machoDataBuilder.append(line).append("\n");
                }

                LOGGER.info("Reading function decompilation data from Ghidra script");
                StringBuilder functionDataBuilder = new StringBuilder();
                while (!(line = in.readLine()).equals("END_DATA")) {
                    functionDataBuilder.append(line).append("\n");
                }

                // Process and store the received data
                JSONArray classData = new JSONArray(classDataBuilder.toString());
                JSONArray functionData = new JSONArray(functionDataBuilder.toString());
                LOGGER.info("Processing " + classData.length() + " classes and " + functionData.length() + " functions from Ghidra analysis");
                
                // Get active libraries from config
                List<String> activeLibraries = LibraryDefinitions.getActiveLibraries(config);
                
                // Process both class and function data together
                Map<String, JSONArray> classToFunctions = new HashMap<>();
                Map<String, String> classNameMapping = new HashMap<>();

                // First pass: organize functions by class and demangle class names
                for (int i = 0; i < functionData.length(); i++) {
                    JSONObject functionObj = functionData.getJSONObject(i);
                    String functionName = functionObj.getString("FunctionName");
                    String className = functionObj.getString("ClassName");
                    String decompiledCode = functionObj.getString("DecompiledCode");
                    
                    // For Swift binaries, get the class name from the function name
                    if (!config.isMac() && targetMacho.isSwift() && functionName.startsWith("_$s")) {
                        DemangleSwift.DemangledName demangledName = DemangleSwift.demangleSwiftName(functionName);
                        if (demangledName != null) {
                            LOGGER.info("Demangled function name from " + functionName + " to " + demangledName.fullMethodName);
                            className = demangledName.className;
                            functionName = demangledName.fullMethodName;
                            LOGGER.info("Using class name from demangled function: " + className);
                        } else {
                            LOGGER.warning("Failed to demangle Swift symbol: " + functionName);
                        }
                    }
                    
                    // Replace empty class name with "Global" after demangling
                    if (className == null || className.trim().isEmpty()) {
                        className = "Global";
                    }
                    
                    // Check if this class should be treated as a library
                    final String finalClassName = className;
                    boolean isLibrary = activeLibraries.stream()
                            .anyMatch(library -> finalClassName.startsWith(library));

                    if (!isLibrary) {
                        // Process and store the decompiled code only for non-library classes
                        decompiledCode = decompiledCode.replaceAll("/\\*.*\\*/", "");  // Remove Ghidra comments
                        
                        // Add headers with the correct class name
                        if (!decompiledCode.trim().startsWith("// Class:") && !decompiledCode.trim().startsWith("// Function:")) {
                            StringBuilder contentBuilder = new StringBuilder();
                            contentBuilder.append("// Class: ").append(className).append("\n");
                            contentBuilder.append("// Function: ").append(functionName).append("\n\n");
                            contentBuilder.append(decompiledCode.trim());
                            decompiledCode = contentBuilder.toString();
                        }

                        // Store function decompilation with the correct class name
                        String message = "Storing decompilation for " + className + "::" + functionName;
                        LOGGER.info(message);
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept(message);
                        }
                        dbHandler.updateFunctionDecompilation(functionName, className, decompiledCode);
                        
                        // Add to class functions map
                        classToFunctions.computeIfAbsent(className, k -> new JSONArray())
                                        .put(functionName);
                    } else {
                        // For library functions, combine class and function names and store under "Libraries"
                        String libraryFunctionName = className + "::" + functionName;
                        String message = "Storing library function: " + libraryFunctionName;
                        LOGGER.info(message);
                        if (consoleOutputCallback != null) {
                            consoleOutputCallback.accept(message);
                        }
                        functionName = libraryFunctionName;
                        
                        // Store the mapping of original class name to "Libraries"
                        classNameMapping.put(className, "Libraries");
                        
                        dbHandler.updateFunctionDecompilation(libraryFunctionName, "Libraries", null);
                        
                        // Add to class functions map under "Libraries"
                        classToFunctions.computeIfAbsent("Libraries", k -> new JSONArray())
                                        .put(libraryFunctionName);
                    }
                }

                // Store class data for all classes (including libraries)
                for (Map.Entry<String, JSONArray> entry : classToFunctions.entrySet()) {
                    String className = entry.getKey();
                    JSONArray functions = entry.getValue();
                    LOGGER.info("Inserting class: " + className + " with " + functions.length() + " functions");
                    dbHandler.insertClass(className, functions.toString());
                }

                // Add this new section to process strings
                LOGGER.info("Reading string data from Ghidra script");
                StringBuilder stringDataBuilder = new StringBuilder();
                while (!(line = in.readLine()).equals("END_STRING_DATA")) {
                    stringDataBuilder.append(line).append("\n");
                }

                // Process string data
                JSONArray stringData = new JSONArray(stringDataBuilder.toString());
                LOGGER.info("Processing " + stringData.length() + " strings from Ghidra analysis");

                for (int i = 0; i < stringData.length(); i++) {
                    JSONObject stringObj = stringData.getJSONObject(i);
                    String address = stringObj.getString("address");
                    String value = stringObj.getString("value");
                    String segment = stringObj.getString("segment");
                    String label = stringObj.getString("label");
                    LOGGER.info("Inserting string: " + value + " at address: " + address);
                    dbHandler.insertMachoString(address, value, segment, label);
                }

                LOGGER.info("Finished processing all data");
            }

            process.waitFor();
            LOGGER.info("Ghidra analysis completed successfully");

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during Ghidra decompilation", e);
            throw new RuntimeException("Ghidra decompilation failed: " + e.getMessage(), e);
        }
    }    

    private String getAnalyzeHeadlessPath() {
        String analyzeHeadless = Paths.get(config.getGhidraPath(), "support", "analyzeHeadless").toString();
        if (config.isWindows()) {
            analyzeHeadless += ".bat";
        }
        LOGGER.info("Using analyzeHeadless path: " + analyzeHeadless);
        return analyzeHeadless;
    }
}
