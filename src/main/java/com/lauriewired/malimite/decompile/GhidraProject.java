package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.configuration.Config;
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

import org.antlr.v4.runtime.tree.ParseTree;

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
            serverSocket.setSoTimeout(300000); // 5 minute timeout

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
            LOGGER.info("Connection established with Ghidra script");

            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                // Wait for initial connection confirmation
                String connectionConfirmation = in.readLine();
                if (!"CONNECTED".equals(connectionConfirmation)) {
                    throw new RuntimeException("Did not receive proper connection confirmation from Ghidra script");
                }
                LOGGER.info("Ghidra script confirmed connection, beginning analysis");

                // Reset socket timeout to unlimited for the actual analysis
                socket.setSoTimeout(0);
                
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
                
                // Process class data as before
                for (int i = 0; i < classData.length(); i++) {
                    JSONObject classObj = classData.getJSONObject(i);
                    String className = classObj.getString("ClassName");
                    JSONArray functions = classObj.getJSONArray("Functions");
                    LOGGER.info("Inserting class: " + className + " with " + functions.length() + " functions");
                    dbHandler.insertClass(className, functions.toString());
                }

                // Process new function data
                for (int i = 0; i < functionData.length(); i++) {
                    JSONObject functionObj = functionData.getJSONObject(i);
                    String className = functionObj.getString("ClassName");
                    String functionName = functionObj.getString("FunctionName");
                    String decompiledCode = functionObj.getString("DecompiledCode");
                    
                    // Remove Ghidra comments before parsing
                    decompiledCode = decompiledCode.replaceAll("/\\*.*\\*/", "");  // Ghidra comments
                    
                    // Add headers first
                    if (!decompiledCode.trim().startsWith("// Class:") && !decompiledCode.trim().startsWith("// Function:")) {
                        StringBuilder contentBuilder = new StringBuilder();
                        contentBuilder.append("// Class: ").append(className).append("\n");
                        contentBuilder.append("// Function: ").append(functionName).append("\n\n");
                        contentBuilder.append(decompiledCode.trim());
                        decompiledCode = contentBuilder.toString();
                    }

                    // Then parse and format the code with headers included
                    SyntaxParser parser = new SyntaxParser(null);
                    String formattedCode = parser.parseAndFormatCode(decompiledCode);
                    
                    // Now collect cross-references from the formatted code
                    parser = new SyntaxParser(dbHandler);
                    parser.setContext(functionName, className);
                    parser.collectCrossReferences(formattedCode);

                    // Store the formatted code
                    LOGGER.info("Updating function: " + functionName + " in class: " + className + " with formatted code");
                    dbHandler.updateFunctionDecompilation(functionName, className, formattedCode);
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
