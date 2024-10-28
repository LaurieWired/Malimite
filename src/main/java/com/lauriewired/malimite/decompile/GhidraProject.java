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

public class GhidraProject {
    private static final Logger LOGGER = Logger.getLogger(GhidraProject.class.getName());
    private String ghidraProjectName;
    private Config config;
    private String scriptPath;
    private SQLiteDBHandler dbHandler;
    private static final int PORT = 8765;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath, Config config, SQLiteDBHandler dbHandler) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_malimite";
        this.config = config;
        this.dbHandler = dbHandler;
        // Set script path based on current directory and OS
        String currentDir = System.getProperty("user.dir");
        this.scriptPath = Paths.get(currentDir, "DecompilerBridge", "ghidra").toString();

        LOGGER.info("Initializing GhidraProject with executable: " + infoPlistBundleExecutable);
        LOGGER.info("Script path: " + scriptPath);
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho) {
        LOGGER.info("Starting Ghidra decompilation for: " + executableFilePath);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            serverSocket.setSoTimeout(10000); // 10-second timeout for accepting connections
    
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
                String.valueOf(PORT)
            );
            
            // Redirect Ghidra's output and error streams to your Java application
            builder.redirectErrorStream(true);
            Process process = builder.start();
    
            // Read Ghidra's output and display it in the Java application's console
            try (BufferedReader ghidraOutput = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = ghidraOutput.readLine()) != null) {
                    System.out.println("Ghidra Output: " + line);
                }
            }
    
            LOGGER.info("Starting Ghidra headless analyzer with command: " + String.join(" ", builder.command()));
            LOGGER.info("Waiting for Ghidra script connection on port " + PORT);
            Socket socket = serverSocket.accept();
            LOGGER.info("Connection established with Ghidra script");
    
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
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

                // Process and store the received data
                JSONArray classData = new JSONArray(classDataBuilder.toString());
                LOGGER.info("Processing " + classData.length() + " classes from Ghidra analysis");
                
                for (int i = 0; i < classData.length(); i++) {
                    JSONObject classObj = classData.getJSONObject(i);
                    String className = classObj.getString("ClassName");
                    JSONArray functions = classObj.getJSONArray("Functions");
                    LOGGER.info("Inserting class: " + className + " with " + functions.length() + " functions");
                    dbHandler.insertClass(className, functions.toString());
                }
                LOGGER.info("Finished processing all class data");
            }
    
            process.waitFor();
            LOGGER.info("Ghidra analysis completed successfully");
    
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during Ghidra decompilation", e);
            e.printStackTrace();
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
