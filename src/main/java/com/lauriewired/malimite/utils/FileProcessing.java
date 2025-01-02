package com.lauriewired.malimite.utils;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.database.SQLiteDBHandler;

import com.lauriewired.malimite.configuration.Project;
import javax.swing.*;
import java.util.Map;
import com.lauriewired.malimite.configuration.Config;

public class FileProcessing {
    private static final Logger LOGGER = Logger.getLogger(FileProcessing.class.getName());
    private static Config config;

    public static void readStream(InputStream stream) {
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    LOGGER.info(line);
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error reading stream", e);
            }
        }).start();
    }

    public static void unzipExecutable(String zipFilePath, String executableName, String outputFilePath) throws IOException {
        LOGGER.info("Attempting to unzip executable from: " + zipFilePath);
        LOGGER.info("Looking for executable: " + executableName);
        LOGGER.info("Output path: " + outputFilePath);
        
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                LOGGER.info("Examining zip entry: " + entry.getName());
                if (!entry.isDirectory() && entry.getName().endsWith(executableName)) {
                    LOGGER.info("Found matching executable, extracting...");
                    extractFile(zipIn, outputFilePath);
                    LOGGER.info("Successfully extracted executable to: " + outputFilePath);
                    break;
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
    }

    public static void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
            byte[] bytesIn = new byte[4096];
            int read;
            while ((read = zipIn.read(bytesIn)) != -1) {
                bos.write(bytesIn, 0, read);
            }
        }
    }

    public static byte[] readContentFromZip(String zipFilePath, String entryPath) throws IOException {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
    
            while (entry != null) {
                if (entry.getName().equals(entryPath)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = zipIn.read(buffer)) > 0) {
                        out.write(buffer, 0, len);
                    }
                    return out.toByteArray();
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
        return new byte[0]; // Return empty array if the entry is not found
    }

    /*
     * Extracts a macho binary from an IPA file to a new project directory
     * Returns the name of the new project directory
     */
    public static String extractMachoToProjectDirectory(String filePath, String executableName, String projectDirectoryPath) {
        LOGGER.info("filePath: " + filePath + " executableName: " + executableName + " projectDirectoryPath: " + projectDirectoryPath);
        if (filePath == null || filePath.isEmpty()) {
            LOGGER.warning("Invalid file path");
            return "";
        }

        // Extract the base name of the input file
        File inputFile = new File(filePath);
        String baseName = inputFile.getName();
        int lastDotIndex = baseName.lastIndexOf('.');
        if (lastDotIndex > 0) {
            baseName = baseName.substring(0, lastDotIndex);
        }

        // If executableName is empty or null, just use the input file name
        if (executableName == null || executableName.isEmpty()) {
            LOGGER.info("No executable name provided, using input file name: " + baseName);
        } else {
            LOGGER.info("Using executable name: " + executableName);
        }

        // Create project directory name based on input file name
        String projectDirPath = inputFile.getParent() + File.separator + baseName + "_malimite";
        LOGGER.info("Created project directory path: " + projectDirPath);
        
        return projectDirPath;
    }
    
    /*
     * Creates a new malimite project if it doesn't exist
     * Otherwise, reopens an existing project
     */
    public static void openProject(String filePath, String projectDirectoryPath, String executableName, String configDir) {
        // Create malimite project directory
        File projectDirectory = new File(projectDirectoryPath);
        if (!projectDirectory.exists()) {
            if (projectDirectory.mkdir()) {
                LOGGER.info("Created project directory: " + projectDirectoryPath);
                
                // Create and save initial project configuration
                Project project = new Project();
                project.setFileName(executableName);
                project.setFilePath(filePath);
                project.setFileSize(new File(filePath).length());
                
                // Save the project configuration to project.json
                saveProjectConfig(projectDirectoryPath, project);
                addProjectToList(filePath);

                File inputFile = new File(filePath);
                if (isArchiveFile(inputFile)) {
                    // Handle archive files (IPA, ZIP, etc.)
                    if (executableName != null && !executableName.isEmpty()) {
                        // Unzip the executable into the new project directory
                        String outputFilePath = projectDirectoryPath + File.separator + executableName;
                        try {
                            unzipExecutable(filePath, executableName, outputFilePath);
                        } catch (IOException e) {
                            LOGGER.log(Level.SEVERE, "Error unzipping executable", e);
                        }
                    } else {
                        LOGGER.warning("No executable name provided for archive file");
                    }
                } else if (inputFile.isDirectory() || inputFile.getName().endsWith(".app")) {
                    // Handle directories and .app bundles
                    // Find the executable in the directory
                    File[] files = inputFile.listFiles();
                    if (files != null) {
                        for (File file : files) {
                            if (file.getName().equals(executableName)) {
                                // Copy the executable to the project directory
                                String outputFilePath = projectDirectoryPath + File.separator + executableName;
                                try {
                                    Files.copy(file.toPath(), new File(outputFilePath).toPath());
                                    LOGGER.info("Copied executable to: " + outputFilePath);
                                } catch (IOException e) {
                                    LOGGER.log(Level.SEVERE, "Error copying executable", e);
                                }
                                break;
                            }
                        }
                    }
                }
            } else {
                LOGGER.warning("Failed to create project directory: " + projectDirectoryPath);
                return;
            }
        } else {
            // Load existing project configuration
            Project project = loadProjectConfig(projectDirectoryPath);
            if (project != null) {
                LOGGER.info("Loaded existing project: " + project.getFileName());
            }
        }
    }

    private static Project loadProjectConfig(String projectDirectoryPath) {
        try {
            String configPath = projectDirectoryPath + File.separator + "project.json";
            String json = Files.readString(Paths.get(configPath));
            Gson gson = new Gson();
            return gson.fromJson(json, Project.class);
        } catch (IOException e) {
            System.err.println("Failed to load project configuration: " + e.getMessage());
            return null;
        }
    }

    public static boolean isArchiveFile(File file) {
        String name = file.getName().toLowerCase();
        return name.endsWith(".ipa") || 
               name.endsWith(".zip") || 
               name.endsWith(".tar") || 
               name.endsWith(".gz") ||
               name.endsWith(".7z");
    }

    private static void addProjectToList(String projectPath) {
        config.addProjectPath(projectPath);
    }

    // Add this method to set the config
    public static void setConfig(Config configuration) {
        config = configuration;
    }

    public static Project updateFileInfo(File file, Macho macho) {
        Project project = new Project();
        project.setFileName(file.getName());
        project.setFilePath(file.getAbsolutePath());
        project.setFileSize(file.length());
        
        try {
            project.setIsMachO(true);
            project.setMachoInfo(macho);
            project.setIsSwift(macho.isSwift());
            
            if (macho.isUniversalBinary()) {
                project.setFileType("Universal Mach-O Binary");
            } else {
                project.setFileType("Single Architecture Mach-O");
            }
        } catch (Exception ex) {
            project.setFileType("Unknown or unsupported file format");
            project.setIsMachO(false);
            LOGGER.warning("Error reading file format: " + ex.getMessage());
        }

        return project;
    }

    public static void updateFunctionList(JPanel functionAssistPanel, SQLiteDBHandler dbHandler, String className) {
        if (functionAssistPanel != null) {
            JList<?> functionList = (JList<?>) ((JScrollPane) ((JPanel) functionAssistPanel
                .getComponent(1)).getComponent(1)).getViewport().getView();
            DefaultListModel<String> model = (DefaultListModel<String>) functionList.getModel();
            model.clear();
            
            // Get functions for the selected class
            Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
            List<String> functions = classesAndFunctions.get(className);
            
            if (functions != null) {
                for (String function : functions) {
                    model.addElement(function);
                }
            }
            
            // Reset "Select All" checkbox
            JCheckBox selectAllBox = (JCheckBox) ((JPanel) functionAssistPanel
                .getComponent(1)).getComponent(0);
            selectAllBox.setSelected(false);
        }
    }

    private static void saveProjectConfig(String projectDirectoryPath, Project project) {
        try {
            File configFile = new File(projectDirectoryPath + File.separator + "project.json");
            // Create parent directories if they don't exist
            configFile.getParentFile().mkdirs();
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(project);
            Files.writeString(configFile.toPath(), json);
            LOGGER.info("Successfully saved project config to: " + configFile.getAbsolutePath());
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to save project configuration", e);
        }
    }
}
