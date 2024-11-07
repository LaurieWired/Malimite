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
import java.util.logging.Logger;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.database.SQLiteDBHandler;

import com.lauriewired.malimite.configuration.Project;
import javax.swing.*;
import java.util.Map;

public class FileProcessing {
    private static String configDirectory = ".";
    private static final String PROJECTS_FILENAME = "malimite.projects";
    private static final Logger LOGGER = Logger.getLogger(FileProcessing.class.getName());

    public static void readStream(InputStream stream) {
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }

    public static void unzipExecutable(String zipFilePath, String executableName, String outputFilePath) throws IOException {
        System.out.println("Attempting to unzip executable from: " + zipFilePath);
        System.out.println("Looking for executable: " + executableName);
        System.out.println("Output path: " + outputFilePath);
        
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                System.out.println("Examining zip entry: " + entry.getName());
                if (!entry.isDirectory() && entry.getName().endsWith(executableName)) {
                    System.out.println("Found matching executable, extracting...");
                    extractFile(zipIn, outputFilePath);
                    System.out.println("Successfully extracted executable to: " + outputFilePath);
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
        if (filePath == null || filePath.isEmpty() || 
            executableName == null || executableName.isEmpty()) {
            System.out.println("Failed to extract executable");
            return "";
        }

        System.out.println(filePath + " " + executableName);

        // Extract the base name of the .ipa file
        File ipaFile = new File(filePath);
        String baseName = ipaFile.getName().replaceFirst("[.][^.]+$", "");
        return ipaFile.getParent() + File.separator + baseName + "_malimite";
    }
    
    /*
     * Creates a new malimite project if it doesn't exist
     * Otherwise, reopens an existing project
     */
    public static void openProject(String filePath, String projectDirectoryPath, String executableName, String configDir) {
        setConfigDirectory(configDir);  // Set the config directory before any operations
        
        // Create malimite project directory
        File projectDirectory = new File(projectDirectoryPath);
        if (!projectDirectory.exists()) {
            if (projectDirectory.mkdir()) {
                System.out.println("Created project directory: " + projectDirectoryPath);
                
                // Create and save initial project configuration
                Project project = new Project();
                project.setFileName(executableName);
                project.setFilePath(filePath);
                project.setFileSize(new File(filePath).length());
                
                saveProjectConfig(projectDirectoryPath, project);
                addProjectToList(filePath);

                // Unzip the executable into the new project directory
                String outputFilePath = projectDirectoryPath + File.separator + executableName;
                try {
                    unzipExecutable(filePath, executableName, outputFilePath);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("Failed to create project directory: " + projectDirectoryPath);
                return;
            }
        } else {
            // Load existing project configuration
            Project project = loadProjectConfig(projectDirectoryPath);
            if (project != null) {
                System.out.println("Loaded existing project: " + project.getFileName());
            }
        }
    }

    private static void saveProjectConfig(String projectDirectoryPath, Project project) {
        try {
            File configFile = new File(projectDirectoryPath + File.separator + "project.json");
            // Create parent directories if they don't exist
            configFile.getParentFile().mkdirs();
            // Create the file if it doesn't exist
            if (!configFile.exists()) {
                configFile.createNewFile();
            }
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(project);
            Files.writeString(configFile.toPath(), json);
            System.out.println("Successfully saved project config");
        } catch (IOException e) {
            System.err.println("Failed to save project configuration: " + e.getMessage());
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

    private static void addProjectToList(String projectPath) {
        List<String> projects = loadProjectsList();
        if (!projects.contains(projectPath)) {
            projects.add(projectPath);
            saveProjectsList(projects);
        }
    }

    private static List<String> loadProjectsList() {
        try {
            File projectsFile = new File(getProjectsFilePath());
            // Ensure the directory exists
            projectsFile.getParentFile().mkdirs();
            
            if (projectsFile.exists()) {
                String json = Files.readString(Paths.get(getProjectsFilePath()));
                Gson gson = new Gson();
                Type listType = new TypeToken<ArrayList<String>>(){}.getType();
                return gson.fromJson(json, listType);
            }
        } catch (IOException e) {
            System.err.println("Failed to load projects list: " + e.getMessage());
        }
        return new ArrayList<>();
    }

    private static void saveProjectsList(List<String> projects) {
        try {
            String projectsPath = getProjectsFilePath();
            System.out.println("Saving projects list to: " + projectsPath);
            System.out.println("Projects to save: " + String.join(", ", projects));
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(projects);
            Files.writeString(Paths.get(projectsPath), json);
            System.out.println("Successfully saved projects list");
        } catch (IOException e) {
            System.err.println("Failed to save projects list: " + e.getMessage());
        }
    }

    // Add this utility method to get all known project paths
    public static List<String> getProjectPaths() {
        return loadProjectsList();
    }

    // Add this method to set the config directory
    public static void setConfigDirectory(String directory) {
        configDirectory = directory;
    }

    // Update to use configDirectory
    private static String getProjectsFilePath() {
        return configDirectory + File.separator + PROJECTS_FILENAME;
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
}
