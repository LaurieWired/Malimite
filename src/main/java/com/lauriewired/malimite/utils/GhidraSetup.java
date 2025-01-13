package com.lauriewired.malimite.utils;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.file.*;

public class GhidraSetup {
    private static final String JSON_VERSION = "20210307";
    private static final String JSON_JAR = "json-" + JSON_VERSION + ".jar";
    private static final String DOWNLOAD_URL = "https://repo1.maven.org/maven2/org/json/json/" + JSON_VERSION + "/" + JSON_JAR;

    private static boolean runAsAdmin(String[] command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.inheritIO();
            Process process = pb.start();
            return process.waitFor() == 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void setupGhidraLibs(String ghidraPath) {
        Path patchDir = Paths.get(ghidraPath, "Ghidra", "patch");
        Path jsonJarPath = patchDir.resolve(JSON_JAR);

        // First try normal file operations
        try {
            Files.createDirectories(patchDir);
            URL url = new URL(DOWNLOAD_URL);
            try (InputStream in = url.openStream()) {
                Files.copy(in, jsonJarPath, StandardCopyOption.REPLACE_EXISTING);
            }
            JOptionPane.showMessageDialog(null,
                "Required library has been successfully installed.",
                "Setup Complete",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        } catch (IOException e) {
            // If normal operation fails, try with admin privileges
            int response = JOptionPane.showConfirmDialog(null,
                "Failed to install library with normal permissions. Try with admin privileges?",
                "Permission Error",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

            if (response == JOptionPane.YES_OPTION) {
                // Download to temp file first
                Path tempFile = null;
                try {
                    tempFile = Files.createTempFile("ghidra_json_", ".jar");
                    URL url = new URL(DOWNLOAD_URL);
                    try (InputStream in = url.openStream()) {
                        Files.copy(in, tempFile, StandardCopyOption.REPLACE_EXISTING);
                    }

                    // Use sudo commands to create directory and copy file
                    String[] mkdirCommand = {"sudo", "mkdir", "-p", patchDir.toString()};
                    String[] copyCommand = {"sudo", "cp", tempFile.toString(), jsonJarPath.toString()};
                    
                    if (runAsAdmin(mkdirCommand) && runAsAdmin(copyCommand)) {
                        JOptionPane.showMessageDialog(null,
                            "Required library has been successfully installed with admin privileges.",
                            "Setup Complete",
                            JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                } finally {
                    if (tempFile != null) {
                        try {
                            Files.deleteIfExists(tempFile);
                        } catch (IOException ignored) {}
                    }
                }
            }
            
            // If everything fails, show error message
            JOptionPane.showMessageDialog(null,
                "Failed to install library: " + e.getMessage(),
                "Setup Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
} 