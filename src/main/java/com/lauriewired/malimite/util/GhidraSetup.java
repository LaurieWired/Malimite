package com.lauriewired.malimite.util;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.file.*;

public class GhidraSetup {
    private static final String JSON_VERSION = "20210307";
    private static final String JSON_JAR = "json-" + JSON_VERSION + ".jar";
    private static final String DOWNLOAD_URL = "https://repo1.maven.org/maven2/org/json/json/" + JSON_VERSION + "/" + JSON_JAR;

    public static void setupGhidraLibs(String ghidraPath) {
        Path patchDir = Paths.get(ghidraPath, "Ghidra", "patch");
        Path jsonJarPath = patchDir.resolve(JSON_JAR);

        // Create patch directory if it doesn't exist
        try {
            Files.createDirectories(patchDir);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, 
                "Failed to create patch directory: " + e.getMessage(),
                "Setup Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Download and save the JSON library
        try {
            URL url = new URL(DOWNLOAD_URL);
            try (InputStream in = url.openStream()) {
                Files.copy(in, jsonJarPath, StandardCopyOption.REPLACE_EXISTING);
            }
            JOptionPane.showMessageDialog(null,
                "Required library has been successfully installed.",
                "Setup Complete",
                JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null,
                "Failed to download library: " + e.getMessage(),
                "Download Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
} 