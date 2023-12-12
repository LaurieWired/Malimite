package com.lauriewired.ipax.utils;

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

public class FileProcessing {

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
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(executableName)) {
                    extractFile(zipIn, outputFilePath);
                    break;
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
    }

    public static void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
            byte[] bytesIn = new byte[4096]; //TODO: remove magic number
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
    private void processExecutable() {
        if (this.currentFilePath == null || this.currentFilePath.isEmpty() || 
            this.infoPlistBundleExecutable == null || this.infoPlistBundleExecutable.isEmpty()) {
            System.out.println("Failed to extract executable");
            return;
        }

        System.out.println(this.currentFilePath + " " + this.infoPlistBundleExecutable);

        // Extract the base name of the .ipa file
        File ipaFile = new File(this.currentFilePath);
        String baseName = ipaFile.getName().replaceFirst("[.][^.]+$", "");
        this.projectDirectoryPath = ipaFile.getParent() + File.separator + baseName + "_ipax";

        // Create ipax project directory
        File projectDirectory = new File(this.projectDirectoryPath);
        if (!projectDirectory.exists()) {
            if (projectDirectory.mkdir()) {
                System.out.println("Created project directory: " + this.projectDirectoryPath);
            } else {
                System.out.println("Failed to create project directory: " + this.projectDirectoryPath);
                return;
            }

            // Unzip the executable into the new project directory
            // Unfortunately we have to extract it for ghidra to process it in headless mode
            String outputFilePath = this.projectDirectoryPath + File.separator + this.infoPlistBundleExecutable;
            try {
                unzipExecutable(this.currentFilePath, this.infoPlistBundleExecutable, outputFilePath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            //TODO: add handling for reopening an existing ipax project
            System.out.println("Project '" + this.ghidraProjectName + "' already exists.");

            //will need to add project name + classes + xrefs + user comments
            //reopening will populate this into ipax
            //maybe should add resource node structure here as an optimization
        }
    }*/
}