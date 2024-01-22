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

    /*
     * Extracts a macho binary from an IPA file to the target directory
     */
    public static void unzipExecutable(String zipFilePath, String executableName, String outputFilePath) throws IOException {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(executableName)) { //TODO add file separator?
                    extractFile(zipIn, outputFilePath + File.separator + executableName);
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
     * Takes in a full path to a file name and returns the path without the file name at the end
     */
    public static String removeFileNameFromPath(String path) {
        File file = new File(path);

        // Check if the path actually has a parent directory
        if (file.getParent() != null) {
            // Return the parent directory's path
            return file.getParent() + File.separator;
        } else {
            // Return the original path if it's already a directory or has no parent
            return path;
        }
    }
    
    /*
     * Creates a new Malamite project if it doesn't exist and returns false
     * Otherwise, reopens an existing project and returns true
     */
    public static boolean openProjectDirectory(String projectDirectoryPath) {
        // Create ipax project directory
        File projectDirectory = new File(projectDirectoryPath);
        if (projectDirectory.exists()) {
            //TODO: the project directory already exists so we need to reopen the project
            return true;
        } else {
            if (projectDirectory.mkdir()) {
                System.out.println("Created project directory: " + projectDirectoryPath);
            } else {
                System.out.println("Failed to create project directory: " + projectDirectoryPath);
            }
            return false;
        }
    }
}