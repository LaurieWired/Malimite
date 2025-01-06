package com.lauriewired.malimite.files;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class Macho {
    private static final Logger LOGGER = Logger.getLogger(Macho.class.getName());

    // Mach-O Magic Numbers
    private static final int UNIVERSAL_MAGIC = 0xcafebabe;
    private static final int UNIVERSAL_CIGAM = 0xbebafeca;

    private List<Integer> cpuTypes;
    private List<Integer> cpuSubTypes;
    private List<Long> offsets;
    private List<Long> sizes;
    private boolean isUniversal;
    private String machoExecutablePath;
    private String outputDirectoryPath;
    private String machoExecutableName;
    private boolean isSwift = false;

    public Macho(String machoExecutablePath, String outputDirectoryPath, String machoExecutableName) {
        this.isUniversal = false;
        this.cpuTypes = new ArrayList<>();
        this.cpuSubTypes = new ArrayList<>();
        this.offsets = new ArrayList<>();
        this.sizes = new ArrayList<>();
        this.machoExecutablePath = machoExecutablePath;
        this.outputDirectoryPath = outputDirectoryPath;
        this.machoExecutableName = machoExecutableName;

        processMacho();
    }

    public void processUniversalMacho(String selectedArchitecture) {
        extractMachoArchitecture(selectedArchitecture);

        // We do not care about the original macho anymore
        // This will effectively reset the instance variables for the extracted macho
        processMacho();
    }


    private void extractMachoArchitecture(String selectedArchitecture) {
        for (int i = 0; i < cpuTypes.size(); i++) {
            String arch = getArchitectureName(cpuTypes.get(i));
            String fullArchitecture = generateFullArchitectureString(arch, cpuTypes.get(i), cpuSubTypes.get(i));

            if (fullArchitecture.equals(selectedArchitecture)) {
                String tempFileName = machoExecutableName + "_extracted.macho";
                try {
                    extractSlice(machoExecutablePath, tempFileName, offsets.get(i), sizes.get(i));
                    LOGGER.info("Extracted " + arch + " slice to " + tempFileName);

                    replaceOldMachoWithNew(tempFileName);
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error extracting Mach-O slice", e);
                }
                break;
            }
        }
    }

    private void extractSlice(String inputFilePath, String outputFileName, long offset, long size) throws IOException {
        // Construct the full path for the output file
        String outputPath = outputDirectoryPath + File.separator + outputFileName;

        try (RandomAccessFile inputFile = new RandomAccessFile(inputFilePath, "r");
             FileOutputStream outputFile = new FileOutputStream(outputPath)) {

            inputFile.seek(offset);
            byte[] buffer = new byte[8192];
            long remaining = size;

            while (remaining > 0) {
                int bytesRead = inputFile.read(buffer, 0, (int) Math.min(buffer.length, remaining));
                if (bytesRead == -1) break;

                outputFile.write(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }
        }
    }

    private void replaceOldMachoWithNew(String tempFileName) throws IOException {
        File oldMacho = new File(machoExecutablePath);
        File extractedMacho = new File(outputDirectoryPath + File.separator + tempFileName);
        File newMacho = new File(machoExecutablePath);

        if (oldMacho.delete()) {
            if (!extractedMacho.renameTo(newMacho)) {
                throw new IOException("Failed to rename extracted Mach-O file.");
            }
            LOGGER.info("Replaced old Mach-O file with the extracted one.");
        } else {
            throw new IOException("Failed to delete old Mach-O file.");
        }
    }

    /*
     * Reads in a Mach-O file and sets instance variables based on type and architecture
     */
    private void processMacho() {
        File file = new File(this.machoExecutablePath);

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();
            if (magic == UNIVERSAL_MAGIC || magic == UNIVERSAL_CIGAM) {
                this.isUniversal = true;
                LOGGER.info("Detected Universal binary with architectures:");

                boolean reverseByteOrder = (magic == UNIVERSAL_CIGAM);
                int archCount = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                for (int i = 0; i < archCount; i++) {
                    raf.seek(8L + i * 20L);
                    int cpuType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    int cpuSubType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long offset = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    long size = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();

                    cpuTypes.add(cpuType);
                    cpuSubTypes.add(cpuSubType);
                    offsets.add(offset);
                    sizes.add(size);
                }
            } else {
                this.isUniversal = false;
                LOGGER.info("This is not a Universal binary.");
            }

            // After processing the Mach-O headers, check for Swift
            detectSwift(file);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading file", e);
        }
    }

    private void detectSwift(File file) {
        try {
            // Read the file content as bytes
            byte[] content = Files.readAllBytes(file.toPath());
            String stringContent = new String(content, StandardCharsets.UTF_8);

            // Look for common Swift indicators in the binary
            isSwift = stringContent.contains("Swift Runtime") || 
                      stringContent.contains("SwiftCore") ||
                      stringContent.contains("_swift_") ||
                      stringContent.contains("_$s");  // Swift name mangling prefix

            LOGGER.info("Binary detected as: " + (isSwift ? "Swift" : "Objective-C"));
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error detecting Swift/Objective-C", e);
            isSwift = false; // Default to Objective-C if detection fails
        }
    }

    public static class Architecture {
        private String name;
        private int cpuType;
        private int cpuSubType;
        
        public Architecture(String name, int cpuType, int cpuSubType) {
            this.name = name;
            this.cpuType = cpuType;
            this.cpuSubType = cpuSubType;
        }
        
        @Override
        public String toString() {
            return name + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
        }
        
        // Getters
        public String getName() { return name; }
        public int getCpuType() { return cpuType; }
        public int getCpuSubType() { return cpuSubType; }
    }

    private String getArchitectureName(int cpuType) {
        switch (cpuType) {
            case 0x00000007: return "Intel x86";
            case 0x01000007: return "Intel x86_64";
            case 0x0000000C: return "ARM";
            case 0x0100000C: return "ARM64";
            default: return "Unknown";
        }
    }

    public List<Architecture> getArchitectures() {
        List<Architecture> architectures = new ArrayList<>();
        for (int i = 0; i < cpuTypes.size(); i++) {
            architectures.add(new Architecture(
                getArchitectureName(cpuTypes.get(i)),
                cpuTypes.get(i),
                cpuSubTypes.get(i)
            ));
        }
        return architectures;
    }

    public List<String> getArchitectureStrings() {
        List<String> architectureStrings = new ArrayList<>();

        for (int i = 0; i < cpuTypes.size(); i++) {
            int cpuType = cpuTypes.get(i);
            int cpuSubType = cpuSubTypes.get(i);
            String arch = getArchitectureName(cpuType);

            String fullArchitecture = generateFullArchitectureString(arch, cpuType, cpuSubType);
            architectureStrings.add(fullArchitecture);
        }

        return architectureStrings;
    } 

    public void printArchitectures() {
        String arch = "";
        String fullArchitecture = "";

        for (int i = 0; i < cpuTypes.size(); i++) {
            int cpuType = cpuTypes.get(i);
            int cpuSubType = cpuSubTypes.get(i);
            arch = getArchitectureName(cpuType);

            fullArchitecture = generateFullArchitectureString(arch, cpuType, cpuSubType);
            LOGGER.info(fullArchitecture);
        }
    }

    private String generateFullArchitectureString(String arch, int cpuType, int cpuSubType) {
        return arch + " (CPU Type: " + cpuType + ", SubType: " + cpuSubType + ")";
    }

    public List<Integer> getCpuTypes() {
        return cpuTypes;
    }

    public List<Integer> getCpuSubTypes() {
        return cpuSubTypes;
    }

    public boolean isUniversalBinary() {
        return this.isUniversal;
    }

    public String getMachoExecutableName() {
        return this.machoExecutableName;
    }

    public boolean isSwift() {
        return isSwift;
    }
}
