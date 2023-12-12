package com.lauriewired.ipax.files;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Macho {
    // Mach-O Magic Numbers
    private static final int FAT_MAGIC = 0xcafebabe;
    private static final int FAT_CIGAM = 0xbebafeca;

    private int cpuType;
    private int cpuSubType;
    private boolean isFat;

    public Macho(String filePath) {
        this.isFat = false;
        processMacho(filePath);
    }

    /*
     * Reads in a Mach-O file and sets instance variables based on type and architecture
     */
    private void processMacho(String filePath) {
        File file = new File(filePath);

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();
            if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
                this.isFat = true;
                System.out.println("Detected FAT binary with architectures:");

                // Adjust byte order for reading
                boolean reverseByteOrder = (magic == FAT_CIGAM);
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(reverseByteOrder ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);

                int archCount = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                for (int i = 0; i < archCount; i++) {
                    raf.seek(8L + i * 20L); // Skip to the architecture info
                    this.cpuType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    this.cpuSubType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    printArchitecture(cpuType, cpuSubType);
                }
            } else {
                this.isFat = false;
                System.out.println("This is not a FAT binary.");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    public void processFatMacho() {
        // Let user select the architecture
        // Extract the target architecture from the current macho
        // Update the instance variables to the newly extracted macho
    }

    public void printArchitecture(int cpuType, int cpuSubType) {
        // TODO: Expand this method to handle different subtypes
        String arch = "Unknown";
        switch (cpuType) {
            case 0x00000007:
                arch = "Intel x86";
                break;
            case 0x01000007:
                arch = "Intel x86_64";
                break;
            case 0x0000000C:
                arch = "ARM";
                break;
            case 0x0100000C:
                arch = "ARM64";
                break;
        }

        System.out.println(arch + " " + cpuSubType);
    }

    public int getCpuType() {
        return this.cpuType;
    }

    public int getCpuSubType() {
        return this.cpuSubType;
    }

    public boolean isFatBinary() {
        return this.isFat;
    }
}
