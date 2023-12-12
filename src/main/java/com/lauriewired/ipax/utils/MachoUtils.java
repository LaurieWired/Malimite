package com.lauriewired.ipax.utils;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MachoUtils {
    // Mach-O Magic Numbers
    private static final int FAT_MAGIC = 0xcafebabe;
    private static final int FAT_CIGAM = 0xbebafeca;

    public static void analyzeMachOFile(String filePath) {
        File file = new File(filePath);

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();
            if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
                System.out.println("Detected FAT binary with architectures:");

                // Adjust byte order for reading
                boolean reverseByteOrder = (magic == FAT_CIGAM);
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(reverseByteOrder ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);

                int archCount = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                for (int i = 0; i < archCount; i++) {
                    raf.seek(8L + i * 20L); // Skip to the architecture info
                    int cpuType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    int cpuSubType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    printArchitecture(cpuType, cpuSubType);
                }
            } else {
                System.out.println("This is not a FAT binary.");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    public static void printArchitecture(int cpuType, int cpuSubType) {
        // Expand this method to handle different subtypes
        String arch = "Unknown";
        switch (cpuType) {
            case 0x00000007: // Intel x86
                arch = "Intel x86";
                break;
            case 0x01000007: // Intel x86_64
                arch = "Intel x86_64";
                break;
            case 0x0000000C: // ARM
                arch = "ARM";
                break;
            case 0x0100000C: // ARM64
                arch = "ARM64";
                break;
        }

        System.out.println(arch + " " + cpuSubType);
    }
}
