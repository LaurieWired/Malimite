package com.lauriewired.malimite.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import com.lauriewired.malimite.files.MobileProvision;
import com.lauriewired.malimite.database.SQLiteDBHandler;
public class ResourceParser {

    private static SQLiteDBHandler dbHandler;

    public static void setDatabaseHandler(SQLiteDBHandler handler) {
        dbHandler = handler;
    }

    // Predefined patterns for identifying resource files
    private static final List<Pattern> RESOURCE_PATTERNS = Arrays.asList(
        Pattern.compile(".*\\.plist$"),                 // Property list files
        Pattern.compile(".*\\.strings$"),               // Localization string files
        Pattern.compile(".*\\.json$"),                  // JSON configuration files
        Pattern.compile(".*\\.xml$"),                   // XML files
        Pattern.compile(".*\\.mobileprovision$"),       // Provisioning profiles
        Pattern.compile(".*\\.storyboardc$"),           // Interface builder files
        Pattern.compile(".*\\.xcassets$"),              // Asset catalogs
        Pattern.compile(".*\\.nib$")                    // Interface builder files
    );

    /**
     * Checks if a file name matches any predefined resource pattern.
     */
    public static boolean isResource(String fileName) {
        System.out.println("LAURIE checking if " + fileName + " is a resource");
        for (Pattern pattern : RESOURCE_PATTERNS) {
            if (pattern.matcher(fileName).matches()) {
                System.out.println("LAURIE YES " + fileName + " is a resource");
                return true;
            }
        }
        return false;
    }

    /**
     * Parses a resource file for readable strings from an input stream.
     * This function handles text-based resources and excludes binary data.
     */
    public static void parseResourceForStrings(InputStream inputStream, String fileName) {
        try {
            // Convert input stream to byte array for multiple reads
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[4096];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            byte[] contentBytes = buffer.toByteArray();

            // Add debug print for file processing
            System.out.println("Processing file: " + fileName);

            // Handle different file types
            String content;
            if (fileName.endsWith(".plist")) {
                content = handlePlist(contentBytes);
                System.out.println("Processed as plist file");
            } else if (fileName.endsWith("embedded.mobileprovision")) {
                content = MobileProvision.extractEmbeddedXML(contentBytes);
                System.out.println("Processed as mobileprovision file");
            } else {
                content = new String(contentBytes, StandardCharsets.UTF_8);
                System.out.println("Processed as regular text file");
            }

            // Process the content line by line
            try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null) {
                    lineCount++;
                    System.out.println("Line " + lineCount + ": " + line);
                    
                    if (!line.trim().isEmpty()) {
                        System.out.println("  -> Line is not empty");
                        // Split the line into segments of printable characters
                        String[] segments = line.split("[^\\p{Print}]+");
                        for (String segment : segments) {
                            // Only process segments that are 4 characters or longer
                            if (!segment.isEmpty() && segment.length() >= 4) {
                                System.out.println("  -> Found printable segment: " + segment);
                                if (dbHandler != null) {
                                    dbHandler.insertResourceString(fileName, segment, getResourceType(fileName));
                                    System.out.println("  -> INSERTED: " + segment);
                                } else {
                                    System.out.println("  -> NOT INSERTED: dbHandler is null");
                                }
                            }
                        }
                    } else {
                        System.out.println("  -> Empty line - SKIPPED");
                    }
                }
                System.out.println("Total lines processed: " + lineCount);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error processing file: " + e.getMessage());
        }
    }

    private static String handlePlist(byte[] contentBytes) throws Exception {
        if (PlistUtils.isBinaryPlist(contentBytes)) {
            return PlistUtils.decodeBinaryPropertyList(contentBytes);
        }
        return new String(contentBytes, StandardCharsets.UTF_8);
    }

    private static String getResourceType(String fileName) {
        if (fileName.endsWith(".plist")) return "plist";
        if (fileName.endsWith(".strings")) return "strings";
        if (fileName.endsWith(".json")) return "json";
        if (fileName.endsWith(".xml")) return "xml";
        if (fileName.endsWith(".mobileprovision")) return "mobileprovision";
        if (fileName.endsWith(".storyboardc")) return "storyboard";
        if (fileName.endsWith(".xcassets")) return "assets";
        if (fileName.endsWith(".nib")) return "nib";
        return "unknown";
    }
}
