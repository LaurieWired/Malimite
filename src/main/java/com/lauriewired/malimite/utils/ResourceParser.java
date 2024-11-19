package com.lauriewired.malimite.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.logging.Logger;
import com.lauriewired.malimite.files.MobileProvision;
import com.lauriewired.malimite.database.SQLiteDBHandler;
public class ResourceParser {

    private static SQLiteDBHandler dbHandler;
    private static final Logger LOGGER = Logger.getLogger(ResourceParser.class.getName());

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
        Pattern.compile(".*\\.nib$"),                   // Interface builder files
        Pattern.compile(".*\\.xib$")                    // Interface builder files (newly added)
    );

    /**
     * Checks if a file name matches any predefined resource pattern.
     */
    public static boolean isResource(String fileName) {
        LOGGER.fine("Checking if file is a resource: " + fileName);
        for (Pattern pattern : RESOURCE_PATTERNS) {
            if (pattern.matcher(fileName).matches()) {
                LOGGER.fine("File identified as resource: " + fileName);
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

            LOGGER.info("Processing file: " + fileName);

            // Handle different file types
            String content;
            if (fileName.endsWith(".plist")) {
                content = handlePlist(contentBytes);
                LOGGER.fine("Processed as plist file");
            } else if (fileName.endsWith("embedded.mobileprovision")) {
                content = MobileProvision.extractEmbeddedXML(contentBytes);
                LOGGER.fine("Processed as mobileprovision file");
            } else {
                content = new String(contentBytes, StandardCharsets.UTF_8);
                LOGGER.fine("Processed as regular text file");
            }

            // Process the content line by line
            try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null) {
                    lineCount++;
                    
                    if (!line.trim().isEmpty()) {
                        String[] segments = line.split("[^\\p{Print}]+");
                        for (String segment : segments) {
                            String trimmedSegment = segment.trim();
                            if (!trimmedSegment.isEmpty() && trimmedSegment.replaceAll("\\s+", "").length() > 4) {
                                if (dbHandler != null) {
                                    // Store the trimmed segment
                                    dbHandler.insertResourceString(fileName, trimmedSegment, getResourceType(fileName));
                                    LOGGER.fine("Inserted resource string: " + trimmedSegment + " for path: " + fileName);
                                }
                            }
                        }
                    }
                }
                LOGGER.info("Completed processing " + lineCount + " lines");
            }
        } catch (IOException e) {
            LOGGER.severe("Error reading file: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.severe("Error processing file: " + e.getMessage());
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
