package com.lauriewired.malimite.utils;

import java.util.Arrays;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class PlistUtils {
    /*
     * Returns true if it's a binary plist
     * Returns false if it is an XML plist
     */
    public static boolean isBinaryPlist(byte[] contentBytes) {
        if (contentBytes.length < "bplist".length()) {
            return false;
        }
        String header = new String(Arrays.copyOf(contentBytes, "bplist".length()));

        return header.equals("bplist");
    }

    /*
     * Takes in a binary or XML Info.plist and returns the CFBundleExecutable value
     */
    public static String extractCFBundleExecutable(NSObject plist) {
        String infoPlistBundleExecutable = "";

        if (plist instanceof NSDictionary) {
            NSDictionary dict = (NSDictionary) plist;
            String executableName = dict.objectForKey("CFBundleExecutable").toString();

            infoPlistBundleExecutable = executableName;
        }

        return infoPlistBundleExecutable;
    }

    /*
     * Inputs the binary plist as a byte array
     * Returns the decoded plist in JSON format
     * Do it this way because using the plist library instead of built-in mac libs makes this cross-platform
     */
    public static String decodeBinaryPropertyList(byte[] plistData) {
        try {
            NSObject plist = PropertyListParser.parse(plistData);
            Object javaObj = plist.toJavaObject();
    
            // Use Gson to format it as a JSON string
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            return gson.toJson(javaObj);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
