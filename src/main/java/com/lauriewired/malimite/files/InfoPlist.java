package com.lauriewired.malimite.files;

import java.util.Map;
import javax.swing.tree.DefaultMutableTreeNode;

import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.utils.FileProcessing;
import com.dd.plist.NSDictionary;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;

public class InfoPlist {
    private String infoPlistBundleExecutable;
    private String bundleIdentifier;

    public InfoPlist(DefaultMutableTreeNode infoPlistNode, String filePath, Map<String, String> fileEntriesMap) {
        try {
            String infoPlistPath = NodeOperations.buildFullPathFromNode(infoPlistNode);
            byte[] plistData = FileProcessing.readContentFromZip(filePath, fileEntriesMap.get(infoPlistPath));
            
            if (PlistUtils.isBinaryPlist(plistData)) {
                // Handle binary plist
                NSObject plist = PropertyListParser.parse(plistData);
                infoPlistBundleExecutable = extractCFBundleExecutable(plist);
                bundleIdentifier = extractCFBundleIdentifier(plist);
            } else {
                // Handle XML plist
                String plistContent = new String(plistData);
                NSObject plist = PropertyListParser.parse(plistContent.getBytes());
                infoPlistBundleExecutable = extractCFBundleExecutable(plist);
                bundleIdentifier = extractCFBundleIdentifier(plist);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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
     * Takes in a binary or XML Info.plist and returns the CFBundleIdentifier value
     */
    public static String extractCFBundleIdentifier(NSObject plist) {
        String bundleIdentifier = "";

        if (plist instanceof NSDictionary) {
            NSDictionary dict = (NSDictionary) plist;
            String identifier = dict.objectForKey("CFBundleIdentifier").toString();
            bundleIdentifier = identifier;
        }

        return bundleIdentifier;
    }

    public String getExecutableName() {
        return this.infoPlistBundleExecutable;
    }

    public String getBundleIdentifier() {
        return this.bundleIdentifier;
    }
}