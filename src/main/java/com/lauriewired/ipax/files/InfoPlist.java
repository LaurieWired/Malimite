package com.lauriewired.ipax.files;

import java.util.Map;
import javax.swing.tree.DefaultMutableTreeNode;

import com.lauriewired.ipax.utils.NodeOperations;
import com.lauriewired.ipax.utils.PlistUtils;
import com.lauriewired.ipax.utils.FileProcessing;

import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;

public class InfoPlist {
    private String infoPlistBundleExecutable; // CFBundleExecutable from Info.plist

    public InfoPlist(DefaultMutableTreeNode infoPlistNode, String filePath, Map<String, String> fileEntriesMap) {
        try {
            String infoPlistPath = NodeOperations.buildFullPathFromNode(infoPlistNode);
            byte[] plistData = FileProcessing.readContentFromZip(filePath, fileEntriesMap.get(infoPlistPath));
    
            if (PlistUtils.isBinaryPlist(plistData)) {
                // Handle binary plist
                NSObject plist = PropertyListParser.parse(plistData);
                infoPlistBundleExecutable = PlistUtils.extractCFBundleExecutable(plist);
            } else {
                // Handle XML plist
                String plistContent = new String(plistData);
                NSObject plist = PropertyListParser.parse(plistContent.getBytes());
                infoPlistBundleExecutable = PlistUtils.extractCFBundleExecutable(plist);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getExecutableName() {
        return this.infoPlistBundleExecutable;
    }
}