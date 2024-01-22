package com.lauriewired.malimite.files;

import java.util.Map;
import javax.swing.tree.DefaultMutableTreeNode;

import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.utils.FileProcessing;

import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;

public class InfoPlist {
    private String infoPlistBundleExecutable; // CFBundleExecutable from Info.plist

    public InfoPlist(String zipFilePath, String plistPath) {
        try {
            byte[] plistData = FileProcessing.readContentFromZip(zipFilePath, plistPath);
    
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

            System.out.println(this.infoPlistBundleExecutable);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getExecutableName() {
        return this.infoPlistBundleExecutable;
    }
}