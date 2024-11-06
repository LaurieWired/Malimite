package com.lauriewired.malimite.files;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;
import com.lauriewired.malimite.utils.PlistUtils;
import java.util.logging.Logger;
import java.util.logging.Level;

public class MobileProvision {
    private static final Logger LOGGER = Logger.getLogger(MobileProvision.class.getName());

    public static String extractEmbeddedXML(byte[] provisionData) throws Exception {
        LOGGER.info("Attempting to extract embedded XML from provision data");
        try {
            CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(provisionData), provisionData);
            String fullContent = new String((byte[]) signedData.getSignedContent().getContent());

            // Find the start and end of the XML plist content
            int plistStart = fullContent.indexOf("<?xml");
            int plistEnd = fullContent.indexOf("</plist>") + "</plist>".length();

            if (plistStart == -1 || plistEnd == -1) {
                LOGGER.severe("Failed to locate XML plist content in embedded.mobileprovision");
                throw new Exception("Failed to locate XML plist content in embedded.mobileprovision");
            }

            LOGGER.info("Successfully extracted XML content from provision data");
            return fullContent.substring(plistStart, plistEnd);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error extracting embedded XML", e);
            throw e;
        }
    }

    public static String parseProvisioningProfile(byte[] provisionData) {
        LOGGER.info("Starting to parse provisioning profile");
        try {
            String xmlContent = extractEmbeddedXML(provisionData);
            byte[] contentBytes = xmlContent.getBytes();

            // Use PlistUtils to handle binary or XML plist parsing
            if (PlistUtils.isBinaryPlist(contentBytes)) {
                LOGGER.info("Detected binary plist format, proceeding with binary parsing");
                return PlistUtils.decodeBinaryPropertyList(contentBytes);
            } else {
                LOGGER.info("Detected XML plist format, proceeding with XML parsing");
                NSObject parsedPlist = PropertyListParser.parse(contentBytes);
                return parsedPlist.toXMLPropertyList();
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error parsing provisioning profile", e);
            return null;
        }
    }
}