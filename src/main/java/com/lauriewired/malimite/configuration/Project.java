package com.lauriewired.malimite.configuration;

import com.lauriewired.malimite.files.Macho;

public class Project {
    private String fileName;
    private String filePath;
    private long fileSize;
    private String fileType;
    private boolean isMachO;
    private Macho machoInfo;  // Reference to Macho object if this is a Mach-O file
    private String bundleIdentifier;  // Add this field
    private boolean isSwift;
    
    public Project() {
    }
    
    // Basic file info getters/setters
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    
    public String getFileType() { return fileType; }
    public void setFileType(String fileType) { this.fileType = fileType; }
    
    public boolean isMachO() { return isMachO; }
    public void setIsMachO(boolean isMachO) { this.isMachO = isMachO; }
    
    public Macho getMachoInfo() { return machoInfo; }
    public void setMachoInfo(Macho machoInfo) { this.machoInfo = machoInfo; }
    
    public String getBundleIdentifier() { return bundleIdentifier; }
    public void setBundleIdentifier(String bundleIdentifier) { this.bundleIdentifier = bundleIdentifier; }
    
    public boolean isSwift() { return isSwift; }
    public void setIsSwift(boolean isSwift) { this.isSwift = isSwift; }
    
    public String generateInfoString() {
        StringBuilder info = new StringBuilder("<html>");
        info.append("<h3>File Analysis Report</h3>");
        info.append("<p><b>File:</b> ").append(fileName).append("</p>");
        info.append("<p><b>Size:</b> ").append(fileSize / 1024).append(" KB</p>");
        info.append("<p><b>Type:</b> ").append(fileType).append("</p>");
        
        if (bundleIdentifier != null && !bundleIdentifier.isEmpty()) {
            info.append("<p><b>Bundle ID:</b> ").append(bundleIdentifier).append("</p>");
        }
        
        if (isMachO && machoInfo != null) {
            info.append("<h4>Mach-O Analysis</h4>");
            info.append("<p><b>Language:</b> ").append(this.isSwift ? "Swift" : "Objective-C").append("</p>");
            if (machoInfo.isUniversalBinary()) {
                info.append("<p><b>Universal Binary:</b> Yes</p>");
                info.append("<p><b>Architectures:</b></p><ul>");
                for (Macho.Architecture arch : machoInfo.getArchitectures()) {
                    info.append("<li>").append(arch.toString()).append("</li>");
                }
                info.append("</ul>");
            }
        }
        
        info.append("</html>");
        return info.toString();
    }
}
