package com.lauriewired.malimite.configuration;

public class Config {
    private String osType;
    private String ghidraPath;

    public Config() {
        this.osType = System.getProperty("os.name").toLowerCase();
        this.ghidraPath = System.getenv("GHIDRA_PATH");
    }

    public String getOsType() {
        return osType;
    }

    public boolean isWindows() {
        return osType.contains("win");
    }

    public boolean isMac() {
        return osType.contains("mac");
    }

    public boolean isUnix() {
        return osType.contains("nix") || osType.contains("nux") || osType.contains("aix");
    }

    public String getGhidraPath() {
        return ghidraPath;
    }

    public void setGhidraPath(String ghidraPath) {
        this.ghidraPath = ghidraPath;
    }

    // TODO: Add more machine configurations as needed
}
