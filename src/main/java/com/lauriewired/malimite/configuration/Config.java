package com.lauriewired.malimite.configuration;

import java.io.*;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;

public class Config {
    private static final Logger LOGGER = Logger.getLogger(Config.class.getName());
    private static final String CONFIG_FILE = "malimite.properties";
    private static final String GHIDRA_PATH_KEY = "ghidra.path";
    
    private String osType;
    private String ghidraPath;
    private Properties properties;

    public Config() {
        this.osType = System.getProperty("os.name").toLowerCase();
        this.properties = new Properties();
        loadConfig();
    }

    private void loadConfig() {
        File configFile = new File(CONFIG_FILE);
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
                this.ghidraPath = properties.getProperty(GHIDRA_PATH_KEY);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to load configuration file", e);
            }
        }
    }

    private void saveConfig() {
        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE)) {
            properties.store(fos, "Malimite Configuration");
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to save configuration file", e);
        }
    }

    public String getGhidraPath() {
        return ghidraPath;
    }

    public void setGhidraPath(String ghidraPath) {
        this.ghidraPath = ghidraPath;
        properties.setProperty(GHIDRA_PATH_KEY, ghidraPath);
        saveConfig();
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

    // TODO: Add more machine configurations as needed
}
