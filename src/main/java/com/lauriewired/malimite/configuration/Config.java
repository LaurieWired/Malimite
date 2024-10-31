package com.lauriewired.malimite.configuration;

import java.io.*;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;

public class Config {
    private static final Logger LOGGER = Logger.getLogger(Config.class.getName());
    private static final String CONFIG_FILE = "malimite.properties";
    private static final String GHIDRA_PATH_KEY = "ghidra.path";
    private static final String THEME_KEY = "app.theme";
    private static final String OS_TYPE_KEY = "os.type";
    
    private String osType;
    private String ghidraPath;
    private String theme;
    private Properties properties;
    private String configDirectory;

    public Config() {
        this.osType = System.getProperty("os.name").toLowerCase();
        this.properties = new Properties();
        this.configDirectory = ".";
        loadConfig();
        
        properties.setProperty(OS_TYPE_KEY, this.osType);
        
        if (this.theme == null) {
            this.theme = "dark";
            properties.setProperty(THEME_KEY, this.theme);
            saveConfig();
        }
    }

    public void loadConfig() {
        File configFile = new File(CONFIG_FILE);
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
                this.configDirectory = configFile.getParent() != null ? configFile.getParent() : ".";
                this.ghidraPath = properties.getProperty(GHIDRA_PATH_KEY);
                this.theme = properties.getProperty(THEME_KEY);
                this.osType = properties.getProperty(OS_TYPE_KEY, System.getProperty("os.name").toLowerCase());
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to load configuration file", e);
            }
        }
    }

    public void saveConfig() {
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

    public String getTheme() {
        return theme;
    }

    public void setTheme(String theme) {
        this.theme = theme;
        properties.setProperty(THEME_KEY, theme);
        saveConfig();
    }

    public String getConfigDirectory() {
        return configDirectory;
    }
}
