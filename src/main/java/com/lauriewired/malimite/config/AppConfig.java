package com.lauriewired.malimite.config;

public class AppConfig {

    public enum Theme {
        DARK("Dark", "/style/dark-theme.css"),
        LIGHT("Light", "/style/light-theme.css");
    
        private final String displayName;
        private final String styleSheetPath;
    
        Theme(String displayName, String styleSheetPath) {
            this.displayName = displayName;
            this.styleSheetPath = styleSheetPath;
        }
    
        public String getDisplayName() {
            return displayName;
        }
    
        public String getStyleSheetPath() {
            return styleSheetPath;
        }
    }

    private static final String baseStyleSheetPath = "/style/base.css";
    private Theme currentTheme;
    private String darkThemeResource;
    private String lightThemeResource;

    public AppConfig() {
        this.currentTheme = Theme.DARK; // Default to dark mode
    }

    public void setDarkThemeResource(String resource) {
        this.darkThemeResource = resource;
    }

    public String getDarkThemeResource() {
        return this.darkThemeResource;
    }

    public void setLightThemeResource(String resource) {
        this.lightThemeResource = resource;
    }

    public String getLightThemeResource() {
        return this.lightThemeResource;
    }

    public void setCurrentTheme(Theme newTheme) {
        this.currentTheme = newTheme;
    }

    public Theme getCurrentTheme() {
        return this.currentTheme;
    }

    public static String getBaseStyleSheetPath() {
        return baseStyleSheetPath;
    }

    public void saveConfig() {
        //TODO: save config data to file for project reloading
    }
}
