package com.lauriewired.malimite.ui;

import com.lauriewired.malimite.config.AppConfig;

import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class ConfigMenu {

    public static void showSettingsDialog(Stage parentStage, Scene mainScene, AppConfig appConfig) {
        // Create a dialog for settings
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(parentStage);
        dialog.initModality(Modality.WINDOW_MODAL);
        dialog.setTitle("Settings");

        // Theme selector within the dialog
        ComboBox<String> themeSelector = new ComboBox<>();
        themeSelector.getItems().addAll("Light", "Dark");
        themeSelector.setValue(appConfig.getCurrentTheme().getDisplayName());
        themeSelector.valueProperty().addListener((obs, oldVal, newVal) -> {
            // Remove current theme CSS
            if (newVal.equals(AppConfig.Theme.DARK.getDisplayName())) {
                appConfig.setCurrentTheme(AppConfig.Theme.DARK);
                mainScene.getStylesheets().remove(appConfig.getLightThemeResource());
                mainScene.getStylesheets().add(appConfig.getDarkThemeResource());
            } else {
                appConfig.setCurrentTheme(AppConfig.Theme.LIGHT);
                mainScene.getStylesheets().remove(appConfig.getDarkThemeResource());
                mainScene.getStylesheets().add(appConfig.getLightThemeResource());
            }
        });

        VBox dialogVBox = new VBox(new Label("Select Theme:"), themeSelector);
        dialogVBox.setAlignment(Pos.CENTER);
        dialogVBox.setSpacing(10);
        dialog.getDialogPane().setContent(dialogVBox);
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.CLOSE);
        dialog.show();
    }
}
