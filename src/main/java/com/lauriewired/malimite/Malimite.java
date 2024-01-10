package com.lauriewired.malimite;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

import com.lauriewired.malimite.ui.MainWindow;

public class Malimite extends Application {
    private static Stage mainStage;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        mainStage = stage;
        MainWindow mainWindow = new MainWindow();
        mainWindow.launchMainWindow(mainStage);
    }

    public static void setRootScene(Scene scene) {
        mainStage.setScene(scene);
    }
}