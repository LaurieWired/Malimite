package com.lauriewired.malimite.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.File;

import com.lauriewired.malimite.config.AppConfig;

public class MainWindow {
    private Stage mainStage;
    private Scene scene;
    private FileChooser fileChooser;
    private Button settingsButton;
    private Button helpButton;
    private HBox menuContainer;
    private Separator menuSeparator;
    private Label fileSelectorLabel;
    private StackPane fileDropArea;

    public void launchMainWindow(Stage stage) {
        this.mainStage = stage;
        mainStage.setTitle("Malimite");
        AppConfig appConfig = new AppConfig();
        appConfig.setDarkThemeResource(getClass().getResource(AppConfig.Theme.DARK.getStyleSheetPath()).toExternalForm());
        appConfig.setLightThemeResource(getClass().getResource(AppConfig.Theme.LIGHT.getStyleSheetPath()).toExternalForm());

        setupWindow(appConfig);

        mainStage.setScene(this.scene);
        mainStage.show();
    }

    private void setupWindow(AppConfig appConfig) {
        VBox root = new VBox(10);
        root.setAlignment(Pos.TOP_CENTER);
        //TODO: change number sizes to be in CSS
        this.scene = new Scene(root, 640, 480);
        scene.getStylesheets().add(getClass().getResource(AppConfig.getBaseStyleSheetPath()).toExternalForm());
        scene.getStylesheets().add(getClass().getResource(AppConfig.Theme.DARK.getStyleSheetPath()).toExternalForm());

        // Setup top menu bar
        settingsButton = new Button("Settings");
        settingsButton.setOnAction(e -> ConfigMenu.showSettingsDialog(this.mainStage, scene, appConfig));
        helpButton = new Button("Help");

        menuContainer = new HBox(10);
        //TODO standardize menu button widths
        menuContainer.getChildren().addAll(settingsButton, helpButton);
        menuContainer.setPadding(new Insets(10, 10, 10, 10));

        // Separator between menu and file selection
        menuSeparator = new Separator();
        menuSeparator.setPrefWidth(Double.MAX_VALUE);

        fileSelectorLabel = new Label("Analyze new file");
        fileSelectorLabel.setFont(new Font("System", 26));
        HBox fileSelectorLabelContainer = new HBox(fileSelectorLabel);
        fileSelectorLabelContainer.setAlignment(Pos.BASELINE_LEFT);
        fileSelectorLabelContainer.setPadding(new Insets(100, 0, 0, 40));
        fileDropArea = new StackPane();
        fileDropArea.setPrefSize(250, 35);
        fileDropArea.setMaxSize(250, 35);

        // File chooser setup
        fileChooser = new FileChooser();
        Button selectFileButton = new Button("Select");
        selectFileButton.setOnAction(e -> {
            File file = fileChooser.showOpenDialog(this.mainStage);
            if (file != null) {
                ProjectWindow.show(this.mainStage, file, appConfig);
            }
        });
        setupFileDragNDrop(fileDropArea, fileChooser, this.mainStage, appConfig);

        HBox fileSelectionArea = new HBox(10);
        fileSelectionArea.getChildren().addAll(fileDropArea, selectFileButton);
        fileSelectionArea.setPadding(new Insets(0, 0, 0, 40));

        // Adding components to the root
        root.getChildren().addAll(menuContainer, menuSeparator, fileSelectorLabelContainer, fileSelectionArea);
        VBox.setVgrow(fileSelectionArea, Priority.ALWAYS);

        // Load the PNG icon file as an Image
        Image iconImage = new Image(getClass().getResourceAsStream("/icons/apple_icon.png"));
        ImageView iconImageView = new ImageView(iconImage);
        iconImageView.setFitHeight(75);
        iconImageView.setPreserveRatio(true);
        VBox bottomContainer = new VBox(iconImageView);
        bottomContainer.setPadding(new Insets(0, 0, 10, 0));
        bottomContainer.setAlignment(Pos.CENTER);
        root.getChildren().add(bottomContainer);
    }

    private static void setupFileDragNDrop(StackPane dropArea, FileChooser fileChooser, Stage stage, AppConfig appConfig) {
        dropArea.setOnDragOver(event -> {
            if (event.getDragboard().hasFiles()) {
                event.acceptTransferModes(javafx.scene.input.TransferMode.ANY);
            }
            event.consume();
        });

        dropArea.setOnDragDropped(event -> {
            if (event.getDragboard().hasFiles()) {
                File file = event.getDragboard().getFiles().get(0);
                ProjectWindow.show(stage, file, appConfig);
                event.setDropCompleted(true);
                event.consume();
            }
        });
    }
}
