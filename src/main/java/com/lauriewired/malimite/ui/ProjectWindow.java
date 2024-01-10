package com.lauriewired.malimite.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TreeView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.Separator;
import javafx.scene.control.SplitPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.lauriewired.malimite.config.AppConfig;
import com.lauriewired.malimite.utils.FileProcessing;

public class ProjectWindow {
    private ConfigMenu configMenu;

    public static void show(Stage stage, File file, AppConfig appConfig) {
        VBox root = new VBox();
        setupWindow(stage, file, appConfig, root);
    
        // Set the new root on the existing scene
        if (stage.getScene() == null) {
            // Only create a new Scene if the stage does not already have one (shouldn't get here)
            Scene scene = new Scene(root, 800, 600);
            stage.setScene(scene);
        } else {
            // Reuse the existing Scene and just update its root
            stage.getScene().setRoot(root);
        }
    
        stage.setMaximized(true);
        stage.show();
    }

    public static void setupWindow(Stage stage, File file, AppConfig appConfig, VBox root) {
        // Setup top menu bar
        Button settingsButton = new Button("Settings");
        settingsButton.setOnAction(e -> ConfigMenu.showSettingsDialog(stage, stage.getScene(), appConfig));
        Button helpButton = new Button("Help");

        HBox menuContainer = new HBox(10);
        menuContainer.getChildren().addAll(settingsButton, helpButton);
        menuContainer.setPadding(new Insets(10, 10, 10, 10));
        Separator menuSeparator = new Separator();
        menuSeparator.setPrefWidth(Double.MAX_VALUE);

        // SplitPane for file contents and decompiled code
        SplitPane splitPane = new SplitPane();

        // Root of the entire tree
        TreeItem<String> treeRoot = new TreeItem<>(file.getName());

        // Sub-roots for displaying the resources and classes after file processing
        TreeItem<String> resourcesRoot = new TreeItem<>("Resources");
        TreeItem<String> classesRoot = new TreeItem<>("Classes");

        // Temp add item to classes node
        createTreeItem(classesRoot, "TestClass");

        populateLefthandTree(resourcesRoot, file);

        TreeView<String> lefthandView = new TreeView<>(treeRoot);
        treeRoot.getChildren().add(classesRoot);
        treeRoot.getChildren().add(resourcesRoot);

        // Placeholder for decompiled code (right pane)
        StackPane decompiledCodePane = new StackPane();
        Label decompiledCodeLabel = new Label("Decompiled code will be displayed here.");
        decompiledCodePane.getChildren().add(decompiledCodeLabel);

        // Add event listener to the TreeView for item selection
        lefthandView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null && newValue.isLeaf()) {
                // Assuming the full path of the file is stored as the value of the TreeItem
                File selectedFile = new File(file.getParent(), newValue.getValue());
                if (selectedFile.exists() && selectedFile.isFile()) {
                    try {
                        // Read the contents of the file (this is a basic example, adjust as needed)
                        String content = new String(Files.readAllBytes(selectedFile.toPath()));
                        decompiledCodeLabel.setText(content); // Display the content in the label
                    } catch (IOException e) {
                        decompiledCodeLabel.setText("Error reading file: " + e.getMessage());
                    }
                }
            }
        });

        splitPane.getItems().addAll(lefthandView, decompiledCodePane);
        splitPane.setDividerPositions(0.2);

        // Set SplitPane to take as much space as possible
        VBox.setVgrow(splitPane, Priority.ALWAYS);

        // Buttons under the SplitPane
        Button decompilerButton = new Button("Decompiler");
        Button stringsButton = new Button("Strings");
        HBox bottomButtons = new HBox(10, decompilerButton, stringsButton);
        bottomButtons.setPadding(new Insets(10, 10, 10, 10));
        bottomButtons.setAlignment(Pos.CENTER);

        // Add all components to the root VBox
        root.getChildren().addAll(menuContainer, menuSeparator, splitPane, bottomButtons);
    }

    private static void populateLefthandTree(TreeItem<String> root, File zipFile) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                createTreeItem(root, entry.getName());
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void createTreeItem(TreeItem<String> root, String entryName) {
        String[] parts = entryName.split("/");
        TreeItem<String> current = root;
    
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
    
            // Check if the part is already a child of the current node
            TreeItem<String> foundChild = current.getChildren().stream()
                .filter(child -> child.getValue().equals(part))
                .findFirst()
                .orElse(null);
    
            if (foundChild == null) {
                // Create a new TreeItem for this part
                TreeItem<String> newItem = new TreeItem<>(part);
                current.getChildren().add(newItem);
                current = newItem;
            } else {
                // Move to the found child for the next iteration
                current = foundChild;
            }
        }
    }
}
