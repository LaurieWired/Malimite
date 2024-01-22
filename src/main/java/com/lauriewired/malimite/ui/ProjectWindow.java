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
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.TextFlow;
import javafx.stage.Stage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.fxmisc.richtext.CodeArea;

import com.lauriewired.malimite.config.AppConfig;
import com.lauriewired.malimite.project.Project;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.utils.FileProcessing;

public class ProjectWindow {
    private static Map<TreeItem<String>, String> filePathMap = new HashMap<>(); // Paths for nodes in the tree mapepd to the actual file path
    private static String infoPlistPath = "";

    public static void show(Stage stage, File file, AppConfig appConfig) {
        VBox root = new VBox();
        Project malimiteProject = new Project();
        
        setupWindow(stage, file, appConfig, root, malimiteProject);
    
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

    public static void setupWindow(Stage stage, File file, AppConfig appConfig, VBox root, Project malimiteProject) {
        // Setup top menu bar
        Button settingsButton = new Button("Settings");
        settingsButton.setOnAction(e -> ConfigMenu.showSettingsDialog(stage, stage.getScene(), appConfig));
        Button helpButton = new Button("Help");

        HBox menuContainer = new HBox(10);
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

        TreeView<String> lefthandView = new TreeView<>(treeRoot);
        treeRoot.getChildren().add(classesRoot);
        treeRoot.getChildren().add(resourcesRoot);

        // Placeholder for decompiled code (right pane)
        StackPane decompiledCodePane = new StackPane();
        decompiledCodePane.getStyleClass().add("decompiled-code-pane");

        CodeArea codeArea = new CodeArea();
        codeArea.setParagraphGraphicFactory(paragraphIndex -> {
            Label lineNum = new Label(Integer.toString(paragraphIndex + 1));
            lineNum.getStyleClass().add("line-number"); // Add a style class to the line number label
            TextFlow flow = new TextFlow(lineNum);
            return flow;
        });
        codeArea.setEditable(false);
        codeArea.getStyleClass().add("code-area");
        System.out.println(codeArea.getStyleClass());

        decompiledCodePane.getChildren().add(codeArea);

        // Add event listener to the TreeView for item selection
        lefthandView.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            System.out.println("Node selected: " + (newValue != null ? newValue.getValue() : "null")); // Debugging log
        
            if (newValue != null && newValue.isLeaf()) {
                TreeItem<String> parent = newValue.getParent();
                while (parent != null) {
                    if (parent == resourcesRoot) {
                        displaySelectedFileContent(newValue, codeArea, file.getAbsolutePath());
                        return; // Exit the loop and listener once the correct item is found
                    }
                    parent = parent.getParent();
                }
            }
        });

        splitPane.getItems().addAll(lefthandView, decompiledCodePane);
        splitPane.setDividerPositions(0.2);

        // Set SplitPane to take as much space as possible
        VBox.setVgrow(splitPane, Priority.ALWAYS);

        Button decompilerButton = new Button("Decompiler");
        Button stringsButton = new Button("Strings");
        Button scriptingButton = new Button("Scripting");
        HBox rightButtons = new HBox(10, scriptingButton, decompilerButton, stringsButton);
        rightButtons.setAlignment(Pos.CENTER_RIGHT);
        menuContainer.getChildren().addAll(settingsButton, helpButton, rightButtons);

        TextArea console = new TextArea();
        console.setEditable(false);
        console.getStyleClass().add("console");

        // Redirect System.out to the TextArea
        PrintStream ps = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) {
                javafx.application.Platform.runLater(() -> {
                    console.appendText(String.valueOf((char) b));
                });
            }
        });
        System.setOut(ps);
        System.setErr(ps);

        populateLefthandTree(resourcesRoot, file);

        // Now initialize the actual project if we have a valid bundle file (has an Info.plist)
        if (!infoPlistPath.isEmpty()) {
            System.out.println("Opening Malamite project");
            malimiteProject.processAppBundle(file.getAbsolutePath(), infoPlistPath);
        } else {
            System.out.println("No valid Info.plist found");
        }

        // Set a fixed height for the console or make it grow as needed
        console.setPrefHeight(150);

        // Add all components to the root VBox
        root.getChildren().addAll(menuContainer, menuSeparator, splitPane, console);
    }

    private static void displaySelectedFileContent(TreeItem<String> newValue, CodeArea codeArea, String currentFilePath) {
        System.out.println("newValue: " + newValue.getValue());
        String zipEntryPath = filePathMap.get(newValue);

        System.out.println("zipEntryPath: " + zipEntryPath);

        if (currentFilePath != null) {
            try {
                byte[] contentBytes = FileProcessing.readContentFromZip(currentFilePath, zipEntryPath);
                String contentText;

                // Decode if it's a binary plist. Otherwise, just print the text
                if (zipEntryPath.endsWith("plist") && PlistUtils.isBinaryPlist(contentBytes)) {
                    System.out.println("Handling binary property list");
                    contentText = PlistUtils.decodeBinaryPropertyList(contentBytes);
                    //this.fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                } else {
                    contentText = new String(contentBytes);
                    //this.fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
                }
        
                codeArea.replaceText(contentText);
                codeArea.moveTo(0);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static void populateLefthandTree(TreeItem<String> root, File zipFile) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                String entryFullPath = entry.getName(); // Full path of the file in the zip
                TreeItem<String> createdItem = createTreeItem(root, entryFullPath);
    
                filePathMap.put(createdItem, entryFullPath); // Map TreeItem path to full zip file path

                // Find our Info.plist to get the main executable
                if (entryFullPath.endsWith("Info.plist")) {
                    infoPlistPath = filePathMap.get(createdItem);
                    System.out.println("Found Info.plist at " + infoPlistPath);
                }
    
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    

    private static TreeItem<String> createTreeItem(TreeItem<String> root, String entryName) {
        String[] parts = entryName.split("/");
        TreeItem<String> current = root;
    
        for (String part : parts) {
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
        
        return current; // Return the last created or found TreeItem
    }
    
}
