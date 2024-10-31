package com.lauriewired.malimite;

import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.ui.SyntaxUtility;
import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.ui.SafeMenuAction;
import com.lauriewired.malimite.ui.ApplicationMenu;

import javax.swing.*;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class Malimite {
    private static final Logger LOGGER = Logger.getLogger(Malimite.class.getName());

    public static void main(String[] args) {
        // Load or create config immediately
        Config config = new Config();
        
        // Enable macOS-specific properties if on Mac
        if (config.isMac()) {
            System.setProperty("apple.laf.useScreenMenuBar", "true");
            //System.setProperty("apple.awt.application.appearance", "system");
        }
        
        // Set initial FlatLaf theme based on config
        if (config.getTheme().equals("dark")) {
            FlatDarkLaf.setup();
        } else {
            FlatLightLaf.setup();
        }
    
        SwingUtilities.invokeLater(() -> createAndShowGUI(config));
    }

    private static void createAndShowGUI(Config config) {
        SafeMenuAction.execute(() -> {
            JFrame frame = new JFrame("Malimite");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(600, 400);
            frame.setLocationRelativeTo(null);
        
            // Config is now passed in from main
        
            // Add the menu bar
            ApplicationMenu applicationMenu = new ApplicationMenu(
                frame, 
                null,  // null since main window might not have a file tree
                config
            );
            frame.setJMenuBar(applicationMenu.createMenuBar());
        
            JPanel panel = new JPanel(new GridBagLayout());
            frame.add(panel);
        
            setupComponents(panel, frame, config);
        
            frame.setVisible(true);
        });
    }
    
    public static void updateTheme(String theme) {
        SafeMenuAction.execute(() -> {
            switch (theme) {
                case "dark":
                    FlatDarkLaf.setup();
                    break;
                case "light":
                    FlatLightLaf.setup();
                    break;
                default:
                    FlatLightLaf.setup();
                    break;
            }
            
            // Update all windows' look-and-feel
            for (Window window : Window.getWindows()) {
                SwingUtilities.updateComponentTreeUI(window);
            }
    
            // Apply custom syntax theme to RSyntaxTextArea components after UI update
            for (Window window : Window.getWindows()) {
                applyCustomSyntaxTheme(window);
            }
        });
    }    

    // Add this helper method
    private static void applyCustomSyntaxTheme(Window window) {
        if (window instanceof JFrame || window instanceof JDialog) {
            for (Component comp : getAllComponents((Container)window)) {
                if (comp instanceof RSyntaxTextArea) {
                    SyntaxUtility.applyCustomTheme((RSyntaxTextArea)comp);
                }
            }
        }
    }

    // Add this utility method to get all components recursively
    private static List<Component> getAllComponents(Container container) {
        List<Component> components = new ArrayList<>();
        for (Component comp : container.getComponents()) {
            components.add(comp);
            if (comp instanceof Container) {
                components.addAll(getAllComponents((Container)comp));
            }
        }
        return components;
    }

    //TODO add full functionality
    private static void showOpenDialog() {
        // Placeholder for the "Open" action
        JOptionPane.showMessageDialog(null, "Open dialog would appear here.");
    }
    
    private static void showSettingsDialog() {
        // Placeholder for the "Settings" dialog
        JOptionPane.showMessageDialog(null, "Settings dialog would appear here.");
    }
    
    private static void showAboutDialog() {
        // Placeholder for the "About" dialog
        JOptionPane.showMessageDialog(null, "Malimite Application\nVersion 1.0");
    }    

    private static void setupComponents(JPanel panel, JFrame frame, Config config) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(15, 15, 15, 15);

        // File path text field
        JTextField filePathText = new JTextField();
        filePathText.setFont(new Font("Verdana", Font.PLAIN, 16));
        filePathText.setEditable(false);
        filePathText.setPreferredSize(new Dimension(275, 30));
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        panel.add(filePathText, constraints);

        // "Select File" button
        JButton fileButton = new JButton("Select File");
        constraints.gridx = 3;
        constraints.gridy = 0;
        constraints.gridwidth = 1;
        panel.add(fileButton, constraints);

        // Status label
        JLabel statusLabel = new JLabel("");
        statusLabel.setFont(new Font("Verdana", Font.ITALIC, 14));
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 4;
        panel.add(statusLabel, constraints);

        // "Analyze" button
        JButton analyzeButton = new JButton("Analyze File");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 4;
        panel.add(analyzeButton, constraints);

        // Set up file listeners
        setupDragAndDrop(filePathText, statusLabel);
        setupFileButtonListener(fileButton, filePathText);
        setupAnalyzeButtonListener(analyzeButton, filePathText, statusLabel, config);
    }

    private static void setupDragAndDrop(JTextField filePathText, JLabel statusLabel) {
        new DropTarget(filePathText, new DropTargetAdapter() {
            @Override
            public void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!droppedFiles.isEmpty()) {
                        File file = droppedFiles.get(0);
                        filePathText.setText(file.getAbsolutePath());
                        statusLabel.setText("File ready for analysis.");
                    }
                } catch (Exception ex) {
                    LOGGER.severe("Error during file drop: " + ex.getMessage());
                    statusLabel.setText("Error loading file.");
                }
            }
        });
    }

    private static void setupFileButtonListener(JButton fileButton, JTextField filePathText) {
        fileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int option = fileChooser.showOpenDialog(null);
            if (option == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                filePathText.setText(selectedFile.getAbsolutePath());
            }
        });
    }

    private static void setupAnalyzeButtonListener(JButton analyzeButton, JTextField filePathText, JLabel statusLabel, Config config) {
        analyzeButton.addActionListener(e -> {
            String filePath = filePathText.getText();
            if (!filePath.isEmpty() && Files.exists(Paths.get(filePath))) {
                // Trigger AnalysisWindow with the updated method call
                AnalysisWindow.show(new File(filePath), config);
            } else {
                statusLabel.setText("Please select a valid file path.");
            }
        });
    }    
}
