package com.lauriewired.malimite;

import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.ui.SyntaxUtility;
import com.lauriewired.malimite.ui.SafeMenuAction;
import com.lauriewired.malimite.ui.ApplicationMenu;
import com.lauriewired.malimite.utils.FileProcessing;

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
        
            JPanel panel = new JPanel(new BorderLayout(10, 10));
            frame.add(panel);
        
            setupComponents(panel, frame, config);
        
            frame.setVisible(true);
        });
    }
    
    public static void updateTheme(String theme) {
        SafeMenuAction.execute(() -> {
            // Mirror exactly what happens in main()
            if (theme.equals("dark")) {
                FlatDarkLaf.setup();
            } else {
                FlatLightLaf.setup();
            }
            
            // Update all windows' look-and-feel
            for (Window window : Window.getWindows()) {
                SwingUtilities.updateComponentTreeUI(window);
                
                // After updating UI, reapply custom syntax theme to any RSyntaxTextArea
                for (Component comp : getAllComponents((Container)window)) {
                    if (comp instanceof RSyntaxTextArea) {
                        RSyntaxTextArea textArea = (RSyntaxTextArea)comp;
                        // Force a clean reset of the syntax theme
                        textArea.setBackground(UIManager.getColor("Panel.background"));
                        SyntaxUtility.applyCustomTheme(textArea);
                    }
                }
            }
        });
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

    private static void setupComponents(JPanel panel, JFrame frame, Config config) {
        // Use BorderLayout for the main panel
        panel.setLayout(new BorderLayout(10, 10));
        
        // Create panel for file selection
        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(15, 15, 15, 15);

        // File path text field
        JTextField filePathText = new JTextField();
        filePathText.setFont(new Font("Verdana", Font.PLAIN, 16));
        filePathText.setEditable(false);
        filePathText.setPreferredSize(new Dimension(400, 30));
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        mainPanel.add(filePathText, constraints);

        // "Select File" button
        JButton fileButton = new JButton("Select File");
        constraints.gridx = 3;
        constraints.gridy = 0;
        constraints.gridwidth = 1;
        mainPanel.add(fileButton, constraints);

        // "Analyze" button
        JButton analyzeButton = new JButton("Analyze File");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 4;
        mainPanel.add(analyzeButton, constraints);

        // Add components to main panel
        panel.add(mainPanel, BorderLayout.NORTH);

        // Add recent projects panel
        JPanel recentProjectsPanel = new JPanel(new BorderLayout());
        recentProjectsPanel.setBorder(BorderFactory.createTitledBorder("Recent Projects"));
        
        JPanel projectsListPanel = new JPanel();
        projectsListPanel.setLayout(new BoxLayout(projectsListPanel, BoxLayout.Y_AXIS));
        
        // Get and add recent projects
        List<String> projectPaths = FileProcessing.getProjectPaths();
        LOGGER.info("Retrieved project paths: " + projectPaths);
        
        for (String path : projectPaths) {
            LOGGER.info("Processing project path: " + path);
            JButton projectButton = new JButton(path);
            projectButton.setHorizontalAlignment(SwingConstants.LEFT);
            projectButton.setBorderPainted(false);
            projectButton.setContentAreaFilled(false);
            projectButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
            
            projectButton.addActionListener(e -> {
                File originalFile = new File(path);
                String parentDir = originalFile.getParent();
                String fileName = originalFile.getName();
                
                // Remove file extension from fileName if it exists
                int lastDotIndex = fileName.lastIndexOf('.');
                if (lastDotIndex > 0) {
                    fileName = fileName.substring(0, lastDotIndex);
                }
                
                LOGGER.info("Original file path: " + originalFile.getAbsolutePath());
                LOGGER.info("Parent directory: " + parentDir);
                LOGGER.info("File name without extension: " + fileName);
                
                File projectFile = new File(parentDir + File.separator + fileName + "_malimite" + File.separator + "project.json");
                LOGGER.info("Looking for project file at: " + projectFile.getAbsolutePath());
                LOGGER.info("Project file exists: " + projectFile.exists());
                
                if (projectFile.exists()) {
                    LOGGER.info("Opening analysis window for: " + path);
                    AnalysisWindow.show(new File(path), config);
                } else {
                    LOGGER.warning("Project directory not found at: " + projectFile.getAbsolutePath());
                    JOptionPane.showMessageDialog(frame,
                        "Project directory no longer exists.",
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            });
            
            projectsListPanel.add(projectButton);
        }
        
        JScrollPane scrollPane = new JScrollPane(projectsListPanel);
        scrollPane.setPreferredSize(new Dimension(0, 150));
        recentProjectsPanel.add(scrollPane, BorderLayout.CENTER);
        
        panel.add(recentProjectsPanel, BorderLayout.CENTER);

        // Set up file listeners
        setupDragAndDrop(filePathText);
        setupFileButtonListener(fileButton, filePathText);
        setupAnalyzeButtonListener(analyzeButton, filePathText, config);
    }

    private static void setupDragAndDrop(JTextField filePathText) {
        new DropTarget(filePathText, new DropTargetAdapter() {
            @Override
            public void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!droppedFiles.isEmpty()) {
                        File file = droppedFiles.get(0);
                        filePathText.setText(file.getAbsolutePath());
                    }
                } catch (Exception ex) {
                    LOGGER.severe("Error during file drop: " + ex.getMessage());
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

    private static void setupAnalyzeButtonListener(JButton analyzeButton, JTextField filePathText, Config config) {
        analyzeButton.addActionListener(e -> {
            String filePath = filePathText.getText();
            if (!filePath.isEmpty() && Files.exists(Paths.get(filePath))) {
                AnalysisWindow.show(new File(filePath), config);
            } else {
                JOptionPane.showMessageDialog(null, 
                    "Please select a valid file path.", 
                    "Invalid File", 
                    JOptionPane.WARNING_MESSAGE);
            }
        });
    }    
}
