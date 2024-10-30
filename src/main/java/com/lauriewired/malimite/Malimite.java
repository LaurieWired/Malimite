package com.lauriewired.malimite;

import com.github.weisj.darklaf.LafManager;
import com.github.weisj.darklaf.theme.DarculaTheme;
import com.github.weisj.darklaf.theme.IntelliJTheme;
import com.github.weisj.darklaf.theme.SolarizedLightTheme;
import com.github.weisj.darklaf.theme.SolarizedDarkTheme;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.configuration.Config;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.logging.Logger;

public class Malimite {
    private static final Logger LOGGER = Logger.getLogger(Malimite.class.getName());

    // Add these as class fields at the top of the Malimite class
    private static JDialog preferencesDialog = null;
    private static boolean menuActionInProgress = false;
    private static final Object menuLock = new Object();

    public static void main(String[] args) {
        // Install Darklaf once at startup with an initial theme
        LafManager.setTheme(new DarculaTheme());
        LafManager.install();

        SwingUtilities.invokeLater(Malimite::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Malimite");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);
        frame.setLocationRelativeTo(null);
    
        // Initialize Config for handling paths
        Config config = new Config();
    
        // Set theme based on config
        updateTheme(config.getTheme());
    
        // Add the menu bar
        frame.setJMenuBar(createMenuBar(config));
    
        JPanel panel = new JPanel(new GridBagLayout());
        frame.add(panel);
    
        setupComponents(panel, frame, config);
    
        frame.setVisible(true);
    }
    
    private static JMenuBar createMenuBar(Config config) {
        JMenuBar menuBar = new JMenuBar();
    
        // File Menu
        JMenu fileMenu = new JMenu("File");
        JMenuItem openItem = new JMenuItem("Open...");
        JMenuItem preferencesItem = new JMenuItem("Preferences");
        JMenuItem exitItem = new JMenuItem("Exit");
        fileMenu.add(openItem);
        fileMenu.add(preferencesItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);
    
        // Tools Menu
        JMenu toolsMenu = new JMenu("Tools");
        JMenuItem pluginsItem = new JMenuItem("Plugins");
        toolsMenu.add(pluginsItem);
    
        // Help Menu
        JMenu helpMenu = new JMenu("Help");
        JMenuItem aboutItem = new JMenuItem("About");
        helpMenu.add(aboutItem);
    
        // Add menus to the menu bar
        menuBar.add(fileMenu);
        menuBar.add(toolsMenu);
        menuBar.add(helpMenu);
    
        // Add action listeners for menu items
        openItem.addActionListener(e -> safeMenuAction(() -> showOpenDialog()));
        preferencesItem.addActionListener(e -> safeMenuAction(() -> showPreferencesDialog(config)));
        exitItem.addActionListener(e -> safeMenuAction(() -> System.exit(0)));
        pluginsItem.addActionListener(e -> safeMenuAction(() -> showSettingsDialog()));
        aboutItem.addActionListener(e -> safeMenuAction(() -> showAboutDialog()));
    
        return menuBar;
    }
    
    private static void showPreferencesDialog(Config config) {
        // If dialog is already showing, bring it to front
        if (preferencesDialog != null && preferencesDialog.isVisible()) {
            preferencesDialog.requestFocus();
            return;
        }
        
        // If dialog exists but not visible, dispose it
        if (preferencesDialog != null) {
            preferencesDialog.dispose();
        }
        
        // Create new dialog
        preferencesDialog = new JDialog((JFrame) null, "Preferences", true);
        preferencesDialog.setLayout(new BorderLayout());
        
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Theme selection
        JLabel themeLabel = new JLabel("Theme:");
        String[] themes = {"darcula", "intellij", "solarized-light", "solarized-dark"};
        JComboBox<String> themeCombo = new JComboBox<>(themes);
        themeCombo.setSelectedItem(config.getTheme());
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(themeLabel, gbc);
        
        gbc.gridx = 1;
        panel.add(themeCombo, gbc);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");
        
        saveButton.addActionListener(e -> {
            String selectedTheme = (String) themeCombo.getSelectedItem();
            preferencesDialog.setVisible(false); // Hide dialog before theme change
            config.setTheme(selectedTheme);
            SwingUtilities.invokeLater(() -> {
                updateTheme(selectedTheme);
                preferencesDialog.dispose();
                preferencesDialog = null;
            });
        });
        
        cancelButton.addActionListener(e -> {
            preferencesDialog.dispose();
            preferencesDialog = null;
        });
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        
        preferencesDialog.add(panel, BorderLayout.CENTER);
        preferencesDialog.add(buttonPanel, BorderLayout.SOUTH);
        
        preferencesDialog.pack();
        preferencesDialog.setLocationRelativeTo(null);
        preferencesDialog.setVisible(true);
        
        // Add window listener to clean up on close
        preferencesDialog.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                preferencesDialog.dispose();
                preferencesDialog = null;
            }
        });
    }
    
    private static void updateTheme(String theme) {
        switch (theme) {
            case "darcula":
                LafManager.setTheme(new DarculaTheme());
                break;
            case "intellij":
                LafManager.setTheme(new IntelliJTheme());
                break;
            case "solarized-light":
                LafManager.setTheme(new SolarizedLightTheme());
                break;
            case "solarized-dark":
                LafManager.setTheme(new SolarizedDarkTheme());
                break;
            default:
                LafManager.setTheme(new DarculaTheme());
                break;
        }
        LafManager.install();
        
        // Update all windows
        for (Window window : Window.getWindows()) {
            SwingUtilities.updateComponentTreeUI(window);
        }
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
        setupAnalyzeButtonListener(analyzeButton, filePathText, statusLabel, frame, config);
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

    private static void setupAnalyzeButtonListener(JButton analyzeButton, JTextField filePathText, JLabel statusLabel, JFrame frame, Config config) {
        analyzeButton.addActionListener(e -> {
            String filePath = filePathText.getText();
            if (!filePath.isEmpty() && Files.exists(Paths.get(filePath))) {
                // Trigger AnalysisWindow
                AnalysisWindow.show(frame, new File(filePath), config);
            } else {
                statusLabel.setText("Please select a valid file path.");
            }
        });
    }

    // Add this new helper method
    private static void safeMenuAction(Runnable action) {
        synchronized (menuLock) {
            if (menuActionInProgress) {
                return;
            }
            menuActionInProgress = true;
        }
        
        try {
            SwingUtilities.invokeLater(() -> {
                try {
                    action.run();
                } finally {
                    synchronized (menuLock) {
                        menuActionInProgress = false;
                    }
                }
            });
        } catch (Exception ex) {
            synchronized (menuLock) {
                menuActionInProgress = false;
            }
            LOGGER.severe("Error in menu action: " + ex.getMessage());
        }
    }
}
