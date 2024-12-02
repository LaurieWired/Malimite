package com.lauriewired.malimite.ui;

import javax.swing.*;
import java.awt.*;
import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.utils.GhidraSetup;
import com.lauriewired.malimite.Malimite;

public class PreferencesDialog {
    private static JDialog dialog;

    public static void show(JFrame parent, Config config) {
        // Check if dialog is already showing
        if (dialog != null && dialog.isVisible()) {
            dialog.toFront();
            return;
        }

        // Create the dialog
        dialog = new JDialog(parent, "Preferences", true);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        // Create the main panel with some padding
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Theme selection
        JPanel themePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        themePanel.add(new JLabel("Theme:"));
        JComboBox<String> themeComboBox = new JComboBox<>(new String[]{
            "dark", 
            "light"
        });
        themeComboBox.setSelectedItem(config.getTheme());
        themePanel.add(themeComboBox);
        mainPanel.add(themePanel);

        // Ghidra path setting
        JPanel ghidraPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        ghidraPanel.add(new JLabel("Ghidra Path:"));
        JTextField ghidraPathField = new JTextField(config.getGhidraPath(), 30);
        JButton browseButton = new JButton("Browse");
        
        // Add help icon with tooltip
        JButton helpButton = new JButton("?");
        helpButton.setPreferredSize(new Dimension(20, 20));
        helpButton.setToolTipText("Path to root directory of Ghidra installation");
        helpButton.setFocusPainted(false);
        
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fileChooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                ghidraPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        ghidraPanel.add(ghidraPathField);
        ghidraPanel.add(browseButton);
        ghidraPanel.add(helpButton);  // Add the help button
        mainPanel.add(ghidraPanel);

        // Add some vertical spacing
        mainPanel.add(Box.createVerticalStrut(10));

        // Add OpenAI API Key field
        JPanel openaiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        openaiPanel.add(new JLabel("OpenAI API Key:"));
        JPasswordField openaiKeyField = new JPasswordField(config.getOpenAIApiKey(), 30);
        openaiPanel.add(openaiKeyField);
        mainPanel.add(openaiPanel);

        // Add Claude API Key field
        JPanel claudePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        claudePanel.add(new JLabel("Claude API Key:"));
        JPasswordField claudeKeyField = new JPasswordField(config.getClaudeApiKey(), 30);
        claudePanel.add(claudeKeyField);
        mainPanel.add(claudePanel);

        // Add some vertical spacing
        mainPanel.add(Box.createVerticalStrut(10));

        // Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> {
            String newTheme = (String) themeComboBox.getSelectedItem();
            String currentTheme = config.getTheme();
            String newGhidraPath = ghidraPathField.getText();
            String currentGhidraPath = config.getGhidraPath();
            
            // Check if Ghidra path has changed
            if (!newGhidraPath.equals(currentGhidraPath)) {
                int response = JOptionPane.showConfirmDialog(dialog,
                    "Ghidra path updated. Downloading JSON dependency to Ghidra directory.\nNote: This will not affect Ghidra",
                    "Setup Required Libraries",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.INFORMATION_MESSAGE);
                
                if (response == JOptionPane.OK_OPTION) {
                    GhidraSetup.setupGhidraLibs(newGhidraPath);
                }
            }
            
            // Save all preferences
            config.setTheme(newTheme);
            config.setGhidraPath(newGhidraPath);
            config.setOpenAIApiKey(new String(openaiKeyField.getPassword()));
            config.setClaudeApiKey(new String(claudeKeyField.getPassword()));
            config.saveConfig();
            
            // Apply theme change if it was modified
            if (!newTheme.equals(currentTheme)) {
                Malimite.updateTheme(newTheme);
            }
            
            dialog.dispose();
        });        

        cancelButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        mainPanel.add(buttonPanel);

        // Add the main panel to the dialog
        dialog.add(mainPanel);

        // Size and position the dialog
        dialog.pack();
        dialog.setLocationRelativeTo(parent);
        dialog.setResizable(false);

        // Show the dialog
        dialog.setVisible(true);
    }
} 