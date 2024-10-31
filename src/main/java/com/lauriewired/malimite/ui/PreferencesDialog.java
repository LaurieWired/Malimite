package com.lauriewired.malimite.ui;

import javax.swing.*;
import java.awt.*;
import com.lauriewired.malimite.configuration.Config;
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
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fileChooser.showOpenDialog(dialog) == JFileChooser.APPROVE_OPTION) {
                ghidraPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        ghidraPanel.add(ghidraPathField);
        ghidraPanel.add(browseButton);
        mainPanel.add(ghidraPanel);

        // Add some vertical spacing
        mainPanel.add(Box.createVerticalStrut(10));

        // Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> {
            String oldTheme = config.getTheme();
            String newTheme = (String) themeComboBox.getSelectedItem();
        
            config.setTheme(newTheme);
            config.setGhidraPath(ghidraPathField.getText());
            config.saveConfig();
        
            // Apply theme change immediately if it changed
            if (!oldTheme.equals(newTheme)) {
                SwingUtilities.invokeLater(() -> Malimite.updateTheme(newTheme));
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