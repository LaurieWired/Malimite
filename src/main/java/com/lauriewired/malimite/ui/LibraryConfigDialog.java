package com.lauriewired.malimite.ui;

import com.lauriewired.malimite.configuration.LibraryDefinitions;
import com.lauriewired.malimite.configuration.Config;
import javax.swing.*;
import java.awt.*;

public class LibraryConfigDialog {
    public static void show(JFrame parent) {
        Config config = new Config();
        JDialog dialog = new JDialog(parent, "Configure Libraries", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(450, 500);
        dialog.setLocationRelativeTo(parent);

        // Create info panel
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JTextArea infoText = new JTextArea(
            "Configure library names to optimize decompilation performance.\n\n" +
            "• Library names are case-sensitive\n" +
            "• Classes starting with these names will be treated as libraries\n" +
            "• Library classes will be skipped during decompilation\n" +
            "• Use this to ignore known frameworks and focus on app-specific code"
        );
        infoText.setEditable(false);
        infoText.setBackground(null);
        infoText.setWrapStyleWord(true);
        infoText.setLineWrap(true);
        infoPanel.add(infoText, BorderLayout.CENTER);
        
        dialog.add(infoPanel, BorderLayout.NORTH);

        // Create list model and populate with active libraries
        DefaultListModel<String> listModel = new DefaultListModel<>();
        LibraryDefinitions.getActiveLibraries(config).forEach(listModel::addElement);

        // Create list with model
        JList<String> libraryList = new JList<>(listModel);
        libraryList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        // Add scroll pane
        JScrollPane scrollPane = new JScrollPane(libraryList);
        dialog.add(scrollPane, BorderLayout.CENTER);

        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        // Add library button
        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> {
            String input = JOptionPane.showInputDialog(dialog, 
                "Enter library name:", 
                "Add Library", 
                JOptionPane.PLAIN_MESSAGE);
            
            if (input != null && !input.trim().isEmpty()) {
                String library = input.trim();
                config.addLibrary(library);
                if (!listModel.contains(library)) {
                    listModel.addElement(library);
                }
            }
        });

        // Remove library button
        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(e -> {
            int[] indices = libraryList.getSelectedIndices();
            for (int i = indices.length - 1; i >= 0; i--) {
                String library = listModel.getElementAt(indices[i]);
                config.removeLibrary(library);
                listModel.remove(indices[i]);
            }
        });

        // Restore defaults button
        JButton restoreButton = new JButton("Restore Defaults");
        restoreButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(dialog,
                "This will restore all libraries to their default settings.\nContinue?",
                "Restore Defaults",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
                
            if (result == JOptionPane.YES_OPTION) {
                config.clearLibraryConfigurations();
                listModel.clear();
                LibraryDefinitions.getDefaultLibraries().forEach(listModel::addElement);
            }
        });

        // Close button
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(restoreButton);
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }
} 