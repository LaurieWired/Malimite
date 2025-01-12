package com.lauriewired.malimite.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

import com.lauriewired.malimite.database.SQLiteDBHandler;

public class SearchResultsDialog {
    private static JDialog dialog;
    private static JTable resultsTable;
    private static DefaultTableModel tableModel;

    public static void show(JFrame parent, SQLiteDBHandler dbHandler, String searchTerm) {
        // Check if dialog is already showing
        if (dialog != null && dialog.isVisible()) {
            dialog.dispose();
        }

        // Create the dialog
        dialog = new JDialog(parent, "Search Results", false);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        // Create main panel with padding
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create table model
        String[] columns = {"Type", "Name", "Location", "Line"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        // Create and configure the table
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getTableHeader().setReorderingAllowed(false);

        // Add table to scroll pane
        JScrollPane scrollPane = new JScrollPane(resultsTable);
        scrollPane.setPreferredSize(new Dimension(800, 400));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Create info panel at the top
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel("Search results for: " + searchTerm);
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(infoLabel);
        mainPanel.add(infoPanel, BorderLayout.NORTH);

        // Create button panel at the bottom
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add the main panel to the dialog
        dialog.add(mainPanel);

        // Load search results
        List<Map<String, String>> results = dbHandler.searchCodebase(searchTerm);
        loadSearchResults(results);

        // Add double-click handler
        resultsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                if (evt.getClickCount() == 2) {
                    int row = resultsTable.getSelectedRow();
                    if (row != -1) {
                        handleDoubleClick(row);
                    }
                }
            }
        });

        // Size and position the dialog
        dialog.pack();
        dialog.setLocationRelativeTo(parent);

        // Show the dialog
        dialog.setVisible(true);
    }

    private static void loadSearchResults(List<Map<String, String>> results) {
        tableModel.setRowCount(0);
        
        for (Map<String, String> result : results) {
            tableModel.addRow(new Object[]{
                result.get("type"),
                result.get("name"),
                result.get("container"),
                result.get("line")
            });
        }

        // Adjust column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // Type
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // Name
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(400);  // Location
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(100);  // Line
    }

    private static void handleDoubleClick(int row) {
        String type = (String) tableModel.getValueAt(row, 0);
        String name = (String) tableModel.getValueAt(row, 1);
        String container = (String) tableModel.getValueAt(row, 2);
        String line = (String) tableModel.getValueAt(row, 3);

        SwingUtilities.invokeLater(() -> {
            String path;
            if ("Class".equals(type)) {
                path = "Classes/" + name;
            } else if ("Function".equals(type)) {
                path = "Classes/" + container + "/" + name;
            } else { // Variable
                String[] parts = container.split(" in ");
                if (parts.length == 2) {
                    path = "Classes/" + parts[1] + "/" + parts[0];
                } else {
                    return;
                }
            }

            // Show the file content
            AnalysisWindow.showFileContent(path);
            
            // Navigate to line if available
            if (line != null && !line.isEmpty()) {
                try {
                    int lineNum = Integer.parseInt(line);
                    AnalysisWindow.navigateToLine(lineNum);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid line number: " + line);
                }
            }
        });
    }
} 