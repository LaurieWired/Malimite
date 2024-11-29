package com.lauriewired.malimite.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

import com.lauriewired.malimite.database.SQLiteDBHandler;

public class ReferencesDialog {
    private static JDialog dialog;
    private static JTable referencesTable;
    private static DefaultTableModel tableModel;
    private static SQLiteDBHandler dbHandler;

    public static void show(JFrame parent, SQLiteDBHandler handler, String name, String className, String functionName) {
        // Check if dialog is already showing
        if (dialog != null && dialog.isVisible()) {
            dialog.toFront();
            return;
        }

        dbHandler = handler;

        // Determine if this is a local variable or function
        boolean isLocalVariable = isLocalVariable(name, className, functionName);

        // Create the dialog with appropriate title
        String title = isLocalVariable ? "Variable References" : "Function References";
        dialog = new JDialog(parent, title, false);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        // Create main panel with padding
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create table model with appropriate columns
        String[] columns;
        if (isLocalVariable) {
            columns = new String[]{"Type", "Variable", "Function", "Line"};
        } else {
            columns = new String[]{"Type", "Source", "Target", "Line"};
        }

        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        // Create and configure the table
        referencesTable = new JTable(tableModel);
        referencesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        referencesTable.getTableHeader().setReorderingAllowed(false);

        // Add table to scroll pane
        JScrollPane scrollPane = new JScrollPane(referencesTable);
        scrollPane.setPreferredSize(new Dimension(600, 300));
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Create info panel at the top
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        String infoText = isLocalVariable ? 
            String.format("References for variable '%s' in %s", name, className) :
            String.format("References for function '%s'", name);
        JLabel infoLabel = new JLabel(infoText);
        infoLabel.setFont(infoLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(infoLabel);

        // Add type information if it's a local variable
        if (isLocalVariable) {
            String type = getVariableType(name, className);
            if (type != null) {
                JLabel typeLabel = new JLabel(String.format(" (Type: %s)", type));
                infoPanel.add(typeLabel);
            }
        }

        mainPanel.add(infoPanel, BorderLayout.NORTH);

        // Create button panel at the bottom
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add the main panel to the dialog
        dialog.add(mainPanel);

        // Load references data
        if (isLocalVariable) {
            System.out.println("Loading local variable references for " + name + " in " + className);
            loadLocalVariableReferences(name, className, functionName);
        } else {
            System.out.println("Loading function references for " + name + " in " + className);
            loadFunctionReferences(name, className);
        }

        // Size and position the dialog
        dialog.pack();
        dialog.setLocationRelativeTo(parent);

        // Show the dialog
        dialog.setVisible(true);
    }

    private static boolean isLocalVariable(String name, String className, String functionName) {
        // First check if it's a known function
        if (dbHandler.isFunctionName(name)) {
            return false; // It's a function
        }


        // Then check if it's a known variable in TypeInformation
        List<Map<String, String>> typeInfo = dbHandler.getTypeInformation(name, className);
        if (!typeInfo.isEmpty()) {
            return true; // It's a variable with type information
        }

        // Check for local variable references
        List<Map<String, String>> localVarRefs = dbHandler.getLocalVariableReferences(name, className, functionName);
        if (!localVarRefs.isEmpty()) {
            return true; // It's referenced as a local variable
        }

        // If we can't definitively determine it's a variable, assume it's a function
        return false;
    }

    private static String getVariableType(String variableName, String className) {
        List<Map<String, String>> typeInfo = dbHandler.getTypeInformation(variableName, className);
        if (!typeInfo.isEmpty()) {
            return typeInfo.get(0).get("variableType");
        }
        return null;
    }

    private static void loadLocalVariableReferences(String variableName, String className, String functionName) {
        // Clear existing table data
        tableModel.setRowCount(0);

        // Get local variable references
        List<Map<String, String>> references = dbHandler.getLocalVariableReferences(variableName, className, functionName);

        // Add references to table
        for (Map<String, String> reference : references) {
            String type = "LOCAL_VAR";
            String variable = reference.get("variableName");
            String function = formatReference(reference.get("containingFunction"), 
                                           reference.get("containingClass"));
            String line = reference.get("lineNumber");

            tableModel.addRow(new Object[]{type, variable, function, line});
        }

        // Adjust column widths
        referencesTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Type
        referencesTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Variable
        referencesTable.getColumnModel().getColumn(2).setPreferredWidth(250); // Function
        referencesTable.getColumnModel().getColumn(3).setPreferredWidth(100); // Line
    }

    private static void loadFunctionReferences(String functionName, String className) {
        // Clear existing table data
        tableModel.setRowCount(0);

        // Get function references
        List<Map<String, String>> references = dbHandler.getFunctionCrossReferences(functionName);

        // Add references to table
        for (Map<String, String> reference : references) {
            String type = reference.get("referenceType");
            String source = formatReference(reference.get("sourceFunction"), 
                                         reference.get("sourceClass"));
            String target = formatReference(reference.get("targetFunction"), 
                                         reference.get("targetClass"));
            String line = reference.get("lineNumber");

            tableModel.addRow(new Object[]{type, source, target, line});
        }

        // Adjust column widths
        referencesTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Type
        referencesTable.getColumnModel().getColumn(1).setPreferredWidth(200); // Source
        referencesTable.getColumnModel().getColumn(2).setPreferredWidth(200); // Target
        referencesTable.getColumnModel().getColumn(3).setPreferredWidth(100); // Line
    }

    private static String formatReference(String function, String className) {
        if (function == null || className == null) {
            return "Unknown";
        }
        return String.format("%s::%s", className, function);
    }
} 