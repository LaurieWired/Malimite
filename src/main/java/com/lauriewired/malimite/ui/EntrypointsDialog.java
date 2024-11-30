package com.lauriewired.malimite.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import com.lauriewired.malimite.database.SQLiteDBHandler;

public class EntrypointsDialog {
    private static final Set<String> ENTRYPOINT_FUNCTIONS = new HashSet<>(Arrays.asList(
        "applicationDidFinishLaunching",
        "application:didFinishLaunchingWithOptions",
        "applicationWillResignActive",
        "applicationDidEnterBackground",
        "applicationWillEnterForeground",
        "applicationDidBecomeActive",
        "applicationWillTerminate",
        "application:configurationForConnectingSceneSession:options",
        "application:didDiscardSceneSessions",
        "application:openURL:options",
        "application:performFetchWithCompletionHandler",
        "application:didReceiveRemoteNotification:fetchCompletionHandler",
        "application:handleEventsForBackgroundURLSession:completionHandler",
        "application:shouldSaveSecureApplicationState",
        "application:shouldRestoreSecureApplicationState",
        "application:didRegisterForRemoteNotificationsWithDeviceToken",
        "application:didFailToRegisterForRemoteNotificationsWithError",
        "application:didReceiveRemoteNotification",
        "application:handleOpenURL",
        "application:continueUserActivity:restorationHandler",
        "application:didUpdateUserActivity",
        "scene:willConnectToSession:options",
        "sceneDidDisconnect",
        "sceneDidBecomeActive",
        "sceneWillResignActive",
        "sceneWillEnterForeground",
        "sceneDidEnterBackground",
        "application:handleWatchKitExtensionRequest:reply",
        "main",
        "loadView",
        "viewDidLoad"
    ));

    public static void show(JFrame parentFrame, SQLiteDBHandler dbHandler) {
        JDialog dialog = new JDialog(parentFrame, "Entrypoints", true);
        dialog.setLayout(new BorderLayout());

        // Create table model with column names
        DefaultTableModel tableModel = new DefaultTableModel(
            new String[]{"Class Name", "Entrypoint Function"}, 
            0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table read-only
            }
        };

        // Find all entrypoints
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
        List<String[]> foundEntrypoints = new ArrayList<>();
        
        for (Map.Entry<String, List<String>> entry : classesAndFunctions.entrySet()) {
            String className = entry.getKey();
            List<String> functions = entry.getValue();
            
            for (String function : functions) {
                if (ENTRYPOINT_FUNCTIONS.contains(function)) {
                    foundEntrypoints.add(new String[]{className, function});
                }
            }
        }

        // Sort entrypoints by class name, then function name
        Collections.sort(foundEntrypoints, (a, b) -> {
            int classCompare = a[0].compareTo(b[0]);
            return classCompare != 0 ? classCompare : a[1].compareTo(b[1]);
        });

        // Add sorted entrypoints to table model
        for (String[] entrypoint : foundEntrypoints) {
            tableModel.addRow(entrypoint);
        }

        // Create and configure the JTable
        JTable entrypointTable = new JTable(tableModel);
        entrypointTable.setFillsViewportHeight(true);
        entrypointTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        
        // Make columns resize better
        entrypointTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        entrypointTable.getColumnModel().getColumn(1).setPreferredWidth(300);

        // Add double-click listener
        entrypointTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = entrypointTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        String className = (String) tableModel.getValueAt(row, 0);
                        String functionName = (String) tableModel.getValueAt(row, 1);
                        
                        // Close the dialog
                        dialog.dispose();
                        
                        // Navigate to the selected function in the analysis window
                        SwingUtilities.invokeLater(() -> {
                            // Navigate to the function using the path format
                            String path = "Classes/" + className + "/" + functionName;
                            AnalysisWindow.showFileContent(path);
                        });
                    }
                }
            }
        });

        // Add the table to a scroll pane
        JScrollPane scrollPane = new JScrollPane(entrypointTable);
        dialog.add(scrollPane, BorderLayout.CENTER);

        // Add a close button at the bottom
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        // Set dialog size and show it
        dialog.setSize(800, 500);
        dialog.setLocationRelativeTo(parentFrame);
        dialog.setVisible(true);
    }
} 