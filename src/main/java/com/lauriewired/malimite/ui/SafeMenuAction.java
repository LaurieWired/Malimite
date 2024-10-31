package com.lauriewired.malimite.ui;

import javax.swing.JDialog;
import javax.swing.SwingUtilities;
import java.util.logging.Logger;

public class SafeMenuAction {
    private static final Logger LOGGER = Logger.getLogger(SafeMenuAction.class.getName());
    private static boolean menuActionInProgress = false;
    private static final Object menuLock = new Object();
    private static JDialog preferencesDialog = null;

    public static void execute(Runnable action) {
        synchronized (menuLock) {
            if (menuActionInProgress) {
                return;  // Prevents simultaneous actions
            }
            menuActionInProgress = true;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                action.run();
            } catch (Exception ex) {
                LOGGER.severe("Error in menu action: " + ex.getMessage());
            } finally {
                releaseMenuLock();  // Ensure the lock is always released
            }
        });
    }

    private static void releaseMenuLock() {
        synchronized (menuLock) {
            menuActionInProgress = false;
        }
    }

    public static JDialog getPreferencesDialog() {
        return preferencesDialog;
    }

    public static void setPreferencesDialog(JDialog dialog) {
        cleanupPreferencesDialog();  // Ensure old dialog is disposed
        preferencesDialog = dialog;
    }

    public static void cleanupPreferencesDialog() {
        if (preferencesDialog != null) {
            preferencesDialog.dispose();  // Dispose of existing dialog to avoid conflicts
            preferencesDialog = null;
        }
    }
}