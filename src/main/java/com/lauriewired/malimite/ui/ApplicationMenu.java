package com.lauriewired.malimite.ui;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.configuration.Config;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;

import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.ui.ReferenceHandler;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

public class ApplicationMenu {
    private final JFrame parentFrame;
    private final JTree fileTree;
    private final Config config;

    public ApplicationMenu(JFrame parentFrame, JTree fileTree, Config config) {
        this.parentFrame = parentFrame;
        this.fileTree = fileTree;
        this.config = config;
    }

    public JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.add(createFileMenu());
        menuBar.add(createViewMenu());
        menuBar.add(createWindowsMenu());
        menuBar.add(createHelpMenu());
        return menuBar;
    }

    private JMenu createFileMenu() {
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);

        addMenuItem(fileMenu, "Preferences...", e -> {
            SwingUtilities.invokeLater(() -> PreferencesDialog.show(parentFrame, config));
        }, KeyStroke.getKeyStroke(KeyEvent.VK_COMMA, KeyEvent.CTRL_DOWN_MASK));

        addMenuItem(fileMenu, "Close Window", e -> {
            parentFrame.dispose();
        }, KeyStroke.getKeyStroke(KeyEvent.VK_W, KeyEvent.CTRL_DOWN_MASK));

        fileMenu.addSeparator();

        addMenuItem(fileMenu, "Edit Function", e -> {
            TreePath path = fileTree.getSelectionPath();
            if (path != null && path.getPathCount() == 4 && 
                ((DefaultMutableTreeNode)path.getPathComponent(1)).getUserObject().toString().equals("Classes")) {
                AnalysisWindow.startEditing(path);
            } else {
                JOptionPane.showMessageDialog(parentFrame,
                    "Please select a function in the Classes tree to edit.",
                    "No Function Selected",
                    JOptionPane.WARNING_MESSAGE);
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_E, KeyEvent.CTRL_DOWN_MASK));

        return fileMenu;
    }

    private JMenu createViewMenu() {
        JMenu viewMenu = new JMenu("View");
        viewMenu.setMnemonic(KeyEvent.VK_V);

        if (fileTree != null) {
            addMenuItem(viewMenu, "Expand All", e -> 
                NodeOperations.expandAllTreeNodes(fileTree),
                KeyStroke.getKeyStroke(KeyEvent.VK_E, KeyEvent.CTRL_DOWN_MASK)
            );

            viewMenu.addSeparator();

            addMenuItem(viewMenu, "Collapse All", e -> 
                NodeOperations.collapseAllTreeNodes(fileTree),
                KeyStroke.getKeyStroke(KeyEvent.VK_C, KeyEvent.CTRL_DOWN_MASK)
            );

            viewMenu.addSeparator();
        }

        addMenuItem(viewMenu, "Zoom In", e -> 
            AnalysisWindow.zoomIn(),
            KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, KeyEvent.CTRL_DOWN_MASK)
        );

        addMenuItem(viewMenu, "Zoom Out", e -> 
            AnalysisWindow.zoomOut(),
            KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, KeyEvent.CTRL_DOWN_MASK)
        );

        addMenuItem(viewMenu, "Reset Zoom", e -> 
            AnalysisWindow.resetZoom(),
            KeyStroke.getKeyStroke(KeyEvent.VK_0, KeyEvent.CTRL_DOWN_MASK)
        );

        return viewMenu;
    }

    private JMenu createWindowsMenu() {
        JMenu windowsMenu = new JMenu("Windows");
        windowsMenu.setMnemonic(KeyEvent.VK_W);

        addMenuItem(windowsMenu, "Right Panel", e -> {
            System.out.println("Right Panel toggle clicked");
            AnalysisWindow.toggleRightPanel();
        },
            KeyStroke.getKeyStroke(KeyEvent.VK_L, config.isMac() ? KeyEvent.META_DOWN_MASK : KeyEvent.CTRL_DOWN_MASK)
        );

        windowsMenu.addSeparator();

        addMenuItem(windowsMenu, "Xrefs", e -> {
            String className = AnalysisWindow.getCurrentClassName();
            String functionName = AnalysisWindow.getCurrentFunctionName();
            SQLiteDBHandler dbHandler = AnalysisWindow.getDbHandler();
            RSyntaxTextArea textArea = AnalysisWindow.getFileContentArea();
            
            if (className != null && dbHandler != null && textArea != null) {
                ReferenceHandler.handleReferenceRequest(textArea, parentFrame, className, dbHandler, functionName);
            }
        },
            KeyStroke.getKeyStroke(KeyEvent.VK_X, KeyEvent.CTRL_DOWN_MASK)
        );

        windowsMenu.addSeparator();

        addMenuItem(windowsMenu, "Entrypoints", e -> {
            EntrypointsDialog.show(parentFrame, AnalysisWindow.getDbHandler());
        });

        return windowsMenu;
    }

    private JMenu createHelpMenu() {
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);

        addMenuItem(helpMenu, "About", e -> 
            JOptionPane.showMessageDialog(parentFrame,
                "Malimite - iOS Malware Analysis Tool\nVersion 1.0\n© 2024",
                "About Malimite",
                JOptionPane.INFORMATION_MESSAGE)
        );

        return helpMenu;
    }

    private void addMenuItem(JMenu menu, String text, ActionListener action, KeyStroke accelerator) {
        JMenuItem menuItem = new JMenuItem(text);
        if (accelerator != null) {
            menuItem.setAccelerator(accelerator);
        }
        menuItem.addActionListener(e -> SafeMenuAction.execute(() -> action.actionPerformed(e)));
        menu.add(menuItem);
    }

    private void addMenuItem(JMenu menu, String text, ActionListener action) {
        addMenuItem(menu, text, action, null);
    }
} 