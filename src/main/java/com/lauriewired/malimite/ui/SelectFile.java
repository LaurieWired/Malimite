package com.lauriewired.malimite.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

public class SelectFile {
    private static final Map<String, FileTab> openFiles = new HashMap<>();
    private static final List<String> fileOrder = new ArrayList<>();
    private static final JPanel fileTabsContainer = new JPanel(new BorderLayout());
    private static final JPanel fileTabsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
    private static final JButton leftArrow = new JButton("◀");
    private static final JButton rightArrow = new JButton("▶");
    private static String activeFile = null;
    private static int scrollPosition = 0;
    private static final Logger LOGGER = Logger.getLogger(SelectFile.class.getName());
    
    private static class FileTab extends JPanel {
        private final String filePath;
        private final JLabel nameLabel;
        private final JLabel closeButton;
        
        public FileTab(String path, Runnable onClose) {
            this.filePath = path;
            setLayout(new FlowLayout(FlowLayout.LEFT, 2, 0));
            setOpaque(false);
            
            // Extract just the file name from the path
            String fileName = path.contains("/") ? 
                path.substring(path.lastIndexOf('/') + 1) : path;
            
            nameLabel = new JLabel(fileName);
            nameLabel.setBorder(BorderFactory.createEmptyBorder(2, 3, 2, 3));
            nameLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
            
            closeButton = new JLabel("×");
            closeButton.setFont(closeButton.getFont().deriveFont(14f));
            closeButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
            closeButton.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
            
            add(nameLabel);
            add(closeButton);
            
            nameLabel.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getButton() == MouseEvent.BUTTON2) {
                        onClose.run();
                        return;
                    }
                    setActiveFile(filePath);
                }
            });
            
            closeButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    onClose.run();
                }
            });
        }
        
        public void setActive(boolean active) {
            if (active) {
                setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 2, 0, Color.GRAY),
                    BorderFactory.createEmptyBorder(2, 2, 0, 2)
                ));
            } else {
                setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
            }
        }
    }
    
    public static JPanel getFileTabsPanel() {
        // Setup scroll buttons
        leftArrow.setMargin(new Insets(0, 2, 0, 2));
        rightArrow.setMargin(new Insets(0, 2, 0, 2));
        
        leftArrow.addActionListener(e -> scroll(-1));
        rightArrow.addActionListener(e -> scroll(1));
        
        // Add components to container
        fileTabsContainer.add(leftArrow, BorderLayout.WEST);
        fileTabsContainer.add(fileTabsPanel, BorderLayout.CENTER);
        fileTabsContainer.add(rightArrow, BorderLayout.EAST);
        
        return fileTabsContainer;
    }
    
    public static void addFile(TreePath path) {
        //printDebugState("addFile - start");
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        String filePath = buildPathFromNode(node);
        
        // Remove "Empty" tab if it exists
        Component[] components = fileTabsPanel.getComponents();
        for (Component comp : components) {
            if (comp instanceof JLabel && "Empty".equals(((JLabel) comp).getText())) {
                fileTabsPanel.remove(comp);
            }
        }
        
        // Check if file is already open
        if (!openFiles.containsKey(filePath)) {
            FileTab tab = new FileTab(filePath, () -> closeFile(filePath));
            openFiles.put(filePath, tab);
            fileOrder.add(filePath);
            
            // Add the tab to the panel
            fileTabsPanel.add(tab);
        }

        // Force layout update
        fileTabsPanel.revalidate();
        fileTabsContainer.revalidate();
        fileTabsPanel.repaint();
        fileTabsContainer.repaint();
        
        // Set as active file
        setActiveFile(filePath);
        //printDebugState("addFile - end");
    }
    
    private static void closeFile(String filePath) {
        LOGGER.info("Closing file: " + filePath);
        FileTab tab = openFiles.remove(filePath);
        if (tab != null) {
            fileTabsPanel.remove(tab);
            fileOrder.remove(filePath);
            
            if (openFiles.isEmpty()) {
                addEmptyTab();
                setActiveFile(null);
            } else if (filePath.equals(activeFile)) {
                int index = fileOrder.indexOf(filePath);
                if (index > 0) {
                    setActiveFile(fileOrder.get(index - 1));
                } else if (!fileOrder.isEmpty()) {
                    setActiveFile(fileOrder.get(0));
                }
            }
            
            fileTabsPanel.revalidate();
            fileTabsPanel.repaint();
        }
    }
    
    private static void setActiveFile(String filePath) {
        LOGGER.info("Setting active file: " + filePath);
        // Prevent unnecessary updates if the file is already active
        if (filePath != null && filePath.equals(activeFile)) {
            return;
        }

        activeFile = filePath;
        openFiles.forEach((path, tab) -> tab.setActive(path.equals(filePath)));
        
        // Force layout update
        fileTabsPanel.revalidate();
        fileTabsContainer.revalidate();
        fileTabsPanel.repaint();
        fileTabsContainer.repaint();
        
        // Always notify AnalysisWindow to update content, whether filePath is null or not
        AnalysisWindow.showFileContent(filePath);
    }
    
    private static String buildPathFromNode(DefaultMutableTreeNode node) {
        StringBuilder path = new StringBuilder(node.toString());
        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
        
        while (parent != null && !parent.isRoot()) {
            path.insert(0, parent.toString() + "/");
            parent = (DefaultMutableTreeNode) parent.getParent();
        }
        
        return path.toString();
    }
    
    public static void clear() {
        //printDebugState("clear - start");
        openFiles.clear();
        fileOrder.clear();
        fileTabsPanel.removeAll();
        fileTabsPanel.revalidate();
        fileTabsPanel.repaint();
        activeFile = null;
        scrollPosition = 0;
        //printDebugState("clear - end");
    }

    private static void addEmptyTab() {
        JLabel emptyLabel = new JLabel("Empty");
        emptyLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
        fileTabsPanel.add(emptyLabel);
    }

    private static void scroll(int direction) {
        //printDebugState("scroll - start");
        if (fileOrder.isEmpty()) return;
        
        int currentIndex = activeFile != null ? fileOrder.indexOf(activeFile) : -1;
        int newIndex = currentIndex + direction;
        
        if (newIndex >= 0 && newIndex < fileOrder.size()) {
            String newFilePath = fileOrder.get(newIndex);
            setActiveFile(newFilePath); // Sets the new active file
    
            // Ensure this tab is visible in the viewport
            ensureTabVisible(newIndex);
    
            // Force content update in AnalysisWindow
            AnalysisWindow.showFileContent(newFilePath);
        }
        //printDebugState("scroll - end");
    }    

    private static void ensureTabVisible(int index) {
        if (index < 0 || index >= fileTabsPanel.getComponentCount()) return;
    
        Component tab = fileTabsPanel.getComponent(index);
        int tabLeft = tab.getX();
        int tabRight = tabLeft + tab.getWidth();
        int visibleWidth = fileTabsPanel.getParent().getWidth() - leftArrow.getWidth() - rightArrow.getWidth();
    
        if (tabLeft < -scrollPosition) {
            // Scroll left to make the tab visible
            scrollPosition = -tabLeft;
        } else if (tabRight > -scrollPosition + visibleWidth) {
            // Scroll right to make the tab visible
            scrollPosition = -(tabRight - visibleWidth);
        }
    
        // Apply the scroll position to each tab component
        for (Component comp : fileTabsPanel.getComponents()) {
            comp.setLocation(comp.getX() - scrollPosition, comp.getY());
        }
    
        fileTabsPanel.revalidate();
        fileTabsPanel.repaint();
    }

    public static void handleNodeClick(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        String filePath = buildPathFromNode(node);
        
        // Only update if the file is already open and not currently active
        if (openFiles.containsKey(filePath) && !filePath.equals(activeFile)) {
            setActiveFile(filePath);
        }
    }

    public static void replaceActiveFile(TreePath path) {
        LOGGER.info("Replacing active file: " + path);
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        String filePath = buildPathFromNode(node);
        
        // Remove current active file if it exists
        if (activeFile != null) {
            FileTab oldTab = openFiles.remove(activeFile);
            if (oldTab != null) {
                fileTabsPanel.remove(oldTab);
                fileOrder.remove(activeFile);
            }
        }
        
        // Add new file
        FileTab tab = new FileTab(filePath, () -> closeFile(filePath));
        openFiles.put(filePath, tab);
        fileOrder.add(filePath);
        fileTabsPanel.add(tab);
        
        // Set as active
        setActiveFile(filePath);
        
        fileTabsPanel.revalidate();
        fileTabsPanel.repaint();
    }

    public static boolean isFileOpen(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        String filePath = buildPathFromNode(node);
        return openFiles.containsKey(filePath);
    }

    private static void printDebugState(String functionName) {
        LOGGER.fine(() -> "\n=== " + functionName + " ===\n" +
                   "openFiles: " + openFiles.keySet() + "\n" +
                   "fileOrder: " + fileOrder + "\n" +
                   "activeFile: " + activeFile);
    }
}
