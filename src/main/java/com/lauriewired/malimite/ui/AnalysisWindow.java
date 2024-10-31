package com.lauriewired.malimite.ui;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.files.InfoPlist;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.configuration.Project;
public class AnalysisWindow {
    private static final Logger LOGGER = Logger.getLogger(AnalysisWindow.class.getName());

    private static JFrame analysisFrame;  // Singleton instance
    private static JLabel fileNameLabel;
    private static RSyntaxTextArea fileContentArea;
    private static DefaultTreeModel treeModel;
    private static JTree fileTree;
    private static Map<String, String> fileEntriesMap;
    private static String currentFilePath;

    private static SQLiteDBHandler dbHandler;
    private static GhidraProject ghidraProject;
    private static String projectDirectoryPath;
    private static String executableFilePath;
    private static InfoPlist infoPlist;
    private static Macho projectMacho;
    private static Config config;

    public static void show(File file, Config config) {
        SafeMenuAction.execute(() -> {
            if (analysisFrame != null && analysisFrame.isVisible()) {
                analysisFrame.toFront();
                return;
            }

            AnalysisWindow.config = config;
            analysisFrame = new JFrame("Malimite - Analysis");
            analysisFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            analysisFrame.setSize(800, 600);
            analysisFrame.setExtendedState(JFrame.MAXIMIZED_BOTH);

            currentFilePath = file.getAbsolutePath();
            fileEntriesMap = new HashMap<>();

            JPanel contentPanel = setupUIComponents();
            analysisFrame.getContentPane().add(contentPanel, BorderLayout.CENTER);

            DefaultMutableTreeNode hiddenRoot = (DefaultMutableTreeNode) treeModel.getRoot();
            DefaultMutableTreeNode classesRootNode = (DefaultMutableTreeNode) hiddenRoot.getChildAt(0);
            DefaultMutableTreeNode filesRootNode = (DefaultMutableTreeNode) hiddenRoot.getChildAt(1);

            loadAndAnalyzeFile(file, filesRootNode, classesRootNode);

            analysisFrame.setVisible(true);

            analysisFrame.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent e) {
                    analysisFrame = null;
                }
            });

            ApplicationMenu applicationMenu = new ApplicationMenu(
                analysisFrame, 
                fileTree,
                config
            );
            analysisFrame.setJMenuBar(applicationMenu.createMenuBar());
        });
    }

    private static JPanel setupUIComponents() {
        fileNameLabel = new JLabel("Analyzing " + currentFilePath);
        fileNameLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
    
        DefaultMutableTreeNode hiddenRootNode = new DefaultMutableTreeNode("Hidden");
        treeModel = new DefaultTreeModel(hiddenRootNode);
        DefaultMutableTreeNode classesRootNode = new DefaultMutableTreeNode("Classes");
        DefaultMutableTreeNode filesRootNode = new DefaultMutableTreeNode("Files");
        hiddenRootNode.add(classesRootNode);
        hiddenRootNode.add(filesRootNode);
    
        fileTree = new JTree(treeModel);
        fileTree.setRootVisible(false);
        fileTree.addTreeSelectionListener(AnalysisWindow::displaySelectedFileContent);
        JScrollPane treeScrollPane = new JScrollPane(fileTree);
    
        // Initialize RSyntaxTextArea with syntax highlighting
        fileContentArea = new RSyntaxTextArea();
        fileContentArea.setEditable(false);
        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        fileContentArea.setCodeFoldingEnabled(true);

        SyntaxUtility.applyCustomTheme(fileContentArea);
    
        // Add RSyntaxTextArea to RTextScrollPane
        RTextScrollPane contentScrollPane = new RTextScrollPane(fileContentArea);
    
        // Create info display panel
        JTextPane infoDisplay = new JTextPane();
        infoDisplay.setContentType("text/html");
        infoDisplay.setEditable(false);
        infoDisplay.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        
        // Create a scroll pane for the info display
        JScrollPane infoScrollPane = new JScrollPane(infoDisplay);
        infoScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create left panel with vertical split
        JPanel leftPanel = new JPanel(new BorderLayout());
        
        // Create a panel for the tree
        JPanel treePanel = new JPanel(new BorderLayout());
        treePanel.add(fileNameLabel, BorderLayout.NORTH);
        treePanel.add(treeScrollPane, BorderLayout.CENTER);
        
        // Create vertical split pane for tree and info
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, treePanel, infoScrollPane);
        leftSplitPane.setResizeWeight(0.7); // This will give 70% to tree by default
        
        // Add the split pane to left panel
        leftPanel.add(leftSplitPane, BorderLayout.CENTER);

        // Create bundle identifier panel (updated)
        JPanel bundleIdPanel = new JPanel(new BorderLayout());
        bundleIdPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JLabel bundleIdValue = new JLabel("Loading...", SwingConstants.CENTER);
        bundleIdValue.setFont(bundleIdValue.getFont().deriveFont(Font.BOLD));
        bundleIdPanel.add(bundleIdValue, BorderLayout.CENTER);

        // Create right panel to hold bundle ID and content
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(bundleIdPanel, BorderLayout.NORTH);
        rightPanel.add(contentScrollPane, BorderLayout.CENTER);

        // Update the split pane to use the right panel instead of just contentScrollPane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        splitPane.setDividerLocation(300);

        // Update the file info display
        updateFileInfo(new File(currentFilePath), infoDisplay);

        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(splitPane, BorderLayout.CENTER);
        analysisFrame.getContentPane().add(contentPanel, BorderLayout.CENTER);
        return contentPanel;
    }

    private static void updateFileInfo(File file, JTextPane infoDisplay) {
        Project project = new Project();
        project.setFileName(file.getName());
        project.setFilePath(file.getAbsolutePath());
        project.setFileSize(file.length());
        
        try {
            // Check if it's a Mach-O file
            Macho macho = new Macho(file.getAbsolutePath(), 
                                   file.getParent(), 
                                   file.getName());
            
            project.setIsMachO(true);
            project.setMachoInfo(macho);
            
            if (macho.isUniversalBinary()) {
                project.setFileType("Universal Mach-O Binary");
            } else {
                project.setFileType("Single Architecture Mach-O");
            }
        } catch (Exception ex) {
            project.setFileType("Unknown or unsupported file format");
            project.setIsMachO(false);
            LOGGER.warning("Error reading file format: " + ex.getMessage());
        }
        
        infoDisplay.setText(project.generateInfoString());
    }

    private static void loadAndAnalyzeFile(File file, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Starting analysis on " + file.getName());
        fileNameLabel.setText(file.getName());
        LOGGER.info("Clearing previous tree data");
        filesRootNode.removeAllChildren();
        treeModel.reload();
        fileEntriesMap.clear();
        fileContentArea.setText("");
        LOGGER.info("Beginning file unzip and analysis process");
        unzipAndLoadToTree(file, filesRootNode, classesRootNode);
    }

    private static void unzipAndLoadToTree(File fileToUnzip, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Analyzing " + fileToUnzip);
        currentFilePath = fileToUnzip.toString();
    
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(fileToUnzip))) {
            ZipEntry entry = zipIn.getNextEntry();
            DefaultMutableTreeNode appNode = null;
        
            // Populate the files section
            while (entry != null) {
                if (entry.getName().endsWith(".app/")) {
                    appNode = new DefaultMutableTreeNode(entry.getName());
                    filesRootNode.add(appNode);
                } else if (appNode != null && entry.getName().startsWith(appNode.toString())) {
                    handleEntry(entry, appNode, zipIn);
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            LOGGER.info("Finished extracting resources");

            initializeProject();
            populateClassesNode(classesRootNode);
    
            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(fileTree);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error unzipping and loading to tree", e);
        }
    }
    
    private static void populateClassesNode(DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Populating classes tree...");
        classesRootNode.removeAllChildren();
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
        LOGGER.info("Retrieved " + classesAndFunctions.size() + " classes from database");

        for (Map.Entry<String, List<String>> entry : classesAndFunctions.entrySet()) {
            String className = entry.getKey();
            List<String> functions = entry.getValue();
            LOGGER.fine("Adding class: " + className + " with " + functions.size() + " functions");
            DefaultMutableTreeNode classNode = new DefaultMutableTreeNode(className);
            for (String function : functions) {
                classNode.add(new DefaultMutableTreeNode(function));
            }
            classesRootNode.add(classNode);
        }
        LOGGER.info("Finished populating classes tree");
    }

    private static void initializeProject() {
        LOGGER.info("Initializing project...");
        projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(currentFilePath, 
            infoPlist.getExecutableName(), config.getConfigDirectory());
        LOGGER.info("Project directory created at: " + projectDirectoryPath);

        FileProcessing.openProject(currentFilePath, projectDirectoryPath, 
            infoPlist.getExecutableName(), config.getConfigDirectory());

        executableFilePath = projectDirectoryPath + File.separator + infoPlist.getExecutableName();
        LOGGER.info("Loading Mach-O file: " + executableFilePath);
        projectMacho = new Macho(executableFilePath, projectDirectoryPath, infoPlist.getExecutableName());

        String dbFilePath = projectDirectoryPath + File.separator + 
            projectMacho.getMachoExecutableName() + "_malimite.db";
        LOGGER.info("Checking for database at: " + dbFilePath);

        File dbFile = new File(dbFilePath);
        if (!dbFile.exists()) {
            LOGGER.info("Database not found. Creating new database...");
            dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                projectMacho.getMachoExecutableName() + "_malimite.db");

            LOGGER.info("Starting Ghidra analysis...");
            ghidraProject = new GhidraProject(infoPlist.getExecutableName(), 
                executableFilePath, config, dbHandler);
        
            if (projectMacho.isUniversalBinary()) {
                LOGGER.info("Universal binary detected. Prompting for architecture selection...");
                List<String> architectures = projectMacho.getArchitectureStrings();
                String selectedArchitecture = selectArchitecture(architectures);
                if (selectedArchitecture != null) {
                    LOGGER.info("Selected architecture: " + selectedArchitecture);
                    projectMacho.processUniversalMacho(selectedArchitecture);
                }
            }
            projectMacho.printArchitectures();
            LOGGER.info("Starting Ghidra decompilation process...");
            ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, projectMacho);
        } else {
            LOGGER.info("Using existing database from previous analysis");
            dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                projectMacho.getMachoExecutableName() + "_malimite.db");
        }
    }

    private static String selectArchitecture(List<String> architectures) {
        JComboBox<String> architectureComboBox = new JComboBox<>(architectures.toArray(new String[0]));
        int result = JOptionPane.showConfirmDialog(null, architectureComboBox, "Select Architecture", 
                                                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            return (String) architectureComboBox.getSelectedItem();
        }
        return null;
    }
    
    private static void handleEntry(ZipEntry entry, DefaultMutableTreeNode appNode, ZipInputStream zipIn) throws IOException {
        String relativePath = entry.getName().substring(appNode.toString().length());
        DefaultMutableTreeNode currentNode;
    
        if (relativePath.equals("Info.plist")) {
            currentNode = new DefaultMutableTreeNode("Info.plist");
            appNode.add(currentNode);
            fileEntriesMap.put(NodeOperations.buildFullPathFromNode(currentNode), entry.getName());
            infoPlist = new InfoPlist(currentNode, currentFilePath, fileEntriesMap);
            updateBundleIdDisplay(infoPlist.getBundleIdentifier());
        } else {
            // Create or get the "Resources" node and add other files to it
            currentNode = NodeOperations.addOrGetNode(appNode, "Resources", true);
    
            // Skip the first part of the path if it's a directory
            String[] pathParts = relativePath.split("/");
            for (int i = (entry.isDirectory() ? 1 : 0); i < pathParts.length; i++) {
                boolean isDirectory = i < pathParts.length - 1 || entry.isDirectory();
                currentNode = NodeOperations.addOrGetNode(currentNode, pathParts[i], isDirectory);
    
                if (!isDirectory) {
                    fileEntriesMap.put(NodeOperations.buildFullPathFromNode(currentNode), entry.getName());
                }
            }
        }
    }

    private static void displaySelectedFileContent(TreeSelectionEvent e) {
        TreePath path = e.getPath();
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
    
        // Check if we're in the Classes root
        if (isInClassesTree(path)) {
            // If this is a class node (direct child of "Classes" node)
            if (path.getPathCount() == 3) {
                String className = node.getUserObject().toString();
                displayClassDecompilation(className);
                return;
            }
            // If this is a function node (grandchild of "Classes" node)
            else if (path.getPathCount() == 4) {
                DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode) node.getParent();
                String className = parentNode.getUserObject().toString();
                displayClassDecompilation(className);
                return;
            }
        }

        // Original file content display logic for the Files tree
        StringBuilder fullPath = new StringBuilder();
        for (int i = 1; i < path.getPathCount(); i++) {
            if (fullPath.length() > 0 && fullPath.charAt(fullPath.length() - 1) != '/') {
                fullPath.append("/");
            }
            fullPath.append(((DefaultMutableTreeNode) path.getPathComponent(i)).getUserObject().toString());
        }

        //System.out.println("fileEntriesMap.get(fullPath.toString()): " + fileEntriesMap.get(fullPath.toString()));
        //System.out.println("fullPath: " + fullPath);

        if (currentFilePath != null) {
            try {
                byte[] contentBytes = FileProcessing.readContentFromZip(currentFilePath, fileEntriesMap.get(fullPath.toString()));
                String contentText;
        
                // Decode if it's a binary plist. Otherwise, just print the text
                if (fullPath.toString().endsWith("plist") && PlistUtils.isBinaryPlist(contentBytes)) {
                    System.out.println("Handling binary property list");
                    contentText = PlistUtils.decodeBinaryPropertyList(contentBytes);
                } else {
                    contentText = new String(contentBytes);
                }
        
                fileContentArea.setText(contentText);
                fileContentArea.setCaretPosition(0);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static boolean isInClassesTree(TreePath path) {
        if (path.getPathCount() < 2) return false;
        DefaultMutableTreeNode secondNode = (DefaultMutableTreeNode) path.getPathComponent(1);
        return secondNode.getUserObject().toString().equals("Classes");
    }

    private static void displayClassDecompilation(String className) {
        try {
            String decompiledCode = dbHandler.getClassDecompilation(className);
            if (decompiledCode != null && !decompiledCode.isEmpty()) {
                fileContentArea.setText(decompiledCode);
                fileContentArea.setCaretPosition(0);
            } else {
                fileContentArea.setText("No decompilation available for " + className);
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error displaying decompilation for " + className, ex);
            fileContentArea.setText("Error loading decompilation for " + className);
        }
    }

    public static void safeMenuAction(Runnable action) {
        SafeMenuAction.execute(action);
    }
    // Add method to update bundle ID display (simplified)
    private static void updateBundleIdDisplay(String bundleId) {
        SwingUtilities.invokeLater(() -> {
            Container contentPane = analysisFrame.getContentPane();
            Component mainPanel = contentPane.getComponent(0);
            if (mainPanel instanceof JPanel) {
                JSplitPane splitPane = (JSplitPane) ((JPanel)mainPanel).getComponent(0);
                Component rightComp = splitPane.getRightComponent();
                if (rightComp instanceof JPanel) {
                    JPanel rightPanel = (JPanel)rightComp;
                    Component bundlePanel = rightPanel.getComponent(0);
                    if (bundlePanel instanceof JPanel) {
                        JPanel bundleIdPanel = (JPanel)bundlePanel;
                        Component valueLabel = bundleIdPanel.getComponent(0);
                        if (valueLabel instanceof JLabel) {
                            ((JLabel)valueLabel).setText(bundleId != null ? bundleId : "N/A");
                        }
                    }
                }
            }
        });
    }
}
