package com.lauriewired.malimite.ui;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.event.TreeSelectionEvent;

import java.awt.BorderLayout;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.files.InfoPlist;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.PlistUtils;

public class AnalysisWindow {
    private static final Logger LOGGER = Logger.getLogger(AnalysisWindow.class.getName());

    private static JLabel fileNameLabel;
    private static JTextArea fileContentArea;
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

    public static void show(JFrame frame, File file, Config config) {
        // Store config in the static field
        AnalysisWindow.config = config;
        frame.setTitle("Malimite - Analysis");
        frame.setExtendedState(JFrame.MAXIMIZED_BOTH);  // Maximize the window
        frame.setVisible(true);

        currentFilePath = file.getAbsolutePath();
        fileEntriesMap = new HashMap<>();

        // Set up UI elements
        JPanel contentPanel = setupUIComponents();
        
        frame.getContentPane().removeAll(); // Clear previous components
        frame.getContentPane().add(contentPanel, BorderLayout.CENTER);

        // Get the root nodes from the tree model
        DefaultMutableTreeNode hiddenRoot = (DefaultMutableTreeNode) treeModel.getRoot();
        DefaultMutableTreeNode classesRootNode = (DefaultMutableTreeNode) hiddenRoot.getChildAt(0);
        DefaultMutableTreeNode filesRootNode = (DefaultMutableTreeNode) hiddenRoot.getChildAt(1);

        // Load and analyze file
        loadAndAnalyzeFile(file, filesRootNode, classesRootNode);

        frame.revalidate();
        frame.repaint();
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

        fileContentArea = new JTextArea();
        fileContentArea.setEditable(false);
        JScrollPane contentScrollPane = new JScrollPane(fileContentArea);

        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.add(fileNameLabel);
        leftPanel.add(treeScrollPane);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, contentScrollPane);
        splitPane.setDividerLocation(300);

        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(splitPane, BorderLayout.CENTER);
        return contentPanel;
    }

    private static void loadAndAnalyzeFile(File file, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Starting analysis on " + file.getName());
        fileNameLabel.setText(file.getName());
        filesRootNode.removeAllChildren();
        treeModel.reload();
        fileEntriesMap.clear();
        fileContentArea.setText("");
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

            initializeGhidraProject();
            populateClassesNode(classesRootNode);
    
            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(fileTree);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error unzipping and loading to tree", e);
        }
    }
    
    private static void populateClassesNode(DefaultMutableTreeNode classesRootNode) {
        classesRootNode.removeAllChildren();
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();

        for (Map.Entry<String, List<String>> entry : classesAndFunctions.entrySet()) {
            String className = entry.getKey();
            List<String> functions = entry.getValue();

            DefaultMutableTreeNode classNode = new DefaultMutableTreeNode(className);
            for (String function : functions) {
                classNode.add(new DefaultMutableTreeNode(function));
            }
            classesRootNode.add(classNode);
        }
    }

    private static void initializeGhidraProject() {
        // Populate the classes based on the main executable macho
        projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(currentFilePath, 
            infoPlist.getExecutableName(), projectDirectoryPath);
        FileProcessing.openProject(currentFilePath, projectDirectoryPath, infoPlist.getExecutableName());

        // Run ghidra command to perform the decompilation
        executableFilePath = projectDirectoryPath + File.separator + infoPlist.getExecutableName();

        projectMacho = new Macho(executableFilePath, projectDirectoryPath, infoPlist.getExecutableName());

        // Initialize database before creating GhidraProject
        dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
            projectMacho.getMachoExecutableName() + "_malimite.db");
        
        // Pass dbHandler to GhidraProject constructor
        ghidraProject = new GhidraProject(infoPlist.getExecutableName(), 
            executableFilePath, config, dbHandler);
    
        // Let the user select the architecture if it is a Universal binary
        if (projectMacho.isUniversalBinary()) {
            List<String> architectures = projectMacho.getArchitectureStrings();
            String selectedArchitecture = selectArchitecture(architectures);
            if (selectedArchitecture != null) {
                projectMacho.processUniversalMacho(selectedArchitecture);
            }
        }
        projectMacho.printArchitectures();
        ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, projectMacho);
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
}
