package com.lauriewired.malimite;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JPanel;
import javax.swing.JOptionPane;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import javax.swing.BorderFactory;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.BoxLayout;

import java.awt.BorderLayout;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipEntry;

import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.files.InfoPlist;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.database.SQLiteDBHandler;

public class Malimite extends JFrame {

    private static final Logger LOGGER = Logger.getLogger(Malimite.class.getName());

    private JLabel fileNameLabel;
    private JTextArea fileContentArea;
    private DefaultTreeModel treeModel;
    private JTree fileTree;
    private Map<String, String> fileEntriesMap;
    private String currentFilePath; // Path to the file being analyzed
    private String projectDirectoryPath;
    private InfoPlist infoPlist;
    private GhidraProject ghidraProject;
    private String executableFilePath; // Path to the main macho file for this app
    private Macho projectMacho;
    private SQLiteDBHandler dbHandler;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Malimite().setVisible(true));
    }

    public Malimite() {
        super("Malimite");

        fileNameLabel = new JLabel("No file selected");
        fileNameLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        fileEntriesMap = new HashMap<>();

        DefaultMutableTreeNode hiddenRootNode = new DefaultMutableTreeNode("Hidden");
        treeModel = new DefaultTreeModel(hiddenRootNode);

        DefaultMutableTreeNode classesRootNode = new DefaultMutableTreeNode("Classes");
        DefaultMutableTreeNode filesRootNode = new DefaultMutableTreeNode("Files");
        hiddenRootNode.add(classesRootNode);
        hiddenRootNode.add(filesRootNode);

        // Initialize the tree with the hidden root node
        fileTree = new JTree(treeModel);
        fileTree.setRootVisible(false); // Hide the hidden root node
        fileTree.setShowsRootHandles(true); // Show the handles for the actual root nodes

        fileTree.addTreeSelectionListener(e -> displaySelectedFileContent(e));
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

        setLayout(new BorderLayout());
        add(splitPane, BorderLayout.CENTER);

        setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    @SuppressWarnings("unchecked")
                    List<File> droppedFiles = (List<File>) evt
                            .getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    classesRootNode.removeAllChildren();
                    for (File file : droppedFiles) {
                        fileNameLabel.setText(file.getName());
                        filesRootNode.removeAllChildren();
                        treeModel.reload();
                        fileEntriesMap.clear();
                        fileContentArea.setText("");
                        unzipAndLoadToTree(file, filesRootNode, classesRootNode);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
    }

    private void unzipAndLoadToTree(File fileToUnzip, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Analyzing " + fileToUnzip);
        this.currentFilePath = fileToUnzip.toString();
    
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
            populateDatabase();
            populateClassesNode(classesRootNode);
    
            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(this.fileTree);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error unzipping and loading to tree", e);
        }
    }
    
    private void populateClassesNode(DefaultMutableTreeNode classesRootNode) {
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

    private void populateDatabase() {
        LOGGER.info("Initializing database for Malimite data");

        LOGGER.info("projectDirectoryPath: " + projectDirectoryPath);
        LOGGER.info("projectMacho.getMachoExecutableName(): " + projectMacho.getMachoExecutableName());

        this.dbHandler = new SQLiteDBHandler(this.projectDirectoryPath + File.separator, this.projectMacho.getMachoExecutableName() + "_malimite.db");
        dbHandler.populateInitialClassData(this.projectDirectoryPath + File.separator + "malimite_class_data.json");

        LOGGER.info("Finished initializing database");

        LOGGER.info("Adding function data to database");

        dbHandler.populateFunctionData(this.projectDirectoryPath, this.projectDirectoryPath + File.separator + "functions_info.json");

        LOGGER.info("Finished adding function data to database");
    }

    private void initializeGhidraProject() {
        // Populate the classes based on the main executable macho
        this.projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(this.currentFilePath, 
            this.infoPlist.getExecutableName(), this.projectDirectoryPath);
        FileProcessing.openProject(this.currentFilePath, this.projectDirectoryPath, this.infoPlist.getExecutableName());

        // Run ghidra command to perform the decompilation
        this.executableFilePath = this.projectDirectoryPath + File.separator + this.infoPlist.getExecutableName();

        this.projectMacho = new Macho(executableFilePath, this.projectDirectoryPath, this.infoPlist.getExecutableName());
        ghidraProject = new GhidraProject(this.infoPlist.getExecutableName(), this.executableFilePath);
    
        // Let the user select the architecture if it is a Universal binary
        if (this.projectMacho.isUniversalBinary()) {
            List<String> architectures = this.projectMacho.getArchitectureStrings();
            String selectedArchitecture = selectArchitecture(architectures);
            if (selectedArchitecture != null) {
                this.projectMacho.processUniversalMacho(selectedArchitecture);
            }
        }
        this.projectMacho.printArchitectures();
        ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, this.projectMacho);
    }

    private String selectArchitecture(List<String> architectures) {
        JComboBox<String> architectureComboBox = new JComboBox<>(architectures.toArray(new String[0]));
        int result = JOptionPane.showConfirmDialog(null, architectureComboBox, "Select Architecture", 
                                                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            return (String) architectureComboBox.getSelectedItem();
        }
        return null;
    }
    
    private void handleEntry(ZipEntry entry, DefaultMutableTreeNode appNode, ZipInputStream zipIn) throws IOException {
        String relativePath = entry.getName().substring(appNode.toString().length());
        DefaultMutableTreeNode currentNode;
    
        if (relativePath.equals("Info.plist")) {
            currentNode = new DefaultMutableTreeNode("Info.plist");
            appNode.add(currentNode);
            fileEntriesMap.put(NodeOperations.buildFullPathFromNode(currentNode), entry.getName());
            this.infoPlist = new InfoPlist(currentNode, this.currentFilePath, this.fileEntriesMap);
        } else {
            // Create or get the "Resources" node and add other files to it
            currentNode = NodeOperations.addOrGetNode(appNode, "Resources", true);
    
            // Skip the first part of the path if it's a directory
            String[] pathParts = relativePath.split("/");
            for (int i = (entry.isDirectory() ? 1 : 0); i < pathParts.length; i++) {
                boolean isDirectory = i < pathParts.length - 1 || entry.isDirectory();
                currentNode = NodeOperations.addOrGetNode(currentNode, pathParts[i], isDirectory);
    
                if (!isDirectory) {
                    this.fileEntriesMap.put(NodeOperations.buildFullPathFromNode(currentNode), entry.getName());
                }
            }
        }
    }

    private void displaySelectedFileContent(TreeSelectionEvent e) {
        TreePath path = e.getPath();
        StringBuilder fullPath = new StringBuilder();
    
        // Skip the root node and concatenate the rest to form the full path
        for (int i = 1; i < path.getPathCount(); i++) {
            if (fullPath.length() > 0 && fullPath.charAt(fullPath.length() - 1) != '/') {
                fullPath.append("/"); // Append '/' if it's not the last character
            }
            fullPath.append(((DefaultMutableTreeNode) path.getPathComponent(i)).getUserObject().toString());
        }

        //System.out.println("fileEntriesMap.get(fullPath.toString()): " + fileEntriesMap.get(fullPath.toString()));
        //System.out.println("fullPath: " + fullPath);

        if (this.currentFilePath != null) {
            try {
                byte[] contentBytes = FileProcessing.readContentFromZip(this.currentFilePath, fileEntriesMap.get(fullPath.toString()));
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
}
