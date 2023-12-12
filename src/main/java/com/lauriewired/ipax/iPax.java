package com.lauriewired.ipax;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.*;
import java.util.*;
import java.util.zip.*;

import com.lauriewired.ipax.utils.NodeOperations;
import com.lauriewired.ipax.utils.FileProcessing;
import com.lauriewired.ipax.utils.PlistUtils;
import com.lauriewired.ipax.files.InfoPlist;

public class iPax extends JFrame {

    private JLabel fileNameLabel;
    private JTextArea fileContentArea;
    private DefaultTreeModel treeModel;
    private JTree fileTree;
    private Map<String, String> fileEntriesMap;
    private String currentFilePath; // Path to the file being analyzed
    private String projectDirectoryPath;
    private InfoPlist infoPlist;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new iPax().setVisible(true));
    }

    public iPax() {
        super("iPax");

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
                    java.util.List<File> droppedFiles = (java.util.List<File>) evt
                            .getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    classesRootNode.removeAllChildren();
                    for (File file : droppedFiles) {
                        fileNameLabel.setText(file.getName());
                        filesRootNode.removeAllChildren();
                        treeModel.reload();
                        fileEntriesMap.clear();
                        fileContentArea.setText("");
                        unzipAndLoadToTree(file, filesRootNode);
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

    private void unzipAndLoadToTree(File fileToUnzip, DefaultMutableTreeNode filesRootNode) {
        System.out.println("Analyzing " + fileToUnzip);
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
            System.out.println("Finished extracting resources");

            // Populate the classes based on the main executable macho
            this.projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(this.currentFilePath, 
                this.infoPlist.getExecutableName(), this.projectDirectoryPath);
            FileProcessing.openProject(this.currentFilePath, this.projectDirectoryPath, this.infoPlist.getExecutableName());
            //runGhidraCommand();
    
            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(this.fileTree);
        } catch (IOException e) {
            e.printStackTrace();
        }
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
