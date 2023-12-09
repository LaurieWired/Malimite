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

import com.dd.plist.*;

public class iPax extends JFrame {

    private JLabel fileNameLabel;
    private JTextArea fileContentArea;
    private DefaultTreeModel treeModel;
    private JTree fileTree;
    private Map<String, String> fileEntriesMap;
    private String currentFilePath; // Path to the file being analyzed

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
    
            while (entry != null) {
                if (entry.getName().endsWith(".app/")) {
                    appNode = new DefaultMutableTreeNode(entry.getName());
                    filesRootNode.add(appNode);
                } else if (appNode != null && entry.getName().startsWith(appNode.toString())) {
                    String relativePath = entry.getName().substring(appNode.toString().length());
                    DefaultMutableTreeNode currentNode;
    
                    if (relativePath.equals("Info.plist")) {
                        // Directly add Info.plist as a child of the appNode
                        currentNode = new DefaultMutableTreeNode("Info.plist");
                        appNode.add(currentNode);

                        fileEntriesMap.put(buildFullPathFromNode(currentNode), entry.getName());

                        //TODO: add call to find macho entrypoint based on Info.plist -> CFBundleExecutable tag
                        //also need to add error checking for invalid ones
                    } else {
                        // Create or get the "Resources" node and add other files to it
                        currentNode = addOrGetNode(appNode, "Resources", true);
    
                        // Skip the first part of the path if it's a directory
                        String[] pathParts = relativePath.split("/");
                        for (int i = (entry.isDirectory() ? 1 : 0); i < pathParts.length; i++) {
                            boolean isDirectory = i < pathParts.length - 1 || entry.isDirectory();
                            currentNode = addOrGetNode(currentNode, pathParts[i], isDirectory);
    
                            if (!isDirectory) {
                                // Store only the file's relative path in the zip file
                                fileEntriesMap.put(buildFullPathFromNode(currentNode), entry.getName());

                                //System.out.println("Entry key: " + buildFullPathFromNode(currentNode));
                                //System.out.println("Entry entry.getName(): " + entry.getName());
                            }
                        }
                    }
                }
    
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
    
            treeModel.reload();
            for (int i = 0; i < fileTree.getRowCount(); i++) {
                fileTree.collapseRow(i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String buildFullPathFromNode(TreeNode node) {
        StringBuilder fullPath = new StringBuilder();
        String nodeString = "";
        
        while (node != null) {
            nodeString = node.toString();

            // Avoid adding the prepended "Files" node
            if (node.getParent() != null && nodeString != "Hidden") {
                //System.out.println("fullPath: " + fullPath.toString());
                //System.out.println("node: " + nodeString);

                // Insert slash into path only if needed
                if (fullPath.length() > 0 && fullPath.charAt(0) != '/' && nodeString.charAt(nodeString.length() - 1) != '/') {
                    fullPath.insert(0, "/");
                }
                fullPath.insert(0, nodeString);
            }

            node = node.getParent();
        }
        return fullPath.toString();
    }    

    private String readContentFromZip(String zipFilePath, String entryPath) throws IOException {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
    
            while (entry != null) {
                if (entry.getName().equals(entryPath)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024]; //TODO: remove magic number and add caching for open files
                    int len;
                    while ((len = zipIn.read(buffer)) > 0) {
                        out.write(buffer, 0, len);
                    }
                    return new String(out.toByteArray());
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
        return ""; // Return empty string if the entry is not found
    }

    private DefaultMutableTreeNode addOrGetNode(DefaultMutableTreeNode parentNode, String nodeName, boolean isDirectory) {
        Enumeration<TreeNode> children = parentNode.children();
        while (children.hasMoreElements()) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) children.nextElement();
            if (childNode.getUserObject().equals(nodeName) && childNode.getAllowsChildren() == isDirectory) {
                return childNode;
            }
        }
    
        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(nodeName, isDirectory);
        parentNode.add(newNode);
        return newNode;
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
                String contentText = readContentFromZip(currentFilePath, fileEntriesMap.get(fullPath.toString()));

                // Decode if it's a binary plist. Otherwise, just print the text
                /*
                if (fullPath.toString().endsWith("plist") && isBinaryPlist(contentBytes)) {
                    System.out.println("Handling binary property list");
                    contentText = decodePropertyList(contentBytes);
                }*/

                fileContentArea.setText(contentText);
                fileContentArea.setCaretPosition(0);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private String decodePropertyList(byte[] plistData) {
        try {
            NSObject plist = PropertyListParser.parse(plistData);
    
            // Convert property list to a JSON-like string
            return plist.toJavaObject().toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean isBinaryPlist(byte[] contentBytes) {
        String header = new String(Arrays.copyOf(contentBytes, "bplist".length()));
        return header.equals("bplist");
    }    
}
