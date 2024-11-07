package com.lauriewired.malimite.utils;

import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

public class NodeOperations {
    private static final Logger LOGGER = Logger.getLogger(NodeOperations.class.getName());

    public static String buildFullPathFromNode(TreeNode node) {
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

    public static void collapseAllTreeNodes(JTree fileTree) {
        for (int i = 0; i < fileTree.getRowCount(); i++) {
            fileTree.collapseRow(i);
        }
    }

    public static DefaultMutableTreeNode addOrGetNode(DefaultMutableTreeNode parentNode, String nodeName, boolean isDirectory) {
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

    public static void expandAllTreeNodes(JTree fileTree) {
        for (int i = 0; i < fileTree.getRowCount(); i++) {
            fileTree.expandRow(i);
        }
    }

    public static DefaultMutableTreeNode findInfoPlistNode(DefaultMutableTreeNode root) {
        // Find the Files node first
        for (int i = 0; i < root.getChildCount(); i++) {
            DefaultMutableTreeNode filesNode = (DefaultMutableTreeNode) root.getChildAt(i);
            
            if (filesNode.getUserObject().toString().equals("Files")) {
                // Look for the .app directory directly under Files
                for (int j = 0; j < filesNode.getChildCount(); j++) {
                    DefaultMutableTreeNode appNode = (DefaultMutableTreeNode) filesNode.getChildAt(j);
                    if (appNode.getUserObject().toString().endsWith(".app/")) {
                        // Look for Info.plist directly under the .app directory
                        for (int k = 0; k < appNode.getChildCount(); k++) {
                            DefaultMutableTreeNode child = (DefaultMutableTreeNode) appNode.getChildAt(k);
                            if (child.getUserObject().toString().equals("Info.plist")) {
                                return child;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static void populateClassesNode(DefaultMutableTreeNode classesRootNode, 
            Map<String, List<String>> classesAndFunctions) {
        LOGGER.info("Populating classes tree...");
        classesRootNode.removeAllChildren();
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
}
