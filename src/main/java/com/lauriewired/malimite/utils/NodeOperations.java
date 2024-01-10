package com.lauriewired.malimite.utils;

import java.util.Enumeration;

import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;

public class NodeOperations {

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
}
