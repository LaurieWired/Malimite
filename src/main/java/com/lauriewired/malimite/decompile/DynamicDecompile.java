package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.utils.FileProcessing;
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.util.HashMap;
import java.util.Enumeration;
import javax.swing.JTree;
import javax.swing.tree.TreePath;

public class DynamicDecompile {
    private static final Logger LOGGER = Logger.getLogger(DynamicDecompile.class.getName());

    public static void decompileFile(String filePath, String projectDirectoryPath, String fullFilePath, Config config, 
            SQLiteDBHandler dbHandler, String infoPlistExecutableName, DefaultTreeModel treeModel, JTree fileTree) {
                
        LOGGER.info("Decompiling: " + fullFilePath);
        
        // Get the file name from the path
        File file = new File(fullFilePath);
        String fileName = file.getName();
        
        // Call openProject with the necessary parameters
        FileProcessing.openProject(
            filePath,           // Original file path
            projectDirectoryPath, // Project directory path
            fileName,           // Executable name (using file name)
            config.getConfigDirectory(),          // Config directory
            true
        );

        String extractedMachoPath = projectDirectoryPath + File.separator + fileName;

        Macho targetMacho = new Macho(extractedMachoPath, projectDirectoryPath, fileName);

        GhidraProject ghidraProject = new GhidraProject(infoPlistExecutableName, extractedMachoPath, config, dbHandler, null);
        ghidraProject.decompileMacho(extractedMachoPath, projectDirectoryPath, targetMacho, true);

        // Add and populate the "Decompiled" node
        DefaultMutableTreeNode decompiledNode = addDecompiledNode(treeModel);
        populateDecompiledNode(decompiledNode, dbHandler, infoPlistExecutableName);

        // Expand the "Decompiled" node two levels deep
        TreePath decompiledPath = new TreePath(decompiledNode.getPath());
        fileTree.expandPath(decompiledPath);
        Enumeration<?> decompiledChildren = decompiledNode.children();
        while (decompiledChildren.hasMoreElements()) {
            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) decompiledChildren.nextElement();
            TreePath childPath = new TreePath(childNode.getPath());
            fileTree.expandPath(childPath);
        }
    }

    private static DefaultMutableTreeNode addDecompiledNode(DefaultTreeModel treeModel) {
        // Get the invisible root node
        DefaultMutableTreeNode rootNode = (DefaultMutableTreeNode) treeModel.getRoot();
        
        // Check if the "Decompiled" node already exists
        Enumeration<?> children = rootNode.children();
        while (children.hasMoreElements()) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) children.nextElement();
            if ("Decompiled".equals(child.getUserObject().toString())) {
                return child; // Return the existing "Decompiled" node
            }
        }
        
        // If not found, create a new "Decompiled" node
        DefaultMutableTreeNode decompiledNode = new DefaultMutableTreeNode("Decompiled");
        rootNode.add(decompiledNode);
        treeModel.reload(rootNode);
        return decompiledNode;
    }

    private static void populateDecompiledNode(DefaultMutableTreeNode decompiledNode, SQLiteDBHandler dbHandler, String infoPlistExecutableName) {
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
        Map<String, DefaultMutableTreeNode> executableNodes = new HashMap<>();
        
        for (Map.Entry<String, List<String>> entry : classesAndFunctions.entrySet()) {
            String className = entry.getKey();
            List<String> functions = entry.getValue();
            
            // Retrieve the executable name for the current class
            String executableName = dbHandler.getExecutableNameForClass(className);
            
            // Check if the class belongs to the specified executable
            if (!infoPlistExecutableName.equals(executableName)) {
                // Get or create the node for this executable
                DefaultMutableTreeNode executableNode = executableNodes.computeIfAbsent(executableName, k -> {
                    DefaultMutableTreeNode node = new DefaultMutableTreeNode(executableName);
                    decompiledNode.add(node);
                    return node;
                });
                
                // Create a node for the class
                DefaultMutableTreeNode classNode = new DefaultMutableTreeNode(className);
                
                // Add function nodes under the class node
                for (String function : functions) {
                    classNode.add(new DefaultMutableTreeNode(function));
                }
                
                // Add the class node under the executable node
                executableNode.add(classNode);
            }
        }
    }

    public static void repopulateDecompiledNode(DefaultTreeModel treeModel, SQLiteDBHandler dbHandler, String infoPlistExecutableName) {
        DefaultMutableTreeNode decompiledNode = addDecompiledNode(treeModel);
        decompiledNode.removeAllChildren(); // Clear existing children before repopulating
        populateDecompiledNode(decompiledNode, dbHandler, infoPlistExecutableName);

        // Only add the "Decompiled" node if it has children
        if (decompiledNode.getChildCount() > 0) {
            treeModel.reload(decompiledNode);
        } else {
            // Remove the "Decompiled" node if it has no children
            ((DefaultMutableTreeNode) treeModel.getRoot()).remove(decompiledNode);
            treeModel.reload();
        }
    }
}
