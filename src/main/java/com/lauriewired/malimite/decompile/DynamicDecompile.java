package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.ui.AnalysisWindow;
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
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import javax.swing.BorderFactory;
import javax.swing.SwingUtilities;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import java.awt.BorderLayout;
import java.util.logging.Level;
import javax.swing.SwingWorker;

public class DynamicDecompile {
    private static final Logger LOGGER = Logger.getLogger(DynamicDecompile.class.getName());

    public static void decompileFile(String filePath, String projectDirectoryPath, String fullFilePath, Config config, 
            SQLiteDBHandler dbHandler, String infoPlistExecutableName, DefaultTreeModel treeModel, JTree fileTree) {
                
        // Create and configure progress dialog
        JDialog progressDialog = new JDialog((JFrame)SwingUtilities.getWindowAncestor(fileTree), "Analyzing File", false);
        progressDialog.setAlwaysOnTop(true);
        progressDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Add progress components
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        JLabel statusLabel = new JLabel("Analyzing file...");
        
        // Add console output area
        JTextArea consoleOutput = new JTextArea(10, 50);
        consoleOutput.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(consoleOutput);
        
        // Add components to panel
        panel.add(statusLabel, BorderLayout.NORTH);
        panel.add(progressBar, BorderLayout.CENTER);
        panel.add(scrollPane, BorderLayout.SOUTH);
        
        progressDialog.add(panel);
        progressDialog.pack();
        progressDialog.setLocationRelativeTo(fileTree);

        // Create SwingWorker for background processing
        SwingWorker<Void, String> worker = new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                try {
                    publish("Starting analysis of: " + fullFilePath);
                    LOGGER.info("Decompiling: " + fullFilePath);
                    
                    File file = new File(fullFilePath);
                    String fileName = file.getName();
                    
                    publish("Opening project...");
                    FileProcessing.openProject(
                        filePath,
                        projectDirectoryPath, 
                        fileName,
                        config.getConfigDirectory(),
                        true
                    );

                    String extractedMachoPath = projectDirectoryPath + File.separator + fileName;
                    publish("Creating Macho object...");
                    Macho targetMacho = new Macho(extractedMachoPath, projectDirectoryPath, fileName);

                    publish("Starting Ghidra analysis...");
                    GhidraProject ghidraProject = new GhidraProject(
                        infoPlistExecutableName, 
                        extractedMachoPath, 
                        config, 
                        dbHandler,
                        // Pass console output callback
                        message -> publish(message)
                    );
                    
                    ghidraProject.decompileMacho(extractedMachoPath, projectDirectoryPath, targetMacho, true);
                    
                    return null;
                } catch (Exception e) {
                    publish("Error: " + e.getMessage());
                    throw e;
                }
            }

            @Override
            protected void process(List<String> chunks) {
                // Update console with new messages
                for (String message : chunks) {
                    consoleOutput.append(message + "\n");
                    consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
                }
            }

            @Override
            protected void done() {
                try {
                    get(); // Check for exceptions
                    
                    // Update tree on success
                    SwingUtilities.invokeLater(() -> {
                        DefaultMutableTreeNode decompiledNode = addDecompiledNode(treeModel);
                        populateDecompiledNode(decompiledNode, dbHandler, infoPlistExecutableName);
                        AnalysisWindow.populateMachoStringsPanel();

                        // Expand nodes
                        TreePath decompiledPath = new TreePath(decompiledNode.getPath());
                        fileTree.expandPath(decompiledPath);
                        Enumeration<?> decompiledChildren = decompiledNode.children();
                        while (decompiledChildren.hasMoreElements()) {
                            DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) decompiledChildren.nextElement();
                            TreePath childPath = new TreePath(childNode.getPath());
                            fileTree.expandPath(childPath);
                        }
                    });
                    
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error during decompilation", e);
                    JOptionPane.showMessageDialog(progressDialog,
                        "Error during decompilation: " + e.getMessage(),
                        "Decompilation Error",
                        JOptionPane.ERROR_MESSAGE);
                } finally {
                    progressDialog.dispose();
                }
            }
        };

        // Start the worker and show dialog
        worker.execute();
        progressDialog.setVisible(true);
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
