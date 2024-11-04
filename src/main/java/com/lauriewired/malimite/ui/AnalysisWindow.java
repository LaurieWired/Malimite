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
import java.awt.event.MouseEvent;

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
import com.lauriewired.malimite.tools.AIBackend;
import com.lauriewired.malimite.tools.AIBackend.Model;
import java.util.Arrays;

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

    private static JSplitPane mainSplitPane;
    private static JPanel functionAssistPanel;
    private static boolean functionAssistVisible = false;
    private static JLabel bundleIdValue;
    private static JLabel closeLabel;

    private static JButton saveButton;
    private static boolean isEditing = false;

    private static JProgressBar processingBar;
    private static JLabel processingLabel;
    private static JPanel statusPanel;

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
    
        JScrollPane infoScrollPane = new JScrollPane(infoDisplay);
        infoScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
    
        JPanel leftPanel = new JPanel(new BorderLayout());
    
        JPanel treePanel = new JPanel(new BorderLayout());
        treePanel.add(fileNameLabel, BorderLayout.NORTH);
        treePanel.add(treeScrollPane, BorderLayout.CENTER);
    
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, treePanel, infoScrollPane);
        leftSplitPane.setResizeWeight(0.7);
    
        leftPanel.add(leftSplitPane, BorderLayout.CENTER);
    
        // Initialize bundleIdValue as a class-level variable
        bundleIdValue = new JLabel("Loading...", SwingConstants.CENTER);
        bundleIdValue.setFont(bundleIdValue.getFont().deriveFont(Font.BOLD));
    
        JPanel bundleIdPanel = new JPanel(new BorderLayout());
        bundleIdPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        bundleIdPanel.add(bundleIdValue, BorderLayout.CENTER);
    
        // Create right panel to hold bundle ID and content
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(bundleIdPanel, BorderLayout.NORTH);
        rightPanel.add(contentScrollPane, BorderLayout.CENTER);
    
        // Create function assist panel with close label
        functionAssistPanel = new JPanel(new BorderLayout());
        functionAssistPanel.setPreferredSize(new Dimension(300, 0));
        functionAssistPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Create header panel to hold both label and close label
        JPanel headerPanel = new JPanel(new BorderLayout());
        JLabel assistLabel = new JLabel("Function Assist", SwingConstants.CENTER);
        assistLabel.setFont(assistLabel.getFont().deriveFont(Font.BOLD));
        assistLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        // Create close label
        closeLabel = new JLabel("✕");  // Using "✕" as the close symbol
        closeLabel.setFont(closeLabel.getFont().deriveFont(14.0f));
        closeLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 10, 5));
        closeLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        closeLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                toggleFunctionAssist();
            }
        });
        
        headerPanel.add(assistLabel, BorderLayout.CENTER);
        headerPanel.add(closeLabel, BorderLayout.EAST);
        functionAssistPanel.add(headerPanel, BorderLayout.NORTH);

        // Add function selection panel
        JPanel selectionPanel = new JPanel(new BorderLayout());
        DefaultListModel<String> functionListModel = new DefaultListModel<>();
        JList<String> functionList = new JList<>(functionListModel);
        functionList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // Add "Select All" checkbox
        JCheckBox selectAllBox = new JCheckBox("Select All");
        selectAllBox.addActionListener(e -> {
            if (selectAllBox.isSelected()) {
                functionList.setSelectionInterval(0, functionListModel.getSize() - 1);
            } else {
                functionList.clearSelection();
            }
        });

        // Add scroll pane for function list
        JScrollPane listScrollPane = new JScrollPane(functionList);
        
        selectionPanel.add(selectAllBox, BorderLayout.NORTH);
        selectionPanel.add(listScrollPane, BorderLayout.CENTER);
        
        // Create model selector
        Model[] models = AIBackend.getSupportedModels();
        String[] modelNames = Arrays.stream(models)
            .map(Model::getDisplayName)
            .toArray(String[]::new);
        JComboBox<String> modelSelector = new JComboBox<>(modelNames);
        
        // Update bottom panel to include both clean button and model selector
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        JPanel modelPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modelPanel.add(new JLabel("Model:"));
        modelPanel.add(modelSelector);
        
        // Add this before creating the buttonPanel
        JButton cleanButton = new JButton("Auto Fix");
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(cleanButton);
        
        bottomPanel.add(modelPanel, BorderLayout.WEST);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);
        
        // Update clean button action listener
        cleanButton.addActionListener(e -> {
            String selectedDisplayName = modelSelector.getSelectedItem().toString();
            Model selectedModel = Arrays.stream(AIBackend.getSupportedModels())
                .filter(m -> m.getDisplayName().equals(selectedDisplayName))
                .findFirst()
                .orElse(AIBackend.getDefaultModel());
            
            // Get selected functions from the list
            List<String> selectedFunctions = ((JList<String>) listScrollPane.getViewport().getView()).getSelectedValuesList();
            
            if (selectedFunctions.isEmpty()) {
                JOptionPane.showMessageDialog(analysisFrame,
                    "Please select at least one function to process.",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }

            // Get the parent class name from the tree selection
            TreePath path = fileTree.getSelectionPath();
            if (path == null) {
                JOptionPane.showMessageDialog(analysisFrame,
                    "Please select a class in the tree view.",
                    "No Class Selected",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            DefaultMutableTreeNode classNode = (DefaultMutableTreeNode) path.getPathComponent(2);
            String className = classNode.getUserObject().toString();

            // Build the complete prompt
            StringBuilder fullPrompt = new StringBuilder(AIBackend.getDefaultPrompt());
            fullPrompt.append("\n\nHere are the functions to translate:\n\n");
            
            for (String functionName : selectedFunctions) {
                String decompilation = dbHandler.getFunctionDecompilation(functionName, className);
                if (decompilation != null && !decompilation.isEmpty()) {
                    fullPrompt.append("// Function: ").append(functionName).append("\n");
                    fullPrompt.append(decompilation).append("\n\n");
                }
            }

            // Create confirmation message
            String confirmMessage = String.format(
                "<html>Sending %d function%s to %s for translation:<br><br>%s</html>",
                selectedFunctions.size(),
                selectedFunctions.size() == 1 ? "" : "s",
                selectedModel.getDisplayName(),
                String.join(", ", selectedFunctions)
            );

            // Create custom dialog with two buttons
            Object[] options = {"Confirm", "Edit Prompt"};
            int choice = JOptionPane.showOptionDialog(
                analysisFrame,
                confirmMessage,
                "Confirm Translation",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]
            );

            if (choice == 0) { // Confirm was clicked
                sendPromptToAI(selectedModel, fullPrompt.toString());
            } else if (choice == 1) { // Edit Prompt was clicked
                showPromptEditor(selectedModel, fullPrompt.toString());
            }
        });

        selectionPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        functionAssistPanel.add(selectionPanel, BorderLayout.CENTER);

        // Add the same click listener to the label for consistency
        assistLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        assistLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                toggleFunctionAssist();
            }
        });

        functionAssistPanel.setVisible(false); // Start with the panel hidden

        // Add functionAssistPanel to the right of rightPanel using a split pane
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, rightPanel, functionAssistPanel);
        rightSplitPane.setDividerLocation(1.0);
        rightSplitPane.setResizeWeight(1.0);
    
        // Combine left and right panels
        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightSplitPane);
        mainSplitPane.setDividerLocation(300);
    
        updateFileInfo(new File(currentFilePath), infoDisplay);
    
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(mainSplitPane, BorderLayout.CENTER);

        toggleFunctionAssist(); // Change my mind. Want to show it by default and this is the easiest way to do it

        // Add save button (initially invisible)
        saveButton = new JButton("Save Changes");
        saveButton.setVisible(false);
        saveButton.addActionListener(e -> saveCurrentFunction());
        
        // Add save button to the right panel, above the content
        JPanel rightTopPanel = new JPanel(new BorderLayout());
        rightTopPanel.add(bundleIdPanel, BorderLayout.CENTER);
        rightTopPanel.add(saveButton, BorderLayout.EAST);
        rightPanel.add(rightTopPanel, BorderLayout.NORTH);

        // Add context menu to the tree
        fileTree.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }
        
            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }
        
            private void maybeShowPopup(MouseEvent e) {
                // Check for right-click or equivalent on all OSes
                if (e.isPopupTrigger() || e.getButton() == MouseEvent.BUTTON3) {
                    TreePath path = fileTree.getPathForLocation(e.getX(), e.getY());
                    if (path != null && isInClassesTree(path) && path.getPathCount() == 4) {
                        // Show context menu for function nodes only
                        JPopupMenu popup = new JPopupMenu();
                        JMenuItem editItem = new JMenuItem("Edit function");
                        editItem.addActionListener(ev -> startEditing(path));
                        popup.add(editItem);
                        popup.show(fileTree, e.getX(), e.getY());
                    }
                }
            }
        });        

        // Add status panel at the bottom
        statusPanel = new JPanel(new BorderLayout());
        processingBar = new JProgressBar();
        processingBar.setIndeterminate(true);
        processingLabel = new JLabel("Processing classes...");
        processingLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        
        statusPanel.add(processingLabel, BorderLayout.WEST);
        statusPanel.add(processingBar, BorderLayout.CENTER);
        statusPanel.setVisible(false);
        
        contentPanel.add(statusPanel, BorderLayout.SOUTH);

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
        
        // Start file processing
        LOGGER.info("Beginning file unzip and analysis process");
        unzipAndLoadToTree(file, filesRootNode, classesRootNode);

        // Start Ghidra analysis in background
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                SwingUtilities.invokeLater(() -> {
                    statusPanel.setVisible(true);
                    processingLabel.setText("Analyzing executable with Ghidra...");
                });
                
                initializeProject();
                
                SwingUtilities.invokeLater(() -> {
                    populateClassesNode(classesRootNode);
                    statusPanel.setVisible(false);
                    treeModel.reload();
                    
                    // Move Info.plist selection here, after tree reload
                    DefaultMutableTreeNode plistNode = findInfoPlistNode(filesRootNode);
                    if (plistNode != null) {
                        TreePath path = new TreePath(plistNode.getPath());
                        // Expand all parent nodes
                        TreePath parentPath = path.getParentPath();
                        while (parentPath != null) {
                            fileTree.expandPath(parentPath);
                            parentPath = parentPath.getParentPath();
                        }
                        // Select and scroll to the Info.plist node
                        fileTree.setSelectionPath(path);
                        fileTree.scrollPathToVisible(path);
                    }
                });
                
                return null;
            }
            
            @Override
            protected void done() {
                try {
                    get(); // Check for exceptions
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error during Ghidra analysis", e);
                    SwingUtilities.invokeLater(() -> {
                        statusPanel.setVisible(false);
                        JOptionPane.showMessageDialog(analysisFrame,
                            "Error during analysis: " + e.getMessage(),
                            "Analysis Error",
                            JOptionPane.ERROR_MESSAGE);
                    });
                }
            }
        };
        
        worker.execute();
    }

    private static DefaultMutableTreeNode findInfoPlistNode(DefaultMutableTreeNode root) {
        for (int i = 0; i < root.getChildCount(); i++) {
            DefaultMutableTreeNode appNode = (DefaultMutableTreeNode) root.getChildAt(i);
            for (int j = 0; j < appNode.getChildCount(); j++) {
                DefaultMutableTreeNode child = (DefaultMutableTreeNode) appNode.getChildAt(j);
                if (child.getUserObject().toString().equals("Info.plist")) {
                    return child;
                }
            }
        }
        return null;
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
        
        // Create and show processing dialog
        JDialog processingDialog = new JDialog(analysisFrame, "Processing", true);
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create top panel for progress bar and status
        JPanel topPanel = new JPanel(new BorderLayout(10, 10));
        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        topPanel.add(progressBar, BorderLayout.CENTER);
        
        JLabel statusLabel = new JLabel("Initializing Ghidra analysis...");
        topPanel.add(statusLabel, BorderLayout.SOUTH);
        
        // Create console output components
        JTextArea consoleOutput = new JTextArea();
        consoleOutput.setEditable(false);
        consoleOutput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane consoleScrollPane = new JScrollPane(consoleOutput);
        consoleScrollPane.setPreferredSize(new Dimension(600, 200));
        
        // Create toggle button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JToggleButton toggleConsoleButton = new JToggleButton("Show Processing Output");
        buttonPanel.add(toggleConsoleButton);
        
        // Add components to main panel
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(buttonPanel, BorderLayout.CENTER);
        
        // Initially hide console
        consoleScrollPane.setVisible(false);
        
        // Toggle console visibility
        toggleConsoleButton.addActionListener(e -> {
            consoleScrollPane.setVisible(toggleConsoleButton.isSelected());
            processingDialog.pack();
            processingDialog.setLocationRelativeTo(analysisFrame);
        });
        
        mainPanel.add(consoleScrollPane, BorderLayout.SOUTH);
        processingDialog.add(mainPanel);
        processingDialog.pack();
        processingDialog.setLocationRelativeTo(analysisFrame);
        
        // Create a SwingWorker to handle the background processing
        SwingWorker<Void, String> worker = new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() throws Exception {
                publish("Extracting Mach-O file...");
                projectDirectoryPath = FileProcessing.extractMachoToProjectDirectory(currentFilePath, 
                    infoPlist.getExecutableName(), config.getConfigDirectory());
                LOGGER.info("Project directory created at: " + projectDirectoryPath);

                publish("Opening project...");
                FileProcessing.openProject(currentFilePath, projectDirectoryPath, 
                    infoPlist.getExecutableName(), config.getConfigDirectory());

                executableFilePath = projectDirectoryPath + File.separator + infoPlist.getExecutableName();
                LOGGER.info("Loading Mach-O file: " + executableFilePath);
                
                publish("Loading Mach-O file...");
                projectMacho = new Macho(executableFilePath, projectDirectoryPath, infoPlist.getExecutableName());

                String dbFilePath = projectDirectoryPath + File.separator + 
                    projectMacho.getMachoExecutableName() + "_malimite.db";
                LOGGER.info("Checking for database at: " + dbFilePath);

                File dbFile = new File(dbFilePath);
                if (!dbFile.exists()) {
                    publish("Creating new database...");
                    dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                        projectMacho.getMachoExecutableName() + "_malimite.db");

                    publish("Starting Ghidra analysis...");
                    ghidraProject = new GhidraProject(infoPlist.getExecutableName(), 
                        executableFilePath, config, dbHandler, 
                        // Add console output callback
                        message -> SwingUtilities.invokeLater(() -> {
                            consoleOutput.append(message + "\n");
                            consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
                        }));
                
                    if (projectMacho.isUniversalBinary()) {
                        processingDialog.setVisible(false);  // Hide dialog for architecture selection
                        List<String> architectures = projectMacho.getArchitectureStrings();
                        String selectedArchitecture = selectArchitecture(architectures);
                        processingDialog.setVisible(true);  // Show dialog again
                        if (selectedArchitecture != null) {
                            publish("Processing " + selectedArchitecture + " architecture...");
                            projectMacho.processUniversalMacho(selectedArchitecture);
                        }
                    }
                    projectMacho.printArchitectures();
                    publish("Decompiling with Ghidra...");
                    ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, projectMacho);
                } else {
                    publish("Loading existing database...");
                    dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                        projectMacho.getMachoExecutableName() + "_malimite.db");
                }
                return null;
            }
            
            @Override
            protected void process(List<String> chunks) {
                if (!chunks.isEmpty()) {
                    String message = chunks.get(chunks.size() - 1);
                    statusLabel.setText(message);
                    consoleOutput.append(message + "\n");
                    consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
                }
            }
            
            @Override
            protected void done() {
                processingDialog.dispose();
                try {
                    get();
                    if (analysisFrame != null) {
                        SwingUtilities.invokeLater(() -> {
                            analysisFrame.toFront();
                            analysisFrame.requestFocus();
                            if (analysisFrame.getExtendedState() == Frame.ICONIFIED) {
                                analysisFrame.setExtendedState(Frame.NORMAL);
                            }
                            analysisFrame.setAlwaysOnTop(true);
                            analysisFrame.setAlwaysOnTop(false);
                        });
                    }
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error during project initialization", e);
                    JOptionPane.showMessageDialog(analysisFrame,
                        "Error during initialization: " + e.getMessage(),
                        "Initialization Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        worker.execute();
        processingDialog.setVisible(true);
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
        // Don't change content if we're currently editing
        if (isEditing) {
            return;
        }

        TreePath path = e.getPath();
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
    
        // Check if we're in the Classes root
        if (isInClassesTree(path)) {
            fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
            
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
                String functionName = node.getUserObject().toString();
                displayFunctionDecompilation(functionName, className);
                return;
            }
        }

        // Build the full path
        StringBuilder fullPath = new StringBuilder();
        for (int i = 1; i < path.getPathCount(); i++) {
            if (fullPath.length() > 0 && fullPath.charAt(fullPath.length() - 1) != '/') {
                fullPath.append("/");
            }
            fullPath.append(((DefaultMutableTreeNode) path.getPathComponent(i)).getUserObject().toString());
        }

        // Only proceed if this path exists in our fileEntriesMap (meaning it's a file, not a directory)
        String entryPath = fileEntriesMap.get(fullPath.toString());
        if (entryPath == null) {
            return; // Exit if this is a directory or non-existent path
        }

        if (currentFilePath != null) {
            try {
                byte[] contentBytes = FileProcessing.readContentFromZip(currentFilePath, entryPath);
                String contentText;
        
                // Set appropriate syntax style based on file type
                if (fullPath.toString().endsWith("plist")) {
                    fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                    if (PlistUtils.isBinaryPlist(contentBytes)) {
                        contentText = PlistUtils.decodeBinaryPropertyList(contentBytes);
                    } else {
                        contentText = new String(contentBytes);
                    }
                } else {
                    // Reset to default C syntax for other files
                    fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
                    contentText = new String(contentBytes);
                }
        
                fileContentArea.setText(contentText);
                fileContentArea.setCaretPosition(0);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private static void displayClassDecompilation(String className) {
        try {
            // Update the function list in the function assist panel
            updateFunctionList(className);
            
            // Get all functions for this class from the map we already have
            Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
            List<String> functions = classesAndFunctions.get(className);
            
            if (functions == null || functions.isEmpty()) {
                fileContentArea.setText("No functions found for " + className);
                return;
            }

            // Build the complete decompilation by combining all function decompilations
            StringBuilder fullDecompilation = new StringBuilder();
            fullDecompilation.append("// Class: ").append(className).append("\n\n");

            for (String functionName : functions) {
                String functionDecompilation = dbHandler.getFunctionDecompilation(functionName, className);
                if (functionDecompilation != null && !functionDecompilation.isEmpty()) {
                    fullDecompilation.append("// Function: ").append(functionName).append("\n");
                    fullDecompilation.append(functionDecompilation).append("\n\n");
                }
            }

            if (fullDecompilation.length() > 0) {
                fileContentArea.setText(fullDecompilation.toString());
                fileContentArea.setCaretPosition(0);
            } else {
                fileContentArea.setText("No decompilation available for " + className);
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error displaying decompilation for " + className, ex);
            fileContentArea.setText("Error loading decompilation for " + className);
        }
    }

    private static void displayFunctionDecompilation(String functionName, String className) {
        try {
            // Update the function list in the function assist panel
            updateFunctionList(className);
            
            String functionDecompilation = dbHandler.getFunctionDecompilation(functionName, className);
            if (functionDecompilation != null && !functionDecompilation.isEmpty()) {
                StringBuilder content = new StringBuilder();
                content.append("// Class: ").append(className).append("\n");
                content.append("// Function: ").append(functionName).append("\n\n");
                content.append(functionDecompilation);
                
                fileContentArea.setText(content.toString());
                fileContentArea.setCaretPosition(0);
            } else {
                fileContentArea.setText("No decompilation available for function " + functionName);
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error displaying decompilation for " + functionName, ex);
            fileContentArea.setText("Error loading decompilation for " + functionName);
        }
    }

    public static void safeMenuAction(Runnable action) {
        SafeMenuAction.execute(action);
    }

    private static void updateBundleIdDisplay(String bundleId) {
        System.out.println("Updating bundle ID display to: " + bundleId);
        SwingUtilities.invokeLater(() -> {
            if (bundleIdValue != null) {
                bundleIdValue.setText(bundleId != null ? bundleId : "N/A");
            }
        });
    }    

    public static void toggleFunctionAssist() {
        if (functionAssistPanel != null && mainSplitPane != null) {
            functionAssistVisible = !functionAssistVisible;
            functionAssistPanel.setVisible(functionAssistVisible);
            closeLabel.setVisible(functionAssistVisible);  // Only show X when panel is visible

            // Adjust the rightSplitPane divider location based on visibility
            JSplitPane rightSplitPane = (JSplitPane) mainSplitPane.getRightComponent();

            if (functionAssistVisible) {
                rightSplitPane.setDividerLocation(rightSplitPane.getWidth() - functionAssistPanel.getPreferredSize().width);
            } else {
                rightSplitPane.setDividerLocation(1.0);
            }

            mainSplitPane.revalidate();
            mainSplitPane.repaint();
        } else {
            System.out.println("Error: functionAssistPanel or mainSplitPane is null");
        }
    }

    // Add this method to update the function list when a class is selected
    private static void updateFunctionList(String className) {
        if (functionAssistPanel != null) {
            JList<?> functionList = (JList<?>) ((JScrollPane) ((JPanel) functionAssistPanel
                .getComponent(1)).getComponent(1)).getViewport().getView();
            DefaultListModel<String> model = (DefaultListModel<String>) functionList.getModel();
            model.clear();
            
            // Get functions for the selected class
            Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
            List<String> functions = classesAndFunctions.get(className);
            
            if (functions != null) {
                for (String function : functions) {
                    model.addElement(function);
                }
            }
            
            // Reset "Select All" checkbox
            JCheckBox selectAllBox = (JCheckBox) ((JPanel) functionAssistPanel
                .getComponent(1)).getComponent(0);
            selectAllBox.setSelected(false);
        }
    }

    private static void sendPromptToAI(Model selectedModel, String prompt) {
        // Create a loading dialog
        JDialog loadingDialog = new JDialog(analysisFrame, "Processing", true);
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Add a spinner
        JProgressBar spinner = new JProgressBar();
        spinner.setIndeterminate(true);
        panel.add(spinner, BorderLayout.CENTER);
        
        // Add a status label
        JLabel statusLabel = new JLabel("Sending request to " + selectedModel.getDisplayName() + "...");
        panel.add(statusLabel, BorderLayout.SOUTH);
        
        loadingDialog.add(panel);
        loadingDialog.pack();
        loadingDialog.setLocationRelativeTo(analysisFrame);
        
        // Run the AI request in a background thread
        SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                try {
                    return AIBackend.sendToModel(
                        selectedModel.getProvider(), 
                        selectedModel.getModelId(), 
                        prompt, 
                        config
                    );
                } catch (IOException ex) {
                    throw ex;
                }
            }
            
            @Override
            protected void done() {
                loadingDialog.dispose();
                try {
                    String aiResponse = get();
                    if (aiResponse != null) {
                        showFunctionAcceptanceDialog(aiResponse);
                    } else {
                        JOptionPane.showMessageDialog(analysisFrame, 
                            "Failed to retrieve response from AI model.", 
                            "Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(analysisFrame, 
                        "Error connecting to AI model: " + ex.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        // Start the background task and show the loading dialog
        worker.execute();
        loadingDialog.setVisible(true);
    }

    private static void showPromptEditor(Model selectedModel, String prompt) {
        // Create an editable text area for the prompt
        JTextArea promptArea = new JTextArea(prompt);
        promptArea.setRows(10);
        promptArea.setColumns(50);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        
        // Create a scroll pane for the text area
        JScrollPane scrollPane = new JScrollPane(promptArea);
        
        // Create a panel with a descriptive label
        JPanel promptPanel = new JPanel(new BorderLayout());
        promptPanel.add(new JLabel("Edit prompt before sending:"), BorderLayout.NORTH);
        promptPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Show prompt editor
        int confirm = JOptionPane.showConfirmDialog(analysisFrame,
            promptPanel,
            "Edit and Confirm Prompt",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);
            
        if (confirm == JOptionPane.OK_OPTION) {
            sendPromptToAI(selectedModel, promptArea.getText());
        }
    }

    private static void showFunctionAcceptanceDialog(String aiResponse) {
        System.out.println("AI response: " + aiResponse);
        
        // Split response into functions using the tags
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "BEGIN_FUNCTION\\s*(.+?)\\s*END_FUNCTION",
            java.util.regex.Pattern.DOTALL
        );
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);
        
        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel functionsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Get selected function names from functionList in order
        JList<String> functionList = (JList<String>) ((JScrollPane) ((JPanel) functionAssistPanel
            .getComponent(1)).getComponent(1)).getViewport().getView();
        List<String> selectedFunctionNames = functionList.getSelectedValuesList();

        TreePath path = fileTree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(analysisFrame, 
                "Please select a class first.", 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        String className = node.getUserObject().toString();

        // Map to track which function names the user has confirmed
        Map<JCheckBox, String> checkboxToCodeMap = new HashMap<>();
        int functionIndex = 0;

        while (matcher.find() && functionIndex < selectedFunctionNames.size()) {
            String function = matcher.group(1).trim();
            if (function.isEmpty()) continue;

            String currentFunctionName = selectedFunctionNames.get(functionIndex);
            
            JPanel functionPanel = new JPanel(new BorderLayout());
            functionPanel.setBorder(BorderFactory.createEtchedBorder());

            JPanel headerPanel = new JPanel(new BorderLayout());
            JCheckBox checkbox = new JCheckBox("Replace function: " + currentFunctionName);
            
            // Display inferred function name as a label if we can extract it
            String inferredFunctionName = extractFunctionName(function);
            if (inferredFunctionName != null) {
                JLabel inferredNameLabel = new JLabel("Inferred: " + inferredFunctionName);
                headerPanel.add(inferredNameLabel, BorderLayout.EAST);
            }

            headerPanel.add(checkbox, BorderLayout.WEST);

            JTextArea codeArea = new JTextArea(function);
            codeArea.setRows(8);
            codeArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(codeArea);

            functionPanel.add(headerPanel, BorderLayout.NORTH);
            functionPanel.add(scrollPane, BorderLayout.CENTER);

            checkboxToCodeMap.put(checkbox, function);

            gbc.gridy++;
            functionsPanel.add(functionPanel, gbc);
            functionIndex++;
        }

        JScrollPane mainScrollPane = new JScrollPane(functionsPanel);
        mainScrollPane.setPreferredSize(new Dimension(800, 600));
        mainPanel.add(mainScrollPane, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(analysisFrame,
            mainPanel,
            "Accept or Reject Function Updates",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            boolean anyUpdates = false;
            functionIndex = 0;
            for (Map.Entry<JCheckBox, String> entry : checkboxToCodeMap.entrySet()) {
                JCheckBox checkbox = entry.getKey();
                if (checkbox.isSelected()) {
                    String newCode = entry.getValue();
                    String functionName = selectedFunctionNames.get(functionIndex);

                    // Update database and verify
                    dbHandler.updateFunctionDecompilation(functionName, className, newCode);
                    String verifyUpdate = dbHandler.getFunctionDecompilation(functionName, className);
                    if (verifyUpdate != null && verifyUpdate.equals(newCode)) {
                        anyUpdates = true;
                    } else {
                        LOGGER.warning("Failed to update function: " + functionName);
                    }
                }
                functionIndex++;
            }

            // Refresh display if any updates were made
            if (anyUpdates) {
                SwingUtilities.invokeLater(() -> displayClassDecompilation(className));
            }
        }
    }

    private static String extractFunctionName(String functionCode) {
        // Basic function name extraction - you might need to make this more robust
        try {
            String[] lines = functionCode.split("\n");
            for (String line : lines) {
                line = line.trim();
                if (line.contains("func ")) {
                    // Extract name between "func " and "("
                    int startIndex = line.indexOf("func ") + 5;
                    int endIndex = line.indexOf("(");
                    if (endIndex > startIndex) {
                        return line.substring(startIndex, endIndex).trim();
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error extracting function name", e);
        }
        return null;
    }

    private static boolean isInClassesTree(TreePath path) {
        return path.getPathCount() > 1 && 
               ((DefaultMutableTreeNode) path.getPathComponent(1)).getUserObject().toString().equals("Classes");
    }

    private static void startEditing(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode) node.getParent();
        String functionName = node.getUserObject().toString();
        String className = parentNode.getUserObject().toString();

        // Enable editing and show save button
        fileContentArea.setEditable(true);
        saveButton.setVisible(true);
        isEditing = true;

        // Store current function info for saving later
        fileContentArea.putClientProperty("currentFunction", functionName);
        fileContentArea.putClientProperty("currentClass", className);
    }

    private static void saveCurrentFunction() {
        if (!isEditing) return;

        String functionName = (String) fileContentArea.getClientProperty("currentFunction");
        String className = (String) fileContentArea.getClientProperty("currentClass");
        String newCode = fileContentArea.getText();

        // Update the database
        dbHandler.updateFunctionDecompilation(functionName, className, newCode);

        // Reset editing state
        fileContentArea.setEditable(false);
        saveButton.setVisible(false);
        isEditing = false;

        // Refresh the display
        displayFunctionDecompilation(functionName, className);
    }
}
