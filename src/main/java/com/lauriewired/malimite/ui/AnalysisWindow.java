package com.lauriewired.malimite.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.DefaultListModel;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseEvent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.Arrays;
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
import com.lauriewired.malimite.configuration.Project;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.files.InfoPlist;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.files.MobileProvision;
import com.lauriewired.malimite.tools.AIBackend;
import com.lauriewired.malimite.tools.AIBackend.Model;
import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.utils.NodeOperations;
import com.lauriewired.malimite.utils.PlistUtils;
import com.lauriewired.malimite.utils.ResourceParser;

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
    private static JSplitPane rightSplitPane;
    private static JSplitPane rightVerticalSplitPane;
    private static JPanel functionAssistPanel;
    private static JPanel stringsPanel;
    private static boolean functionAssistVisible = false;
    private static JLabel bundleIdValue;
    private static JLabel closeLabel;
    private static JLabel selectedFileLabel;

    private static JButton saveButton;
    private static boolean isEditing = false;

    private static JProgressBar processingBar;
    private static JLabel processingLabel;
    private static JPanel statusPanel;

    private static JTextPane infoDisplay;

    private static Project currentProject;

    private static JLabel stringsCloseLabel;

    private static JPanel resourceStringsPanel;
    private static JLabel resourceStringsCloseLabel;

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
            
            // Select Info.plist node by default
            DefaultMutableTreeNode infoNode = NodeOperations.findInfoPlistNode((DefaultMutableTreeNode) treeModel.getRoot());

            if (infoNode != null) {
                TreePath infoPath = new TreePath(treeModel.getPathToRoot(infoNode));
                fileTree.setSelectionPath(infoPath);
                fileTree.scrollPathToVisible(infoPath);
            }
            
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
        infoDisplay = new JTextPane();
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
    
        // Initialize the selected file label and set some padding
        selectedFileLabel = new JLabel("No file selected");
        selectedFileLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // Create a panel for the selected file label
        JPanel fileLabelPanel = new JPanel(new BorderLayout());
        fileLabelPanel.add(selectedFileLabel, BorderLayout.CENTER);
        // Add a thinner, semi-transparent border just to the top and bottom
        fileLabelPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, new java.awt.Color(200, 200, 200, 128)));

        // Add this panel to the top of the content area
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(fileLabelPanel, BorderLayout.NORTH);
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

        // Create strings panel
        stringsPanel = new JPanel(new BorderLayout());
        stringsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Create header for strings panel
        JPanel stringsHeaderPanel = new JPanel(new BorderLayout());
        JLabel stringsLabel = new JLabel("Mach-O Strings", SwingConstants.CENTER);
        stringsLabel.setFont(stringsLabel.getFont().deriveFont(Font.BOLD));
        stringsLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        // Add close button for strings panel
        stringsCloseLabel = new JLabel("✕");  // Using "✕" as the close symbol
        stringsCloseLabel.setFont(stringsCloseLabel.getFont().deriveFont(14.0f));
        stringsCloseLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 10, 5));
        stringsCloseLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        stringsCloseLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                toggleFunctionAssist();  // Reuse the same toggle since panels are linked
            }
        });
        stringsCloseLabel.setVisible(functionAssistVisible);
        
        stringsHeaderPanel.add(stringsLabel, BorderLayout.CENTER);
        stringsHeaderPanel.add(stringsCloseLabel, BorderLayout.EAST);
        
        stringsPanel.add(stringsHeaderPanel, BorderLayout.NORTH);
        
        // Create placeholder content
        JTextArea stringsContent = new JTextArea("String analysis will appear here...");
        stringsContent.setEditable(false);
        stringsContent.setBackground(null);
        stringsContent.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JScrollPane stringsScrollPane = new JScrollPane(stringsContent);
        stringsPanel.add(stringsScrollPane, BorderLayout.CENTER);

        // Create resource strings panel
        resourceStringsPanel = new JPanel(new BorderLayout());
        resourceStringsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create header for resource strings panel
        JPanel resourceStringsHeaderPanel = new JPanel(new BorderLayout());
        JLabel resourceStringsLabel = new JLabel("Resource Strings", SwingConstants.CENTER);
        resourceStringsLabel.setFont(resourceStringsLabel.getFont().deriveFont(Font.BOLD));
        resourceStringsLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        // Add close button for resource strings panel
        resourceStringsCloseLabel = new JLabel("✕");
        resourceStringsCloseLabel.setFont(resourceStringsCloseLabel.getFont().deriveFont(14.0f));
        resourceStringsCloseLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 10, 5));
        resourceStringsCloseLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        resourceStringsCloseLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                toggleFunctionAssist();  // Reuse the same toggle since panels are linked
            }
        });
        resourceStringsCloseLabel.setVisible(functionAssistVisible);

        resourceStringsHeaderPanel.add(resourceStringsLabel, BorderLayout.CENTER);
        resourceStringsHeaderPanel.add(resourceStringsCloseLabel, BorderLayout.EAST);

        resourceStringsPanel.add(resourceStringsHeaderPanel, BorderLayout.NORTH);

        // Create placeholder content
        JTextArea resourceStringsContent = new JTextArea("Resource string analysis will appear here...");
        resourceStringsContent.setEditable(false);
        resourceStringsContent.setBackground(null);
        resourceStringsContent.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JScrollPane resourceStringsScrollPane = new JScrollPane(resourceStringsContent);
        resourceStringsPanel.add(resourceStringsScrollPane, BorderLayout.CENTER);

        // Create vertical split pane for all three panels
        rightVerticalSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightVerticalSplitPane.setResizeWeight(0.67); // Give top section 67% of space

        // First split: Strings and Resource Strings
        JSplitPane topSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, stringsPanel, resourceStringsPanel);
        topSplitPane.setResizeWeight(0.5);  // Equal split between top two panels

        // Add the top split pane and function assist panel to the main vertical split
        rightVerticalSplitPane.setTopComponent(topSplitPane);
        rightVerticalSplitPane.setBottomComponent(functionAssistPanel);

        // Create the main horizontal split between content and right panels
        rightSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, rightPanel, rightVerticalSplitPane);
        rightSplitPane.setDividerLocation(1.0);
        rightSplitPane.setResizeWeight(1.0);

        // Set initial sizes for the panels
        stringsPanel.setPreferredSize(new Dimension(300, 200));
        resourceStringsPanel.setPreferredSize(new Dimension(300, 200));
        functionAssistPanel.setPreferredSize(new Dimension(300, 200));

        // Combine left and right panels
        mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightSplitPane);
        mainSplitPane.setDividerLocation(300);
    
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(mainSplitPane, BorderLayout.CENTER);

        toggleFunctionAssist(); // Change my mind. Want to show it by default and this is the easiest way to do it

        // Add save button (initially invisible)
        saveButton = new JButton("Save Changes");
        saveButton.setVisible(false);
        saveButton.addActionListener(e -> saveCurrentFunction());
        
        // Add save button to the right panel, above the content
        JPanel rightTopPanel = new JPanel(new BorderLayout());
        rightTopPanel.add(bundleIdPanel, BorderLayout.NORTH);
        rightTopPanel.add(fileLabelPanel, BorderLayout.CENTER);
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

    private static void loadAndAnalyzeFile(File file, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Starting analysis on " + file.getName());
        fileNameLabel.setText(file.getName());
        filesRootNode.removeAllChildren();
        treeModel.reload();
        fileEntriesMap.clear();
        fileContentArea.setText("");
    
        LOGGER.info("Beginning file unzip and analysis process");
        unzipAndLoadToTree(file, filesRootNode, classesRootNode);
        
        // Update this line to use FileProcessing
        Project project = FileProcessing.updateFileInfo(new File(currentFilePath), projectMacho);
        currentProject = project;  // Keep track of current project
        infoDisplay.setText(project.generateInfoString());
        
        // Add this line to populate the strings panel after loading the tree
        populateMachoStringsPanel();

        // Add this line after populating the strings panel
        populateResourceStringsPanel();
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
                    handleEntryWithoutResources(entry, appNode, zipIn);
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            LOGGER.info("Finished extracting resources");

            initializeProject();
            populateClassesNode(classesRootNode);
            
            // Now process all resources in a separate pass
            processResourceStrings(fileToUnzip, appNode);
    
            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(fileTree);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error unzipping and loading to tree", e);
        }
    }
    
    private static void populateClassesNode(DefaultMutableTreeNode classesRootNode) {
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
        NodeOperations.populateClassesNode(classesRootNode, classesAndFunctions);
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
                    publish("Processing and decompiling...");
                    ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, projectMacho);
                } else {
                    publish("Loading existing database...");
                    dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                        projectMacho.getMachoExecutableName() + "_malimite.db");
                }

                // After dbHandler is initialized, set it in ResourceParser
                System.out.println("LAURIE setting dbHandler in ResourceParser");
                ResourceParser.setDatabaseHandler(dbHandler);

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
    
    private static void handleEntryWithoutResources(ZipEntry entry, DefaultMutableTreeNode appNode, ZipInputStream zipIn) throws IOException {
        String relativePath = entry.getName().substring(appNode.toString().length());
        DefaultMutableTreeNode currentNode;

        // Read the content once into a byte array
        byte[] contentBytes = null;
        if (!entry.isDirectory()) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int len;
            while ((len = zipIn.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }
            contentBytes = outputStream.toByteArray();
        }

        if (relativePath.equals("Info.plist")) {
            currentNode = new DefaultMutableTreeNode("Info.plist");
            appNode.add(currentNode);
            fileEntriesMap.put(NodeOperations.buildFullPathFromNode(currentNode), entry.getName());

            // Process Info.plist content
            if (contentBytes != null) {
                // Process as Info.plist
                infoPlist = new InfoPlist(currentNode, currentFilePath, fileEntriesMap);
                updateBundleIdDisplay(infoPlist.getBundleIdentifier());
            }
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

    private static void processResourceStrings(File fileToUnzip, DefaultMutableTreeNode appNode) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(fileToUnzip))) {
            ZipEntry entry = zipIn.getNextEntry();
            
            while (entry != null) {
                if (!entry.isDirectory() && appNode != null && entry.getName().startsWith(appNode.toString())) {
                    // Check if this is a resource file and process it
                    if (ResourceParser.isResource(entry.getName())) {
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = zipIn.read(buffer)) > 0) {
                            outputStream.write(buffer, 0, len);
                        }
                        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray())) {
                            ResourceParser.parseResourceForStrings(inputStream, entry.getName());
                        }
                    }
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error processing resource strings", e);
        }
    }

    private static void displaySelectedFileContent(TreeSelectionEvent e) {
        // Don't change content if we're currently editing
        if (isEditing) {
            return;
        }

        TreePath path = e.getPath();
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();

        selectedFileLabel.setText(node.getUserObject().toString());
    
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

        // Only proceed if this path exists in our fileEntriesMap
        String entryPath = fileEntriesMap.get(fullPath.toString());
        if (entryPath == null) {
            return;
        }

        if (currentFilePath != null) {
            try {
                byte[] contentBytes = FileProcessing.readContentFromZip(currentFilePath, entryPath);
                String contentText;

                // Check if this is a mobile provision file
                if (entryPath.endsWith("embedded.mobileprovision")) {
                    contentText = MobileProvision.parseProvisioningProfile(contentBytes);
                    fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
                } else if (fullPath.toString().endsWith("plist")) {
                    if (PlistUtils.isBinaryPlist(contentBytes)) {
                        contentText = PlistUtils.decodeBinaryPropertyList(contentBytes);
                        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                    } else {
                        contentText = new String(contentBytes);
                        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
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
            } catch (Exception ex) {
                // Handle other exceptions that might occur during mobile provision parsing
                LOGGER.log(Level.SEVERE, "Error parsing mobile provision file", ex);
                fileContentArea.setText("Error parsing mobile provision file: " + ex.getMessage());
            }
        }
    }

    private static void displayClassDecompilation(String className) {
        try {
            // Update the function list in the function assist panel
            FileProcessing.updateFunctionList(functionAssistPanel, dbHandler, className);
            
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
            FileProcessing.updateFunctionList(functionAssistPanel, dbHandler, className);
            
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
            stringsPanel.setVisible(functionAssistVisible);
            resourceStringsPanel.setVisible(functionAssistVisible);
            closeLabel.setVisible(functionAssistVisible);
            stringsCloseLabel.setVisible(functionAssistVisible);
            resourceStringsCloseLabel.setVisible(functionAssistVisible);

            if (functionAssistVisible) {
                rightSplitPane.setDividerLocation(rightSplitPane.getWidth() - 300);
                // Set equal spacing for all three panels
                JSplitPane topSplitPane = (JSplitPane) rightVerticalSplitPane.getTopComponent();
                topSplitPane.setDividerLocation(0.5);  // Equal split between top two panels
                rightVerticalSplitPane.setDividerLocation(0.66);  // Give bottom panel 1/3 of space
            } else {
                rightSplitPane.setDividerLocation(1.0);
            }

            mainSplitPane.revalidate();
            mainSplitPane.repaint();
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

            // Simplified header with just the checkbox, selected by default
            JCheckBox checkbox = new JCheckBox("Replace function: " + currentFunctionName);
            checkbox.setSelected(true);  // Set checked by default

            JTextArea codeArea = new JTextArea(function);
            codeArea.setRows(8);
            codeArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(codeArea);

            functionPanel.add(checkbox, BorderLayout.NORTH);
            functionPanel.add(scrollPane, BorderLayout.CENTER);

            checkboxToCodeMap.put(checkbox, function);

            gbc.gridy++;
            functionsPanel.add(functionPanel, gbc);
            functionIndex++;
        }

        JScrollPane mainScrollPane = new JScrollPane(functionsPanel);
        // Remove fixed height, let it be determined by content
        mainScrollPane.setPreferredSize(new Dimension(800, Math.min(600, functionsPanel.getPreferredSize().height + 50)));
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

    public static Project getCurrentProject() {
        return currentProject;
    }

    // Add this new method
    private static void populateMachoStringsPanel() {
        if (dbHandler != null && stringsPanel != null) {
            List<Map<String, String>> machoStrings = dbHandler.getMachoStrings();
            
            StringBuilder content = new StringBuilder();
            content.append("<html><body style='font-family: monospace'>");
            
            content.append("<table>");
            content.append("<tr>");
            content.append("<th style='text-align: left; padding-right: 20px'>Value</th>");
            content.append("<th style='text-align: left; padding-right: 20px'>Segment</th>");
            content.append("<th style='text-align: left'>Label</th>");
            content.append("</tr>");
            
            for (Map<String, String> string : machoStrings) {
                content.append("<tr>");
                content.append("<td style='padding-right: 20px'>").append(string.get("value")).append("</td>");
                content.append("<td style='padding-right: 20px'>").append(string.get("segment")).append("</td>");
                content.append("<td>").append(string.get("label")).append("</td>");
                content.append("</tr>");
            }
            
            content.append("</table></body></html>");
            
            // Update panel content (same as before)
            updatePanelContent(stringsPanel, content.toString());
        }
    }

    // Add this new method to populate the resource strings panel
    private static void populateResourceStringsPanel() {
        if (dbHandler != null && resourceStringsPanel != null) {
            List<Map<String, String>> resourceStrings = dbHandler.getResourceStrings();
            
            StringBuilder content = new StringBuilder();
            content.append("<html><body style='font-family: monospace'>");
            
            content.append("<table style='white-space: nowrap'>");
            content.append("<tr>");
            content.append("<th style='text-align: left; padding-right: 20px'>Value</th>");
            content.append("<th style='text-align: left; padding-right: 20px'>File</th>");
            content.append("<th style='text-align: left'>Type</th>");
            content.append("</tr>");
            
            for (Map<String, String> string : resourceStrings) {
                String value = string.get("value");
                // Escape HTML special characters
                value = value.replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;")
                           .replace("\"", "&quot;")
                           .replace("'", "&#39;");
                
                String truncatedValue = value.length() > 60 ? value.substring(0, 60) + "..." : value;
                
                // Extract just the filename from the full path
                String fullPath = string.get("resourceId");
                String fileName = fullPath.substring(fullPath.lastIndexOf('/') + 1);
                
                content.append("<tr>");
                content.append("<td style='padding-right: 20px; white-space: nowrap'>").append(truncatedValue).append("</td>");
                content.append("<td style='padding-right: 20px; white-space: nowrap'>").append(fileName).append("</td>");
                content.append("<td style='white-space: nowrap'>").append(string.get("type")).append("</td>");
                content.append("</tr>");
            }
            
            content.append("</table></body></html>");
            
            updatePanelContent(resourceStringsPanel, content.toString());
        }
    }

    // Helper method to reduce code duplication
    private static void updatePanelContent(JPanel panel, String content) {
        Component[] components = panel.getComponents();
        for (Component component : components) {
            if (component instanceof JScrollPane) {
                JScrollPane scrollPane = (JScrollPane) component;
                Component view = scrollPane.getViewport().getView();
                if (view instanceof JTextArea) {
                    JEditorPane editorPane = new JEditorPane();
                    editorPane.setContentType("text/html");
                    editorPane.setEditable(false);
                    editorPane.setText(content);
                    editorPane.setBackground(null);
                    editorPane.setCaretPosition(0);
                    scrollPane.getVerticalScrollBar().setValue(0);
                    scrollPane.setViewportView(editorPane);
                    break;
                }
            }
        }
    }
}
