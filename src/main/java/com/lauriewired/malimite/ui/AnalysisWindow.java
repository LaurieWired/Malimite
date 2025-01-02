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
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.DefaultListModel;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.table.TableColumnModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.Timer;
import java.awt.event.ActionListener;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
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

import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;

import java.nio.file.Files;

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

    // Add this flag to track whether we're updating from SelectFile
    private static boolean updatingFromSelectFile = false;

    // Add this near the other static variables at the top of the class
    private static String currentClassName;
    private static String currentSelectedText;
    private static int currentCaretPosition;

    // Add this constant at the class level
    private static final int RIGHT_PANEL_WIDTH = 300;
    private static int lastDividerLocation = -1;  // Store the last divider location

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

            SelectFile.clear();

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
                SelectFile.addFile(infoPath);
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
        fileNameLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
    
        DefaultMutableTreeNode hiddenRootNode = new DefaultMutableTreeNode("Hidden");
        treeModel = new DefaultTreeModel(hiddenRootNode);
        DefaultMutableTreeNode classesRootNode = new DefaultMutableTreeNode("Classes");
        DefaultMutableTreeNode filesRootNode = new DefaultMutableTreeNode("Files");
        hiddenRootNode.add(classesRootNode);
        hiddenRootNode.add(filesRootNode);
    
        fileTree = new JTree(treeModel);
        fileTree.setRootVisible(false);
        fileTree.addMouseListener(new MouseAdapter() {
            private Timer clickTimer;
        
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopupTrigger(e); // Check for right-click or popup trigger on press
            }
        
            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopupTrigger(e); // Check for right-click or popup trigger on release
            }
        
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isLeftMouseButton(e)) {
                    TreePath path = fileTree.getPathForLocation(e.getX(), e.getY());
                    if (path == null || path.getLastPathComponent() == null) {
                        return;
                    }
        
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        
                    // Add this block to update currentClassName when clicking on a class node
                    if (isInClassesTree(path)) {
                        if (path.getPathCount() == 3) { // Class node
                            currentClassName = node.getUserObject().toString();
                            LOGGER.info("Selected class: " + currentClassName);
                        } else if (path.getPathCount() == 4) { // Function node
                            DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode) node.getParent();
                            currentClassName = parentNode.getUserObject().toString();
                            LOGGER.info("Selected class (from function): " + currentClassName);
                        }
                    }
        
                    if (e.getClickCount() == 2) {
                        // Cancel the single-click timer if a double-click is detected
                        if (clickTimer != null && clickTimer.isRunning()) {
                            clickTimer.stop();
                        }
        
                        // Handle double-click
                        if (node.isLeaf()) {
                            SelectFile.addFile(path);
                            displaySelectedFileContent(new TreeSelectionEvent(fileTree, path, false, null, null));
                        }
                    } else if (e.getClickCount() == 1) {
                        // Delay single-click logic to distinguish it from double-click
                        if (clickTimer != null && clickTimer.isRunning()) {
                            clickTimer.stop();
                        }
        
                        clickTimer = new Timer(200, new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent evt) {
                                // Handle single-click
                                displaySelectedFileContent(new TreeSelectionEvent(fileTree, path, false, null, null));
        
                                // Check if the file is already open
                                if (SelectFile.isFileOpen(path)) {
                                    SelectFile.handleNodeClick(path);
                                } else if (node.isLeaf() || isInClassesTree(path)) {
                                    SelectFile.replaceActiveFile(path);
                                }
                                clickTimer.stop();
                            }
                        });
                        clickTimer.setRepeats(false);
                        clickTimer.start();
                    }
                }
            }
        
            private void handlePopupTrigger(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    TreePath path = fileTree.getPathForLocation(e.getX(), e.getY());
                    if (path != null && isInClassesTree(path) && path.getPathCount() == 4) {
                        JPopupMenu popup = new JPopupMenu();
                        JMenuItem editItem = new JMenuItem("Edit function");
                        editItem.addActionListener(ev -> startEditing(path));
                        popup.add(editItem);
                        popup.show(fileTree, e.getX(), e.getY());
                    }
                }
            }
        });
        
        JScrollPane treeScrollPane = new JScrollPane(fileTree);
    
        // Initialize RSyntaxTextArea with syntax highlighting
        fileContentArea = new RSyntaxTextArea();
        fileContentArea.setTabSize(2);
        fileContentArea.setTabsEmulated(true);  // This makes it use spaces instead of tabs
        fileContentArea.setEditable(false);
        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);
        fileContentArea.setCodeFoldingEnabled(true);
    
        // Add cursor and selection tracking
        fileContentArea.addCaretListener(e -> {
            currentCaretPosition = e.getDot();
            currentSelectedText = fileContentArea.getSelectedText();
        });
    
        // Add these lines to enable bracket matching
        fileContentArea.setPaintMatchedBracketPair(true);
        fileContentArea.setBracketMatchingEnabled(true);
        fileContentArea.setAnimateBracketMatching(true);
        fileContentArea.setPaintTabLines(true);  // This enables the vertical scope lines
    
        SyntaxHighlighter.applyCustomTheme(fileContentArea);
        SyntaxHighlighter.setupWordHighlighting(fileContentArea);
    
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
        bundleIdPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 10, 5));
        bundleIdPanel.add(bundleIdValue, BorderLayout.CENTER);

        // Create a panel to hold both the label and tabs
        JPanel labelAndTabsPanel = new JPanel(new BorderLayout());
        labelAndTabsPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, javax.swing.UIManager.getColor("Separator.foreground")));
        labelAndTabsPanel.add(SelectFile.getFileTabsPanel(), BorderLayout.CENTER);

        // Create a panel to hold both the label and tabs
        JPanel fileLabelPanel = new JPanel(new BorderLayout());
        fileLabelPanel.add(labelAndTabsPanel, BorderLayout.CENTER);

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
        closeLabel = new JLabel("");
        //closeLabel = new JLabel("✕");  // Using "✕" as the close symbol
        closeLabel.setFont(closeLabel.getFont().deriveFont(14.0f));
        closeLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 10, 5));
        closeLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        // closeLabel.addMouseListener(new java.awt.event.MouseAdapter() {
        //     @Override
        //     public void mouseClicked(java.awt.event.MouseEvent evt) {
        //         toggleFunctionAssist();
        //     }
        // });
        
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
        // assistLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        // assistLabel.addMouseListener(new java.awt.event.MouseAdapter() {
        //     @Override
        //     public void mouseClicked(java.awt.event.MouseEvent evt) {
        //         toggleFunctionAssist();
        //     }
        // });

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
                toggleRightPanel();  // Reuse the same toggle since panels are linked
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
        //resourceStringsCloseLabel = new JLabel("✕");
        resourceStringsCloseLabel = new JLabel("");
        resourceStringsCloseLabel.setFont(resourceStringsCloseLabel.getFont().deriveFont(14.0f));
        resourceStringsCloseLabel.setBorder(BorderFactory.createEmptyBorder(0, 5, 10, 5));
        resourceStringsCloseLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        // resourceStringsCloseLabel.addMouseListener(new java.awt.event.MouseAdapter() {
        //     @Override
        //     public void mouseClicked(java.awt.event.MouseEvent evt) {
        //         toggleFunctionAssist();  // Reuse the same toggle since panels are linked
        //     }
        // });
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

        toggleRightPanel(); // Change my mind. Want to show it by default and this is the easiest way to do it

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

        KeyboardShortcuts.setupShortcuts(fileContentArea, analysisFrame);

        return contentPanel;
    }      

    private static void loadAndAnalyzeFile(File file, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Starting analysis on " + file.getName());
        fileNameLabel.setText(file.getName());
        filesRootNode.removeAllChildren();
        treeModel.reload();
        fileEntriesMap.clear();
        fileContentArea.setText("");
    
        LOGGER.info("Beginning file analysis process");
        
        if (FileProcessing.isArchiveFile(file)) {
            System.out.println("LAURIEEEEEE isArchiveFile: " + file.getName());
            // Handle archive files (IPA, ZIP, etc.)
            unzipAndLoadToTree(file, filesRootNode, classesRootNode);
        } else if (file.isDirectory() || file.getName().endsWith(".app")) {
            System.out.println("LAURIEEEEEE isDirectory: " + file.getName());
            // Handle directories and .app bundles
            loadDirectoryToTree(file, filesRootNode, classesRootNode);
        } else {
            LOGGER.warning("Unsupported file type: " + file.getName());
            return;
        }
        
        // Update project info
        Project project = FileProcessing.updateFileInfo(file, projectMacho);
        config.addProjectPath(project.getFilePath());
        currentProject = project;
        infoDisplay.setText(project.generateInfoString());
        
        populateMachoStringsPanel();
        populateResourceStringsPanel();

        // Select Info.plist node by default and display its content
        DefaultMutableTreeNode infoNode = NodeOperations.findInfoPlistNode((DefaultMutableTreeNode) treeModel.getRoot());
        if (infoNode != null) {
            TreePath infoPath = new TreePath(treeModel.getPathToRoot(infoNode));
            fileTree.setSelectionPath(infoPath);
            fileTree.scrollPathToVisible(infoPath);
            SelectFile.addFile(infoPath);
            
            displaySelectedFileContent(new TreeSelectionEvent(fileTree, infoPath, false, null, null));
        }
    }

    private static void loadDirectoryToTree(File directory, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Loading directory: " + directory.getAbsolutePath());
        
        // Create app node if this is an .app bundle
        DefaultMutableTreeNode appNode = directory.getName().endsWith(".app") ? 
            new DefaultMutableTreeNode(directory.getName()) : null;
        if (appNode != null) {
            filesRootNode.add(appNode);
        }
        
        // Process all files in the directory
        processDirectory(directory, appNode != null ? appNode : filesRootNode, "");
        
        // Find Info.plist with CFBundleIdentifier
        DefaultMutableTreeNode foundInfoNode = findInfoPlistWithBundleId(directory, appNode != null ? appNode : filesRootNode);
        if (foundInfoNode != null) {
            String nodePath = NodeOperations.buildFullPathFromNode(foundInfoNode);
            infoPlist = new InfoPlist(foundInfoNode, fileEntriesMap.get(nodePath), fileEntriesMap);
            updateBundleIdDisplay(infoPlist.getBundleIdentifier());
            
            // Initialize project if Info.plist was found
            initializeProject();
            populateClassesNode(classesRootNode);
            
            // Process resource strings
            processResourceStrings(directory, appNode);
            
            // Select Info.plist node and display its content
            TreePath infoPath = new TreePath(treeModel.getPathToRoot(foundInfoNode));
            fileTree.setSelectionPath(infoPath);
            fileTree.scrollPathToVisible(infoPath);
            SelectFile.addFile(infoPath);
            displaySelectedFileContent(new TreeSelectionEvent(fileTree, infoPath, false, null, null));
        }
        
        treeModel.reload();
    }

    private static DefaultMutableTreeNode findInfoPlistWithBundleId(File directory, DefaultMutableTreeNode rootNode) {
        File[] files = directory.listFiles();
        if (files == null) return null;

        for (File file : files) {
            if (file.getName().equals("Info.plist")) {
                try {
                    // Read the file as bytes first
                    byte[] contentBytes = Files.readAllBytes(file.toPath());
                    
                    // Check if it's a binary plist and decode appropriately
                    String content;
                    if (PlistUtils.isBinaryPlist(contentBytes)) {
                        content = PlistUtils.decodeBinaryPropertyList(contentBytes);
                    } else {
                        content = new String(contentBytes);
                    }

                    if (content.contains("CFBundleIdentifier")) {
                        // Find the existing Info.plist node in the tree
                        Enumeration<?> e = rootNode.breadthFirstEnumeration();
                        while (e.hasMoreElements()) {
                            DefaultMutableTreeNode node = (DefaultMutableTreeNode) e.nextElement();
                            if (node.getUserObject().toString().equals("Info.plist")) {
                                return node;
                            }
                        }
                    }
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Error reading Info.plist: " + e.getMessage(), e);
                }
            } else if (file.isDirectory()) {
                DefaultMutableTreeNode result = findInfoPlistWithBundleId(file, rootNode);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }

    private static void processDirectory(File directory, DefaultMutableTreeNode parentNode, String currentPath) {
        File[] files = directory.listFiles();
        if (files == null) return;

        for (File file : files) {
            String newPath = currentPath.isEmpty() ? file.getName() : currentPath + "/" + file.getName();
            
            if (file.isDirectory()) {
                DefaultMutableTreeNode dirNode = new DefaultMutableTreeNode(file.getName());
                parentNode.add(dirNode);
                processDirectory(file, dirNode, newPath);
            } else {
                DefaultMutableTreeNode fileNode = new DefaultMutableTreeNode(file.getName());
                parentNode.add(fileNode);
                fileEntriesMap.put(NodeOperations.buildFullPathFromNode(fileNode), file.getAbsolutePath());
            }
        }
    }

    private static void unzipAndLoadToTree(File fileToUnzip, DefaultMutableTreeNode filesRootNode, DefaultMutableTreeNode classesRootNode) {
        LOGGER.info("Analyzing " + fileToUnzip);
        currentFilePath = fileToUnzip.toString();

        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(fileToUnzip))) {
            ZipEntry entry = zipIn.getNextEntry();
            DefaultMutableTreeNode appNode = null;
            
            // First pass: Find and process Info.plist containing CFBundleIdentifier
            while (entry != null) {
                if (entry.getName().endsWith("Info.plist")) {
                    // Read the content of the Info.plist file
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = zipIn.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, len);
                    }
                    byte[] contentBytes = outputStream.toByteArray();

                    // Check if this Info.plist contains CFBundleIdentifier
                    String content;
                    if (PlistUtils.isBinaryPlist(contentBytes)) {
                        content = PlistUtils.decodeBinaryPropertyList(contentBytes);
                    } else {
                        content = new String(contentBytes);
                    }

                    if (content.contains("CFBundleIdentifier")) {
                        DefaultMutableTreeNode infoNode = new DefaultMutableTreeNode("Info.plist");
                        filesRootNode.add(infoNode);
                        String nodePath = NodeOperations.buildFullPathFromNode(infoNode);
                        fileEntriesMap.put(nodePath, entry.getName());
                        infoPlist = new InfoPlist(infoNode, currentFilePath, fileEntriesMap);
                        updateBundleIdDisplay(infoPlist.getBundleIdentifier());
                        
                        // Remove Info.plist from fileEntriesMap so it can be processed separately later
                        fileEntriesMap.remove(nodePath);
                        filesRootNode.remove(infoNode);
                        break;
                    }
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
            
            // Reset stream for second pass
            zipIn.close();
            try (ZipInputStream zipIn2 = new ZipInputStream(new FileInputStream(fileToUnzip))) {
                entry = zipIn2.getNextEntry();
                
                // Second pass: Process all other files
                while (entry != null) {
                    if (entry.getName().endsWith(".app/")) {
                        appNode = new DefaultMutableTreeNode(entry.getName());
                        filesRootNode.add(appNode);
                    } else if (appNode != null && entry.getName().startsWith(appNode.toString())) {
                        handleEntryWithoutResources(entry, appNode, zipIn2);
                    }
                    zipIn2.closeEntry();
                    entry = zipIn2.getNextEntry();
                }
            }
            
            LOGGER.info("Finished extracting resources");

            // Only initialize project if we have a valid Info.plist
            if (infoPlist != null) {
                initializeProject();
                populateClassesNode(classesRootNode);
                
                // Now process all resources in a separate pass
                processResourceStrings(fileToUnzip, appNode);
            } else {
                LOGGER.severe("Could not find or process Info.plist file");
                throw new IOException("Info.plist file not found or could not be processed");
            }

            treeModel.reload();
            NodeOperations.collapseAllTreeNodes(fileTree);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error unzipping and loading to tree", e);
        }
    }
    
    private static void populateClassesNode(DefaultMutableTreeNode classesRootNode) {
        Map<String, List<String>> classesAndFunctions = dbHandler.getAllClassesAndFunctions();
        
        // Convert map keys to sorted list
        List<String> sortedClassNames = new ArrayList<>(classesAndFunctions.keySet());
        
        // Remove "Libraries" from the list if it exists
        sortedClassNames.remove("Libraries");
        
        // Sort remaining class names
        Collections.sort(sortedClassNames);
        
        // Add "Libraries" first if it exists in the original map
        if (classesAndFunctions.containsKey("Libraries")) {
            DefaultMutableTreeNode librariesNode = new DefaultMutableTreeNode("Libraries");
            List<String> libraryFunctions = classesAndFunctions.get("Libraries");
            if (libraryFunctions != null) {
                Collections.sort(libraryFunctions);
                for (String function : libraryFunctions) {
                    librariesNode.add(new DefaultMutableTreeNode(function));
                }
            }
            classesRootNode.add(librariesNode);
        }
        
        // Add remaining classes in sorted order
        for (String className : sortedClassNames) {
            DefaultMutableTreeNode classNode = new DefaultMutableTreeNode(className);
            List<String> functions = classesAndFunctions.get(className);
            
            // Sort functions alphabetically if they exist
            if (functions != null) {
                Collections.sort(functions);
                for (String function : functions) {
                    classNode.add(new DefaultMutableTreeNode(function));
                }
            }
            
            classesRootNode.add(classNode);
        }
        
        treeModel.reload(classesRootNode);
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

                // Get the input file name without extension
                String inputFileName = new File(currentFilePath).getName();
                int lastDotIndex = inputFileName.lastIndexOf('.');
                if (lastDotIndex > 0) {
                    inputFileName = inputFileName.substring(0, lastDotIndex);
                }
                
                String dbFilePath = projectDirectoryPath + File.separator + inputFileName + "_malimite.db";
                LOGGER.info("Checking for database at: " + dbFilePath);

                File dbFile = new File(dbFilePath);
                if (!dbFile.exists()) {
                    if (projectMacho.isUniversalBinary()) {
                        LOGGER.info("Detected universal binary - preparing to handle architecture selection");
                        final String[] selectedArch = new String[1];
                        
                        // Don't hide the processing dialog, just show arch selection on top
                        SwingUtilities.invokeAndWait(() -> {
                            LOGGER.info("Showing architecture selection dialog");
                            List<String> architectures = projectMacho.getArchitectureStrings();
                            LOGGER.info("Available architectures: " + String.join(", ", architectures));
                            selectedArch[0] = selectArchitecture(architectures);
                            LOGGER.info("Selected architecture: " + selectedArch[0]);
                        });

                        // Process the selected architecture if one was chosen
                        if (selectedArch[0] != null) {
                            LOGGER.info("Beginning processing of " + selectedArch[0] + " architecture");
                            publish("Processing " + selectedArch[0] + " architecture...");
                            try {
                                projectMacho.processUniversalMacho(selectedArch[0]);
                                LOGGER.info("Finished processing " + selectedArch[0] + " architecture");
                            } catch (Exception e) {
                                LOGGER.severe("Error processing universal Mach-O: " + e.getMessage());
                                e.printStackTrace();
                                throw e;
                            }
                        } else {
                            LOGGER.warning("No architecture selected - cannot proceed");
                            throw new IllegalStateException("No architecture selected for universal binary");
                        }
                    }
                    projectMacho.printArchitectures();
                    publish("Processing and decompiling...");

                    publish("Creating new database...");
                    dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                        inputFileName + "_malimite.db");

                    publish("Starting Ghidra analysis...");
                    ghidraProject = new GhidraProject(infoPlist.getExecutableName(), 
                        executableFilePath, config, dbHandler, 
                        // Add console output callback
                        message -> SwingUtilities.invokeLater(() -> {
                            consoleOutput.append(message + "\n");
                            consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
                        }));
                
                    ghidraProject.decompileMacho(executableFilePath, projectDirectoryPath, projectMacho);
                } else {
                    publish("Loading existing database...");
                    dbHandler = new SQLiteDBHandler(projectDirectoryPath + File.separator, 
                        inputFileName + "_malimite.db");
                }

                // After dbHandler is initialized, set it in ResourceParser
                ResourceParser.setDatabaseHandler(dbHandler);

                return null;
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    if (message.equals("HIDE_DIALOG")) {
                        processingDialog.setVisible(false);
                    } else if (message.equals("SHOW_DIALOG")) {
                        processingDialog.setVisible(true);
                    } else {
                        statusLabel.setText(message);
                        consoleOutput.append(message + "\n");
                        consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
                    }
                }
            }
            
            @Override
            protected void done() {
                processingDialog.dispose();
                try {
                    get();
                    // Show the analysis window after processing is complete
                    SwingUtilities.invokeLater(() -> {
                        if (analysisFrame != null) {
                            analysisFrame.setVisible(true);
                            analysisFrame.toFront();
                            analysisFrame.requestFocus();
                            if (analysisFrame.getExtendedState() == Frame.ICONIFIED) {
                                analysisFrame.setExtendedState(Frame.NORMAL);
                            }
                            analysisFrame.setAlwaysOnTop(true);
                            analysisFrame.setAlwaysOnTop(false);
                        }
                    });
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

    private static void processResourceStrings(File inputFile, DefaultMutableTreeNode appNode) {
        if (FileProcessing.isArchiveFile(inputFile)) {
            // Handle archive files (IPA, ZIP, etc.)
            processArchiveResourceStrings(inputFile, appNode);
        } else {
            // Handle directories and .app bundles
            processDirectoryResourceStrings(inputFile, appNode);
        }
    }

    private static void processArchiveResourceStrings(File archiveFile, DefaultMutableTreeNode appNode) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(archiveFile))) {
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
            LOGGER.log(Level.SEVERE, "Error processing archive resource strings", e);
        }
    }

    private static void processDirectoryResourceStrings(File directory, DefaultMutableTreeNode appNode) {
        try {
            // Get the app directory if it exists
            File appDirectory = directory;
            if (appNode != null) {
                String appName = appNode.getUserObject().toString();
                if (directory.getName().equals(appName)) {
                    appDirectory = directory;
                } else {
                    File[] files = directory.listFiles();
                    if (files != null) {
                        for (File file : files) {
                            if (file.getName().equals(appName)) {
                                appDirectory = file;
                                break;
                            }
                        }
                    }
                }
            }

            // Process all files in the directory recursively
            processDirectoryContents(appDirectory);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error processing directory resource strings", e);
        }
    }

    private static void processDirectoryContents(File directory) {
        if (directory == null || !directory.exists()) {
            return;
        }

        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    processDirectoryContents(file);
                } else if (ResourceParser.isResource(file.getName())) {
                    try (FileInputStream inputStream = new FileInputStream(file)) {
                        ResourceParser.parseResourceForStrings(inputStream, file.getAbsolutePath());
                    } catch (IOException e) {
                        LOGGER.log(Level.SEVERE, "Error processing resource file: " + file.getName(), e);
                    }
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
            fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);
            
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
                byte[] contentBytes;
                File file = new File(currentFilePath);
                
                if (FileProcessing.isArchiveFile(file)) {
                    // Handle archive files (IPA, ZIP, etc.)
                    contentBytes = FileProcessing.readContentFromZip(currentFilePath, entryPath);
                } else {
                    // Handle directories and .app bundles - read file directly
                    contentBytes = Files.readAllBytes(new File(entryPath).toPath());
                }

                String contentText;
                setSyntaxStyle(entryPath);

                // Check if this is a mobile provision file
                if (entryPath.endsWith("embedded.mobileprovision")) {
                    contentText = MobileProvision.parseProvisioningProfile(contentBytes);
                } else if (fullPath.toString().endsWith("plist")) {
                    if (PlistUtils.isBinaryPlist(contentBytes)) {
                        contentText = PlistUtils.decodeBinaryPropertyList(contentBytes);
                        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                    } else {
                        contentText = new String(contentBytes);
                        fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
                    }
                } else {
                    contentText = new String(contentBytes);
                }

                fileContentArea.setText(contentText);
                fileContentArea.setCaretPosition(0);
            } catch (IOException ex) {
                LOGGER.log(Level.SEVERE, "Error reading file content", ex);
                fileContentArea.setText("Error reading file: " + ex.getMessage());
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, "Error processing file content", ex);
                fileContentArea.setText("Error processing file: " + ex.getMessage());
            }
        }
    }

    private static void displayFunctionDecompilation(String functionName, String className) {
        try {
            // Update the function list in the function assist panel
            FileProcessing.updateFunctionList(functionAssistPanel, dbHandler, className);
            
            String functionDecompilation = dbHandler.getFunctionDecompilation(functionName, className);
            if (functionDecompilation != null && !functionDecompilation.isEmpty()) {
                // Only add headers if they don't already exist
                String content = functionDecompilation;
                if (!content.trim().startsWith("// Class:") && !content.trim().startsWith("// Function:")) {
                    StringBuilder contentBuilder = new StringBuilder();
                    contentBuilder.append("// Class: ").append(className).append("\n");
                    contentBuilder.append("// Function: ").append(functionName).append("\n\n");
                    contentBuilder.append(functionDecompilation);
                    content = contentBuilder.toString();
                }

                fileContentArea.setText(content);
                fileContentArea.setCaretPosition(0);
            } else {
                fileContentArea.setText("No decompilation available for function " + functionName);
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error displaying decompilation for " + functionName, ex);
            fileContentArea.setText("Error loading decompilation for " + functionName);
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
            
            // Only add class header if it's not already present
            String firstFunction = dbHandler.getFunctionDecompilation(functions.get(0), className);
            if (firstFunction == null || !firstFunction.trim().startsWith("// Class:")) {
                fullDecompilation.append("// Class: ").append(className).append("\n\n");
            }

            for (String functionName : functions) {
                String functionDecompilation = dbHandler.getFunctionDecompilation(functionName, className);
                if (functionDecompilation != null && !functionDecompilation.isEmpty()) {
                    // Only add function header if it's not already present
                    if (!functionDecompilation.trim().startsWith("// Class:") && !functionDecompilation.trim().startsWith("// Function:")) {
                        fullDecompilation.append("// Function: ").append(functionName).append("\n");
                    }
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

    public static void toggleRightPanel() {
        if (functionAssistPanel != null && mainSplitPane != null) {
            functionAssistVisible = !functionAssistVisible;
            functionAssistPanel.setVisible(functionAssistVisible);
            stringsPanel.setVisible(functionAssistVisible);
            resourceStringsPanel.setVisible(functionAssistVisible);
            closeLabel.setVisible(functionAssistVisible);
            stringsCloseLabel.setVisible(functionAssistVisible);
            resourceStringsCloseLabel.setVisible(functionAssistVisible);

            if (functionAssistVisible) {
                if (lastDividerLocation == -1) {
                    // First time opening, calculate the position
                    lastDividerLocation = rightSplitPane.getWidth() - RIGHT_PANEL_WIDTH;
                }
                rightSplitPane.setDividerLocation(lastDividerLocation);
                
                // Set equal spacing for all three panels
                JSplitPane topSplitPane = (JSplitPane) rightVerticalSplitPane.getTopComponent();
                topSplitPane.setDividerLocation(0.5);  // Equal split between top two panels
                rightVerticalSplitPane.setDividerLocation(0.66);  // Give bottom panel 1/3 of space
            } else {
                // Store the current location before hiding
                lastDividerLocation = rightSplitPane.getDividerLocation();
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
                    }
                } catch (Exception ex) {
                    // Only show error dialog if it's not an ApiKeyMissingException
                    if (!(ex.getCause() instanceof AIBackend.ApiKeyMissingException)) {
                        JOptionPane.showMessageDialog(analysisFrame, 
                            "Error connecting to AI model: " + ex.getMessage(), 
                            "Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
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
        JList<String> functionList = (JList<String>) ((JScrollPane) ((JPanel) functionAssistPanel.getComponent(1)).getComponent(1)).getViewport().getView();
        List<String> selectedFunctionNames = functionList.getSelectedValuesList();

        TreePath path = fileTree.getSelectionPath();
        if (path == null) {
            JOptionPane.showMessageDialog(analysisFrame, 
                "Please select a class first.", 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
            return;
        }
        String className = getCurrentClassName();

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

                    // Ensure comments are present
                    if (!newCode.trim().startsWith("// Class:") && !newCode.trim().startsWith("// Function:")) {
                        StringBuilder contentBuilder = new StringBuilder();
                        contentBuilder.append("// Class: ").append(className).append("\n");
                        contentBuilder.append("// Function: ").append(functionName).append("\n\n");
                        contentBuilder.append(newCode);
                        newCode = contentBuilder.toString();
                    }

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

    public static void startEditing(TreePath path) {
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
            
            // Create table model with column names
            String[] columnNames = {"Value", "File", "Type"};
            Object[][] data = new Object[resourceStrings.size()][3];
            
            // Populate table data
            for (int i = 0; i < resourceStrings.size(); i++) {
                Map<String, String> string = resourceStrings.get(i);
                String value = string.get("value").trim();
                String fullPath = string.get("resourceId");
                String fileName = fullPath.substring(fullPath.lastIndexOf('/') + 1);
                
                // Truncate value if too long
                String truncatedValue = value.length() > 60 ? value.substring(0, 60) + "..." : value;
                
                data[i][0] = truncatedValue;
                data[i][1] = fileName;
                data[i][2] = string.get("type");
            }
            
            // Create table
            JTable table = new JTable(data, columnNames) {
                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;  // Make table read-only
                }
            };
            
            // Add mouse listener for row clicks
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {  // Only handle double clicks
                        LOGGER.info("Double click detected");
                        
                        int row = table.rowAtPoint(e.getPoint());
                        LOGGER.info("Selected row: " + row);
                        
                        if (row >= 0 && row < resourceStrings.size()) {
                            Map<String, String> selectedString = resourceStrings.get(row);
                            String resourcePath = selectedString.get("resourceId");
                            LOGGER.info("Resource path: " + resourcePath);
                            
                            // Construct the correct path by prepending "Files/" and adding "Resources/"
                            // after the .app/ component if it's not the main Info.plist
                            String fullPath;
                            if (resourcePath.matches("Payload/[^/]+\\.app/Info\\.plist")) {
                                fullPath = "Files/" + resourcePath;
                            } else {
                                // Find the .app/ part and insert Resources/ after it
                                int appIndex = resourcePath.indexOf(".app/");
                                if (appIndex != -1) {
                                    fullPath = "Files/" + resourcePath.substring(0, appIndex + 5) + 
                                             "Resources/" + resourcePath.substring(appIndex + 5);
                                } else {
                                    fullPath = "Files/" + resourcePath;
                                }
                            }
                            LOGGER.info("Constructed full path: " + fullPath);
                            
                            // Find the node and create a TreePath
                            DefaultMutableTreeNode node = findNodeByPath((DefaultMutableTreeNode) treeModel.getRoot(), fullPath);
                            if (node != null) {
                                TreePath path = new TreePath(node.getPath());
                                SelectFile.addFile(path);  // This will handle both opening and activating the file
                                
                                // Find and highlight the string after a short delay
                                String searchValue = selectedString.get("value").trim();
                                LOGGER.info("Searching for value: " + searchValue);
                                
                                SwingUtilities.invokeLater(() -> {
                                    try {
                                        String content = fileContentArea.getText();
                                        LOGGER.info("Content length: " + content.length());
                                        
                                        int index = content.indexOf(searchValue);
                                        LOGGER.info("Found string at index: " + index);
                                        
                                        if (index != -1) {
                                            LOGGER.info("Setting caret and selection");
                                            fileContentArea.setCaretPosition(index);
                                            fileContentArea.setSelectionStart(index);
                                            fileContentArea.setSelectionEnd(index + searchValue.length());
                                            
                                            Rectangle rect = fileContentArea.modelToView(index);
                                            LOGGER.info("View rectangle: " + (rect != null ? rect.toString() : "null"));
                                            
                                            if (rect != null) {
                                                fileContentArea.scrollRectToVisible(rect);
                                                LOGGER.info("Scrolled to make selection visible");
                                            }
                                        } else {
                                            LOGGER.warning("String not found in content");
                                            // Log a small portion of the content for debugging
                                            LOGGER.info("Content preview: " + 
                                                content.substring(0, Math.min(100, content.length())) + "...");
                                        }
                                    } catch (Exception ex) {
                                        LOGGER.log(Level.SEVERE, "Error highlighting text", ex);
                                    }
                                });
                            } else {
                                LOGGER.warning("Could not find node for path: " + fullPath);
                            }
                        } else {
                            LOGGER.warning("Invalid row selected: " + row);
                        }
                    }
                }
            });
            
            // Style the table
            table.setShowGrid(false);
            table.setIntercellSpacing(new Dimension(0, 0));
            table.setRowHeight(25);
            table.getTableHeader().setReorderingAllowed(false);
            
            // Add selection highlighting
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setRowSelectionAllowed(true);
            
            // Set column widths
            TableColumnModel columnModel = table.getColumnModel();
            columnModel.getColumn(0).setPreferredWidth(300);  // Value column
            columnModel.getColumn(1).setPreferredWidth(150);  // File column
            columnModel.getColumn(2).setPreferredWidth(100);  // Type column
            
            // Update the panel's content
            Component[] components = resourceStringsPanel.getComponents();
            for (Component component : components) {
                if (component instanceof JScrollPane) {
                    ((JScrollPane) component).setViewportView(table);
                    break;
                }
            }
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

    public static void setSyntaxStyle(String filePath) {
        if (filePath == null) {
            fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
            return;
        }

        // Classes directory always uses C syntax
        if (filePath.startsWith("Classes/")) {
            fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);
            return;
        }

        // Handle different file types
        if (!filePath.endsWith(".plist")) {
            if (filePath.endsWith("embedded.mobileprovision")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else if (filePath.endsWith(".json")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
            } else if (filePath.endsWith(".xml")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
            } else if (filePath.endsWith(".js")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
            } else if (filePath.endsWith(".html") || filePath.endsWith(".htm")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
            } else if (filePath.endsWith(".css")) {
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CSS);
            } else {
                // Default to C syntax for unknown file types
                fileContentArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);
            }
        }
    }

    public static void showFileContent(String filePath) {
        if (filePath == null) {
            fileContentArea.setText("");
            return;
        }

        SwingUtilities.invokeLater(() -> {
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
            DefaultMutableTreeNode targetNode = null;
            
            // Check if this is a class/function path (contains "Classes/")
            if (filePath.startsWith("Classes/")) {
                String[] parts = filePath.split("/");
                if (parts.length >= 2) {
                    String className = parts[1];
                    String functionName = parts.length == 3 ? parts[2] : null;
                    
                    // If it's a function, display just that function
                    if (functionName != null) {
                        displayFunctionDecompilation(functionName, className);
                    } else {
                        // If it's a class, display the whole class
                        displayClassDecompilation(className);
                    }
                    
                    // Find the node for tree selection
                    targetNode = findClassOrFunctionNode(root, className, functionName);
                }
            } else {
                // Regular file path handling
                targetNode = findNodeByPath(root, filePath);
                
                if (targetNode != null) {
                    TreePath path = new TreePath(targetNode.getPath());
                    displaySelectedFileContent(new TreeSelectionEvent(fileTree, path, false, null, null));
                }
            }

            // Only update tree selection if not called from SelectFile
            if (targetNode != null && !updatingFromSelectFile) {
                TreePath path = new TreePath(targetNode.getPath());
                fileTree.setSelectionPath(path);
                fileTree.scrollPathToVisible(path);
            }

            setSyntaxStyle(filePath);
            
            // Force focus and repaint
            fileContentArea.requestFocusInWindow();
            fileContentArea.repaint();
        });
    }

    // Add this method to be called from SelectFile
    public static void showFileContentFromSelectFile(String filePath) {
        updatingFromSelectFile = true;
        showFileContent(filePath);
        updatingFromSelectFile = false;
    }

    // Helper method to find a node by path
    private static DefaultMutableTreeNode findNodeByPath(DefaultMutableTreeNode root, String path) {
        path = path.replaceAll("/+", "/");
        
        String[] parts = path.split("/");
        DefaultMutableTreeNode current = root;
        
        for (int i = 0; i < parts.length; i++) {
            boolean found = false;
            
            for (int j = 0; j < current.getChildCount(); j++) {
                DefaultMutableTreeNode child = (DefaultMutableTreeNode) current.getChildAt(j);
                String nodeValue = child.getUserObject().toString().replaceAll("/+", "/");
                
                if (nodeValue.equals(parts[i])) {
                    current = child;
                    j = 0;
                    found = true;
                    break;
                } else if (nodeValue.contains(parts[i]) && i + 1 < parts.length) {
                    String combined = parts[i] + "/" + parts[i + 1] + "/";
                    if (nodeValue.equals(combined)) {
                        current = child;
                        j = 0;
                        i++;
                        found = true;
                        break;
                    }
                }
                    
            }
            
            if (!found) {
                return null; // If any part of the path is not found, return null
            }
        }
        
        return current;
    }

    // Helper method to find class or function node
    private static DefaultMutableTreeNode findClassOrFunctionNode(DefaultMutableTreeNode root, String className, String functionName) {
        // Find Classes root node
        for (int i = 0; i < root.getChildCount(); i++) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) root.getChildAt(i);
            if (node.getUserObject().toString().equals("Classes")) {
                // Find class node
                for (int j = 0; j < node.getChildCount(); j++) {
                    DefaultMutableTreeNode classNode = (DefaultMutableTreeNode) node.getChildAt(j);
                    if (classNode.getUserObject().toString().equals(className)) {
                        // If we're looking for a specific function
                        if (functionName != null) {
                            for (int k = 0; k < classNode.getChildCount(); k++) {
                                DefaultMutableTreeNode functionNode = (DefaultMutableTreeNode) classNode.getChildAt(k);
                                if (functionNode.getUserObject().toString().equals(functionName)) {
                                    return functionNode;
                                }
                            }
                        } else {
                            return classNode;
                        }
                    }
                }
            }
        }
        return null;
    }

    public static void zoomIn() {
        if (fileContentArea != null) {
            Font currentFont = fileContentArea.getFont();
            float newSize = currentFont.getSize() + 2.0f;
            if (newSize <= 72.0f) { // Maximum size limit
                fileContentArea.setFont(currentFont.deriveFont(newSize));
            }
        }
    }

    public static void zoomOut() {
        if (fileContentArea != null) {
            Font currentFont = fileContentArea.getFont();
            float newSize = currentFont.getSize() - 2.0f;
            if (newSize >= 8.0f) { // Minimum size limit
                fileContentArea.setFont(currentFont.deriveFont(newSize));
            }
        }
    }

    public static void resetZoom() {
        if (fileContentArea != null) {
            Font currentFont = fileContentArea.getFont();
            fileContentArea.setFont(currentFont.deriveFont(14.0f)); // Reset to default size
        }
    }

    // Add these getter methods
    public static String getCurrentClassName() {
        return currentClassName;
    }

    public static SQLiteDBHandler getDbHandler() {
        return dbHandler;
    }

    public static String getCurrentFunctionName() {
        if (fileContentArea == null) return "";
        
        String content = fileContentArea.getText();
        int caretPosition = fileContentArea.getCaretPosition();
        
        // Split the content into lines for processing
        String[] lines = content.split("\n");
        int currentLine = 0;
        int currentPosition = 0;
        
        // Find which line contains the caret
        while (currentPosition < caretPosition && currentLine < lines.length) {
            currentPosition += lines[currentLine].length() + 1; // +1 for newline
            currentLine++;
        }
        
        // Search backwards from current line to find function declaration
        String currentFunction = "";
        for (int i = currentLine - 1; i >= 0; i--) {
            String line = lines[i].trim();
            
            // Look for function marker comment
            if (line.startsWith("// Function: ")) {
                currentFunction = line.substring("// Function: ".length()).trim();
                break;
            }
            
            // If we hit another function's end or the class declaration, stop searching
            if (line.startsWith("// Function: ") || line.startsWith("// Class: ")) {
                break;
            }
        }
        
        return currentFunction;
    }

    public static String getCurrentSelectedText() {
        return currentSelectedText;
    }

    public static int getCurrentCaretPosition() {
        return currentCaretPosition;
    }

    public static RSyntaxTextArea getFileContentArea() {
        return fileContentArea;
    }

    public static void navigateToLine(int lineNumber) {
        SwingUtilities.invokeLater(() -> {
            try {
                int line = lineNumber - 1; // Convert to 0-based index
                int offset = fileContentArea.getLineStartOffset(line);
                fileContentArea.setCaretPosition(offset);
                
                // Ensure the line is visible
                Rectangle rect = fileContentArea.modelToView(offset);
                if (rect != null) {
                    fileContentArea.scrollRectToVisible(rect);
                }
                
                // Highlight the line
                int lineEnd = fileContentArea.getLineEndOffset(line);
                fileContentArea.setSelectionStart(offset);
                fileContentArea.setSelectionEnd(lineEnd - 1);
                
                fileContentArea.requestFocusInWindow();
                fileContentArea.repaint();
            } catch (Exception e) {
                System.err.println("Error navigating to line: " + e.getMessage());
            }
        });
    }
}
