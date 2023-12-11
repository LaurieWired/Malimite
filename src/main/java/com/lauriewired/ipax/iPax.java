package com.lauriewired.ipax;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.zip.*;

import com.dd.plist.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class iPax extends JFrame {

    private JLabel fileNameLabel;
    private JTextArea fileContentArea;
    private DefaultTreeModel treeModel;
    private JTree fileTree;
    private Map<String, String> fileEntriesMap;
    private String currentFilePath; // Path to the file being analyzed
    private String infoPlistBundleExecutable; // CFBundleExecutable from Info.plist
    private String projectDirectoryPath;
    private String ghidraProjectName;

    // Mach-O Magic Numbers
    private static final int FAT_MAGIC = 0xcafebabe;
    private static final int FAT_CIGAM = 0xbebafeca;

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
            processExecutable();
    
            treeModel.reload();
            collapseAllTreeNodes();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void processExecutable() {
        if (this.currentFilePath == null || this.currentFilePath.isEmpty() || 
            this.infoPlistBundleExecutable == null || this.infoPlistBundleExecutable.isEmpty()) {
            System.out.println("Failed to extract executable");
            return;
        }

        System.out.println(this.currentFilePath + " " + this.infoPlistBundleExecutable);

        // Extract the base name of the .ipa file
        File ipaFile = new File(this.currentFilePath);
        String baseName = ipaFile.getName().replaceFirst("[.][^.]+$", "");
        this.projectDirectoryPath = ipaFile.getParent() + File.separator + baseName + "_ipax";

        // Create ipax project directory
        File projectDirectory = new File(this.projectDirectoryPath);
        if (!projectDirectory.exists()) {
            if (projectDirectory.mkdir()) {
                System.out.println("Created project directory: " + this.projectDirectoryPath);
            } else {
                System.out.println("Failed to create project directory: " + this.projectDirectoryPath);
                return;
            }

            // Unzip the executable into the new project directory
            // Unfortunately we have to extract it for ghidra to process it in headless mode
            String outputFilePath = this.projectDirectoryPath + File.separator + this.infoPlistBundleExecutable;
            try {
                unzipExecutable(this.currentFilePath, this.infoPlistBundleExecutable, outputFilePath);
            } catch (IOException e) {
                e.printStackTrace();
            }

            runGhidraCommand();
        } else {
            //TODO: add handling for reopening an existing ipax project
            System.out.println("Project '" + this.ghidraProjectName + "' already exists.");

            //will need to add project name + classes + xrefs + user comments
            //reopening will populate this into ipax
            //maybe should add resource node structure here as an optimization
        }
    }

    private void runGhidraCommand() {
        this.ghidraProjectName = this.infoPlistBundleExecutable + "_ipax";
        String executableFilePath = this.projectDirectoryPath + File.separator + this.infoPlistBundleExecutable;

        // See if we're dealing with a FAT binary and need to select architecture
        analyzeMachOFile(executableFilePath);

        try {
            //FIXME why is this not seeing my env vars
            //FIXME do we have to write the ghidra scripts to the ghidra_scripts folder
            ProcessBuilder builder = new ProcessBuilder(
                "C:\\Users\\Laurie\\Documents\\GitClones\\ghidra_10.4_PUBLIC\\support\\analyzeHeadless.bat",
                this.projectDirectoryPath,
                this.ghidraProjectName,
                "-import",
                executableFilePath,
                "-postScript",
                "ParseClasses.java" //TODO: also run name demangler if this is a swift binary
            );

            //FIXME need to let user decide which architecture to pull from the fat binary and pass the selection to ghidra

            System.out.println("Running: " + builder.command().toString());
            
            Process process = builder.start();

            // Read output and error streams
            readStream(process.getInputStream());
            readStream(process.getErrorStream());

            process.waitFor();
            System.out.println("Done with ghidra analysis");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void analyzeMachOFile(String filePath) {
        File file = new File(filePath);

        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            int magic = raf.readInt();
            if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
                System.out.println("Detected FAT binary with architectures:");

                // Adjust byte order for reading
                boolean reverseByteOrder = (magic == FAT_CIGAM);
                ByteBuffer buffer = ByteBuffer.allocate(4);
                buffer.order(reverseByteOrder ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);

                int archCount = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                for (int i = 0; i < archCount; i++) {
                    raf.seek(8L + i * 20L); // Skip to the architecture info
                    int cpuType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    int cpuSubType = reverseByteOrder ? Integer.reverseBytes(raf.readInt()) : raf.readInt();
                    printArchitecture(cpuType, cpuSubType);

                    System.out.println("cpuType: " + cpuType);
                    System.out.println("cpuSubType: " + cpuSubType);
                }
            } else {
                System.out.println("This is not a FAT (Universal) binary.");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void printArchitecture(int cpuType, int cpuSubType) {
        // Expand this method to handle different subtypes
        String arch = "Unknown";
        switch (cpuType) {
            case 0x00000007: // Intel x86
                arch = "Intel x86";
                break;
            case 0x01000007: // Intel x86_64
                arch = "Intel x86_64";
                break;
            case 0x0000000C: // ARM
                arch = "ARM";
                break;
            case 0x0100000C: // ARM64
                arch = "ARM64";
                break;
        }

        System.out.println(arch + " " + cpuSubType);
    }

    private static void readStream(InputStream stream) {
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }

    private void unzipExecutable(String zipFilePath, String executableName, String outputFilePath) throws IOException {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(executableName)) {
                    extractFile(zipIn, outputFilePath);
                    break;
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
    }

    private void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
            byte[] bytesIn = new byte[4096]; //TODO: remove magic number
            int read;
            while ((read = zipIn.read(bytesIn)) != -1) {
                bos.write(bytesIn, 0, read);
            }
        }
    }
    
    private void handleEntry(ZipEntry entry, DefaultMutableTreeNode appNode, ZipInputStream zipIn) throws IOException {
        String relativePath = entry.getName().substring(appNode.toString().length());
        DefaultMutableTreeNode currentNode;
    
        if (relativePath.equals("Info.plist")) {
            currentNode = new DefaultMutableTreeNode("Info.plist");
            appNode.add(currentNode);
            fileEntriesMap.put(buildFullPathFromNode(currentNode), entry.getName());
            handleInfoPlist(currentNode);
        } else {
            // Create or get the "Resources" node and add other files to it
            currentNode = addOrGetNode(appNode, "Resources", true);
    
            // Skip the first part of the path if it's a directory
            String[] pathParts = relativePath.split("/");
            for (int i = (entry.isDirectory() ? 1 : 0); i < pathParts.length; i++) {
                boolean isDirectory = i < pathParts.length - 1 || entry.isDirectory();
                currentNode = addOrGetNode(currentNode, pathParts[i], isDirectory);
    
                if (!isDirectory) {
                    fileEntriesMap.put(buildFullPathFromNode(currentNode), entry.getName());
                }
            }
        }
    }

    private void handleInfoPlist(DefaultMutableTreeNode infoPlistNode) {
        try {
            String infoPlistPath = buildFullPathFromNode(infoPlistNode);
            byte[] plistData = readContentFromZip(currentFilePath, fileEntriesMap.get(infoPlistPath));
    
            if (isBinaryPlist(plistData)) {
                // Handle binary plist
                NSObject plist = PropertyListParser.parse(plistData);
                extractCFBundleExecutable(plist);
            } else {
                // Handle XML plist
                String plistContent = new String(plistData);
                NSObject plist = PropertyListParser.parse(plistContent.getBytes());
                extractCFBundleExecutable(plist);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void extractCFBundleExecutable(NSObject plist) {
        if (plist instanceof NSDictionary) {
            NSDictionary dict = (NSDictionary) plist;
            String executableName = dict.objectForKey("CFBundleExecutable").toString();

            this.infoPlistBundleExecutable = executableName;
            System.out.println("CFBundleExecutable: " + executableName);
        }
    }
    
    private void collapseAllTreeNodes() {
        for (int i = 0; i < fileTree.getRowCount(); i++) {
            fileTree.collapseRow(i);
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

    private byte[] readContentFromZip(String zipFilePath, String entryPath) throws IOException {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipIn.getNextEntry();
    
            while (entry != null) {
                if (entry.getName().equals(entryPath)) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = zipIn.read(buffer)) > 0) {
                        out.write(buffer, 0, len);
                    }
                    return out.toByteArray();
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        }
        return new byte[0]; // Return empty array if the entry is not found
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
                byte[] contentBytes = readContentFromZip(currentFilePath, fileEntriesMap.get(fullPath.toString()));
                String contentText;
        
                // Decode if it's a binary plist. Otherwise, just print the text
                if (fullPath.toString().endsWith("plist") && isBinaryPlist(contentBytes)) {
                    System.out.println("Handling binary property list");
                    contentText = decodePropertyList(contentBytes);
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

    private String decodePropertyList(byte[] plistData) {
        try {
            NSObject plist = PropertyListParser.parse(plistData);
            Object javaObj = plist.toJavaObject();
    
            // Use Gson to format it as a JSON string
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            return gson.toJson(javaObj);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean isBinaryPlist(byte[] contentBytes) {
        if (contentBytes.length < "bplist".length()) {
            return false;
        }
        String header = new String(Arrays.copyOf(contentBytes, "bplist".length()));
        return header.equals("bplist");
    }   
}
