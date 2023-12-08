import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.zip.*;


public class iPax extends JFrame {

    private JLabel fileNameLabel;
    private JTextArea fileContentArea;
    private DefaultTreeModel treeModel;
    private JTree fileTree;
    private Map<String, String> fileContentsMap;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new iPax().setVisible(true));
    }

    public iPax() {
        super("iPax");

        fileNameLabel = new JLabel("No file selected");
        fileNameLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        fileContentsMap = new HashMap<>();

        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode("Files");
        treeModel = new DefaultTreeModel(rootNode);
        fileTree = new JTree(treeModel);
        fileTree.addTreeSelectionListener(e -> displaySelectedFileContent(e));
        JScrollPane treeScrollPane = new JScrollPane(fileTree);

        fileContentArea = new JTextArea();
        fileContentArea.setEditable(false);
        JScrollPane contentScrollPane = new JScrollPane(fileContentArea);

        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.add(fileNameLabel);
        leftPanel.add(new JLabel("Classes")); // Placeholder for classes section
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

                    for (File file : droppedFiles) {
                        fileNameLabel.setText(file.getName());
                        rootNode.removeAllChildren();
                        treeModel.reload();
                        fileContentsMap.clear();
                        unzipAndLoadToTree(file, rootNode);
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

    private void unzipAndLoadToTree(File fileToUnzip, DefaultMutableTreeNode rootNode) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(fileToUnzip))) {
            ZipEntry entry = zipIn.getNextEntry();
            DefaultMutableTreeNode appNode = null;
    
            while (entry != null) {
                if (entry.getName().endsWith(".app/")) {
                    appNode = new DefaultMutableTreeNode(entry.getName());
                    rootNode.add(appNode);
                } else if (appNode != null && entry.getName().startsWith(appNode.toString())) {
                    String relativePath = entry.getName().substring(appNode.toString().length());
                    DefaultMutableTreeNode currentNode;
            
                    if (relativePath.equals("Info.plist")) {
                        // Directly add Info.plist as a child of the appNode
                        currentNode = new DefaultMutableTreeNode("Info.plist");
                        appNode.add(currentNode);
                        fileContentsMap.put(entry.getName(), readZipEntryContent(zipIn));
                    } else {
                        // Create or get the "Resources" node and add other files to it
                        currentNode = addOrGetNode(appNode, "Resources", true);
            
                        // Skip the first part of the path if it's a directory
                        String[] pathParts = relativePath.split("/");
                        for (int i = (entry.isDirectory() ? 1 : 0); i < pathParts.length; i++) {
                            boolean isDirectory = i < pathParts.length - 1 || entry.isDirectory();
                            currentNode = addOrGetNode(currentNode, pathParts[i], isDirectory);
            
                            if (!isDirectory) {
                                fileContentsMap.put(entry.getName(), readZipEntryContent(zipIn));
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

    private String readZipEntryContent(ZipInputStream zipIn) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = zipIn.read(buffer)) > 0) {
            out.write(buffer, 0, len);
        }
        return new String(out.toByteArray());
    }

    private void displaySelectedFileContent(TreeSelectionEvent e) {
        TreePath path = e.getPath();
        StringBuilder fullPath = new StringBuilder();

        // Skip the root node and concatenate the rest to form the full path
        for (int i = 1; i < path.getPathCount(); i++) {
            fullPath.append(((DefaultMutableTreeNode) path.getPathComponent(i)).getUserObject().toString());
        }

        String content = fileContentsMap.get(fullPath.toString());
        if (content != null) {
            fileContentArea.setText(content);
            fileContentArea.setCaretPosition(0); // Reset scroll to the top
        }
    }
}
