import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.*;
import java.util.zip.*;

public class iPax extends JFrame {

    private JList<String> fileList;
    private DefaultListModel<String> listModel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new UnzipperApp().setVisible(true);
        });
    }

    public iPax() {
        super("Unzipper App");

        listModel = new DefaultListModel<>();
        fileList = new JList<>(listModel);
        JScrollPane scrollPane = new JScrollPane(fileList);

        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.WEST);

        setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    java.util.List<File> droppedFiles = (java.util.List<File>) evt
                            .getTransferable().getTransferData(DataFlavor.javaFileListFlavor);

                    for (File file : droppedFiles) {
                        unzipFile(file);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center the window
    }

    private void unzipFile(File fileToUnzip) {
        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(fileToUnzip))) {
            ZipEntry entry = zipIn.getNextEntry();

            while (entry != null) {
                listModel.addElement(entry.getName());
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
