package com.lauriewired.malimite;

import com.github.weisj.darklaf.LafManager;
import com.github.weisj.darklaf.theme.DarculaTheme;
import com.lauriewired.malimite.ui.AnalysisWindow;
import com.lauriewired.malimite.configuration.Config;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.logging.Logger;

public class Malimite {
    private static final Logger LOGGER = Logger.getLogger(Malimite.class.getName());

    public static void main(String[] args) {
        // Set Darklaf Look and Feel
        try {
            LafManager.install(new DarculaTheme());
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(Malimite::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Malimite");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);
        frame.setLocationRelativeTo(null);

        // Initialize Config for handling paths
        Config config = new Config();
        
        JPanel panel = new JPanel(new GridBagLayout());
        frame.add(panel);

        setupComponents(panel, frame, config);

        frame.setVisible(true);
    }

    private static void setupComponents(JPanel panel, JFrame frame, Config config) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(15, 15, 15, 15);

        // File path text field
        JTextField filePathText = new JTextField();
        filePathText.setFont(new Font("Verdana", Font.PLAIN, 16));
        filePathText.setEditable(false);
        filePathText.setPreferredSize(new Dimension(275, 30));
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        panel.add(filePathText, constraints);

        // "Select File" button
        JButton fileButton = new JButton("Select File");
        constraints.gridx = 3;
        constraints.gridy = 0;
        constraints.gridwidth = 1;
        panel.add(fileButton, constraints);

        // Status label
        JLabel statusLabel = new JLabel("");
        statusLabel.setFont(new Font("Verdana", Font.ITALIC, 14));
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 4;
        panel.add(statusLabel, constraints);

        // "Analyze" button
        JButton analyzeButton = new JButton("Analyze File");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 4;
        panel.add(analyzeButton, constraints);

        // Set up file listeners
        setupDragAndDrop(filePathText, statusLabel);
        setupFileButtonListener(fileButton, filePathText);
        setupAnalyzeButtonListener(analyzeButton, filePathText, statusLabel, frame, config);
    }

    private static void setupDragAndDrop(JTextField filePathText, JLabel statusLabel) {
        new DropTarget(filePathText, new DropTargetAdapter() {
            @Override
            public void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> droppedFiles = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!droppedFiles.isEmpty()) {
                        File file = droppedFiles.get(0);
                        filePathText.setText(file.getAbsolutePath());
                        statusLabel.setText("File ready for analysis.");
                    }
                } catch (Exception ex) {
                    LOGGER.severe("Error during file drop: " + ex.getMessage());
                    statusLabel.setText("Error loading file.");
                }
            }
        });
    }

    private static void setupFileButtonListener(JButton fileButton, JTextField filePathText) {
        fileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int option = fileChooser.showOpenDialog(null);
            if (option == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                filePathText.setText(selectedFile.getAbsolutePath());
            }
        });
    }

    private static void setupAnalyzeButtonListener(JButton analyzeButton, JTextField filePathText, JLabel statusLabel, JFrame frame, Config config) {
        analyzeButton.addActionListener(e -> {
            String filePath = filePathText.getText();
            if (!filePath.isEmpty() && Files.exists(Paths.get(filePath))) {
                // Trigger AnalysisWindow
                AnalysisWindow.show(frame, new File(filePath), config);
            } else {
                statusLabel.setText("Please select a valid file path.");
            }
        });
    }
}
