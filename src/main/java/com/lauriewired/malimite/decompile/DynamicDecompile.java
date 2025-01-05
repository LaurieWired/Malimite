package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.configuration.Config;
import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.utils.FileProcessing;
import java.io.File;
import java.util.logging.Logger;
import javax.swing.SwingUtilities;

public class DynamicDecompile {
    private static final Logger LOGGER = Logger.getLogger(DynamicDecompile.class.getName());

    public static void decompileFile(String filePath, String projectDirectoryPath, String fullFilePath, Config config, SQLiteDBHandler dbHandler, String infoPlistExecutableName) {
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

        Macho targetMacho = new Macho(fullFilePath, projectDirectoryPath, fileName);

        GhidraProject ghidraProject = new GhidraProject(infoPlistExecutableName, fullFilePath, config, dbHandler, null);
            // message -> SwingUtilities.invokeLater(() -> {
            //     consoleOutput.append(message + "\n");
            //     consoleOutput.setCaretPosition(consoleOutput.getDocument().getLength());
            // }));
        ghidraProject.decompileMacho(fullFilePath, projectDirectoryPath, targetMacho, true);
    }
}
