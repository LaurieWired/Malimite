package com.lauriewired.ipax.decompile;

import com.lauriewired.ipax.utils.FileProcessing;
import com.lauriewired.ipax.files.Macho;

public class GhidraProject {
    private String ghidraProjectName;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_ipax";
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho) {
        try {
            //FIXME why is this not seeing my env vars
            //FIXME do we have to write the ghidra scripts to the ghidra_scripts folder
            ProcessBuilder builder = new ProcessBuilder(
                "C:\\Users\\Laurie\\Documents\\GitClones\\ghidra_10.4_PUBLIC\\support\\analyzeHeadless.bat",
                projectDirectoryPath,
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
            FileProcessing.readStream(process.getInputStream());
            FileProcessing.readStream(process.getErrorStream());

            process.waitFor();
            System.out.println("Done with ghidra analysis");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}