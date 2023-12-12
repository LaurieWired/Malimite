package com.lauriewired.ipax.decompile;

import java.io.File;

public class GhidraBridge {
    private String ghidraProjectName;

    /*
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
    }*/
}