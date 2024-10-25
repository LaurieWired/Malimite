package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.files.Macho;

public class GhidraProject {
    private String ghidraProjectName;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_ipax";
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho) {
        try {
            //FIXME why is this not seeing my env vars
            //FIXME use "-scriptPath" for ghidra scripts location
            //TODO idea: loading bar saying "decompiled 50/103 classes" during decompilation, running in the background
            ProcessBuilder builder = new ProcessBuilder(
                "/Users/laurie/Documents/ghidra_11.2_PUBLIC/support/analyzeHeadless.bat",
                projectDirectoryPath,
                this.ghidraProjectName,
                "-import",
                executableFilePath,
                "-postScript",
                "Ghidra-DumpClassData.py",
                projectDirectoryPath
            );

            System.out.println("Analyzing classes with Ghidra" + builder.command().toString());
            Process process = builder.start();

            // Read output and error streams
            FileProcessing.readStream(process.getInputStream());
            FileProcessing.readStream(process.getErrorStream());

            process.waitFor();
            System.out.println("Finished dumping class data");
            
            //FIXME move to another function and make this multithreaded and run in background
            builder = new ProcessBuilder(
                "/Users/laurie/Documents/ghidra_11.2_PUBLIC/support/analyzeHeadless.bat",
                projectDirectoryPath,
                this.ghidraProjectName,
                "-postScript",
                "Ghidra-DumpMacho.py",
                projectDirectoryPath,
                "-process",
                "-noanalysis"
            );

            System.out.println("Running Ghidra decompilation" + builder.command().toString());
            process = builder.start();

            // Read output and error streams
            FileProcessing.readStream(process.getInputStream());
            FileProcessing.readStream(process.getErrorStream());

            process.waitFor();

            System.out.println("Done with Ghidra analysis");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}