package com.lauriewired.malimite.decompile;

import com.lauriewired.malimite.utils.FileProcessing;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.configuration.Config;

import java.nio.file.Paths;

public class GhidraProject {
    private String ghidraProjectName;
    private Config config;

    public GhidraProject(String infoPlistBundleExecutable, String executableFilePath, Config config) {
        this.ghidraProjectName = infoPlistBundleExecutable + "_malimite";
        this.config = config;
    }

    public void decompileMacho(String executableFilePath, String projectDirectoryPath, Macho targetMacho) {
        try {
            String analyzeHeadless = getAnalyzeHeadlessPath();

            ProcessBuilder builder = new ProcessBuilder(
                analyzeHeadless,
                projectDirectoryPath,
                this.ghidraProjectName,
                "-import",
                executableFilePath,
                "-postScript",
                "Ghidra-DumpClassData.py",
                projectDirectoryPath
            );

            runGhidraProcess(builder, "Analyzing classes with Ghidra");

            builder = new ProcessBuilder(
                analyzeHeadless,
                projectDirectoryPath,
                this.ghidraProjectName,
                "-postScript",
                "Ghidra-DumpMacho.py",
                projectDirectoryPath,
                "-process",
                "-noanalysis"
            );

            runGhidraProcess(builder, "Running Ghidra decompilation");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getAnalyzeHeadlessPath() {
        String analyzeHeadless = Paths.get(config.getGhidraPath(), "support", "analyzeHeadless").toString();
        if (config.isWindows()) {
            analyzeHeadless += ".bat";
        }
        return analyzeHeadless;
    }

    private void runGhidraProcess(ProcessBuilder builder, String message) throws Exception {
        System.out.println(message + ": " + builder.command().toString());
        Process process = builder.start();

        FileProcessing.readStream(process.getInputStream());
        FileProcessing.readStream(process.getErrorStream());

        process.waitFor();
        System.out.println("Finished " + message.toLowerCase());
    }
}
