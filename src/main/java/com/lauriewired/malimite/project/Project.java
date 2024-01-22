package com.lauriewired.malimite.project;

import java.io.File;
import java.io.IOException;
import java.util.List;

import com.lauriewired.malimite.database.SQLiteDBHandler;
import com.lauriewired.malimite.decompile.GhidraProject;
import com.lauriewired.malimite.files.InfoPlist;
import com.lauriewired.malimite.files.Macho;
import com.lauriewired.malimite.utils.FileProcessing;

public class Project {
    private InfoPlist infoPlist;
    private GhidraProject ghidraProject;
    private String executableFilePath; // Path to the main macho file for this app
    private String projectDirectoryPath;
    private Macho projectMacho;
    private SQLiteDBHandler dbHandler;

    public void processAppBundle(String zipFilePath, String plistPath) {
        this.infoPlist = new InfoPlist(zipFilePath, plistPath);
        System.out.println(zipFilePath);
        System.out.println(FileProcessing.removeFileNameFromPath(zipFilePath));
        String inputFilePath = FileProcessing.removeFileNameFromPath(zipFilePath);

        // Generate / open project directory
        this.projectDirectoryPath = inputFilePath + this.infoPlist.getExecutableName() + "_malimite";
        if (FileProcessing.openProjectDirectory(this.projectDirectoryPath)) {
            System.out.println("Reopening project");
            this.executableFilePath = this.projectDirectoryPath + File.separator + this.infoPlist.getExecutableName();
        } else {
            // Do initial processing
            try {
                FileProcessing.unzipExecutable(zipFilePath, this.infoPlist.getExecutableName(), this.projectDirectoryPath);
            } catch (IOException e) {
                e.printStackTrace();
            }

            this.executableFilePath = this.projectDirectoryPath + File.separator + this.infoPlist.getExecutableName();
            this.projectMacho = new Macho(this.executableFilePath, zipFilePath, plistPath);
            this.ghidraProject = new GhidraProject(this.infoPlist.getExecutableName(), this.executableFilePath);

            // Let the user select the architecture if it is a FAT binary
            if (this.projectMacho.isFatBinary()) {
                List<String> architectures = this.projectMacho.getArchitectureStrings();
                
                /*
                String selectedArchitecture = selectArchitecture(architectures);
                if (selectedArchitecture != null) {
                    this.projectMacho.processFatMacho(selectedArchitecture);
                }*/
            }

            ghidraProject.decompileMacho(this.executableFilePath, this.projectDirectoryPath, this.projectMacho);
        }
    }

    private void populateDatabase() {
        System.out.println("Initializing database for iPax data");

        System.out.println("projectDirectoryPath: " + projectDirectoryPath);
        System.out.println("projectMacho.getMachoExecutableName(): " + projectMacho.getMachoExecutableName());

        this.dbHandler = new SQLiteDBHandler(this.projectDirectoryPath + File.separator, this.projectMacho.getMachoExecutableName() + "_ipax.db");
        dbHandler.populateInitialClassData(this.projectDirectoryPath + File.separator + "ipax_class_data.json");

        System.out.println("Finished initializing database");

        System.out.println("Adding function data to database");

        dbHandler.populateFunctionData(this.projectDirectoryPath, this.projectDirectoryPath + File.separator + "functions_info.json");

        System.out.println("Finished adding function data to database");

        //dbHandler.readClasses();
    }

}
