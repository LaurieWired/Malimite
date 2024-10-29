package com.lauriewired.malimite.database;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

public class SQLiteDBHandler { 
    private String url;

    /*
     *  SQLiteDBHandler dbHandler = new SQLiteDBHandler("mydatabase.db");
        dbHandler.insertClass("example.c", "ExampleClass", "[function1, function2]", "void function1() {...}");
        dbHandler.readClasses();
     */

    public SQLiteDBHandler(String dbPath, String dbName) {
        this.url = "jdbc:sqlite:" + dbPath + dbName;
        initializeDatabase();
    }

    private void initializeDatabase() {
        String sqlClasses = "CREATE TABLE IF NOT EXISTS Classes ("
                + "ClassName TEXT PRIMARY KEY,"
                + "ClassFileName TEXT,"
                + "Functions TEXT,"
                + "DecompilationCode TEXT);";  // Application file format

        String sqlFunctions = "CREATE TABLE IF NOT EXISTS Functions ("
                + "FunctionName TEXT PRIMARY KEY,"
                + "ClassFileName TEXT,"
                + "ParentClass TEXT,"
                + "DecompilationLine INTEGER);";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement()) {
            // Create tables
            stmt.execute(sqlClasses);
            stmt.execute(sqlFunctions);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Map<String, List<String>> getAllClassesAndFunctions() {
        Map<String, List<String>> classFunctionMap = new HashMap<>();
        String sql = "SELECT ClassName, Functions FROM Classes";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                String className = rs.getString("ClassName");
                String functionsJson = rs.getString("Functions");
                List<String> functions = parseFunctions(functionsJson);
                classFunctionMap.put(className, functions);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return classFunctionMap;
    }

    private List<String> parseFunctions(String json) {
        // Assuming the JSON is in the format: ["function1", "function2", ...]
        try {
            JSONArray jsonArray = new JSONArray(json);
            List<String> functions = new ArrayList<>();
            for (int i = 0; i < jsonArray.length(); i++) {
                functions.add(jsonArray.getString(i));
            }
            return functions;
        } catch (JSONException e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    public void populateFunctionData(String pathToClassFiles, String pathToFunctionDataJson) {
        try {
            // Read the entire JSON file into a String
            String jsonData = new String(Files.readAllBytes(new File(pathToFunctionDataJson).toPath()), StandardCharsets.UTF_8);

            // Parse the JSON data
            JSONArray functionsArray = new JSONArray(new JSONTokener(jsonData));

            // Iterate over each class in the JSON array
            for (int i = 0; i < functionsArray.length(); i++) {
                JSONObject classObject = functionsArray.getJSONObject(i);
                String functionName = classObject.getString("FunctionName");
                String className = classObject.getString("ClassName");
                String classFileName = classObject.getString("ClassFileName");

                // Insert each function into the database
                insertFunction(functionName, className, classFileName);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error reading or parsing JSON class data file: " + e.getMessage());
        }
    }

    public void insertFunction(String functionName, String parentClass, String decompiledCode) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode) "
                   + "VALUES(?,?,?) "
                   + "ON CONFLICT(FunctionName) "
                   + "DO UPDATE SET DecompilationCode = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setString(3, decompiledCode);
            pstmt.setString(4, decompiledCode);  // Value for UPDATE case
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertFunction(String functionName, String parentClass, int decompilationLine) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationLine) VALUES(?,?,?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setInt(3, decompilationLine);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void populateInitialClassData(String pathToClassDataJson) {
        try {
            // Read the entire JSON file into a String
            String jsonData = new String(Files.readAllBytes(new File(pathToClassDataJson).toPath()), StandardCharsets.UTF_8);

            // Parse the JSON data
            JSONArray classesArray = new JSONArray(new JSONTokener(jsonData));

            // Iterate over each class in the JSON array
            for (int i = 0; i < classesArray.length(); i++) {
                JSONObject classObject = classesArray.getJSONObject(i);
                String className = classObject.getString("ClassName");
                String functions = classObject.getString("Functions");

                // Insert each class into the database
                insertClass(className, functions);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error reading or parsing JSON class data file: " + e.getMessage());
        }
    }

    public void insertClass(String className, String functions) {
        String sql = "INSERT INTO Classes(ClassName, Functions, ClassFileName, DecompilationCode) VALUES(?,?,NULL,NULL)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, className);
            pstmt.setString(2, functions);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void insertClass(String classFileName, String className, String functions, String decompilationCode) {
        String sql = "INSERT INTO Classes(ClassFileName, ClassName, Functions, DecompilationCode) VALUES(?,?,?,?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, classFileName);
            pstmt.setString(2, className);
            pstmt.setString(3, functions);
            pstmt.setString(4, decompilationCode);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void readClasses() {
        String sql = "SELECT * FROM Classes";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                System.out.println(rs.getString("ClassFileName") + "\t" +
                                   rs.getString("ClassName") + "\t" +
                                   rs.getString("Functions") + "\t" +
                                   rs.getString("DecompilationCode"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void updateClassDecompilation(String className, String decompiledCode) {
        String sql = "UPDATE Classes SET DecompilationCode = ? WHERE ClassName = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, decompiledCode);
            pstmt.setString(2, className);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public String getClassDecompilation(String className) {
        String sql = "SELECT DecompilationCode FROM Classes WHERE ClassName = ?";
        
        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, className);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("DecompilationCode");
                }
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }
}
