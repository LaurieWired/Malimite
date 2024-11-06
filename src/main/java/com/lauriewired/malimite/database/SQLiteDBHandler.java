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
                + "Functions TEXT);";  // Removed DecompilationCode from Classes

        String sqlFunctions = "CREATE TABLE IF NOT EXISTS Functions ("
                + "FunctionName TEXT,"
                + "ParentClass TEXT,"
                + "DecompilationCode TEXT,"
                + "PRIMARY KEY (FunctionName, ParentClass));";  // Composite key to allow same function name in different classes

        String sqlMachoStrings = "CREATE TABLE IF NOT EXISTS MachoStrings ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "address TEXT,"
                + "value TEXT,"
                + "segment TEXT,"
                + "label TEXT);";

        String sqlResourceStrings = "CREATE TABLE IF NOT EXISTS ResourceStrings ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "resourceId TEXT,"
                + "value TEXT,"
                + "type TEXT);";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sqlClasses);
            stmt.execute(sqlFunctions);
            stmt.execute(sqlMachoStrings);
            stmt.execute(sqlResourceStrings);
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
                   + "ON CONFLICT(FunctionName, ParentClass) "
                   + "DO UPDATE SET DecompilationCode = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setString(3, decompiledCode);
            pstmt.setString(4, decompiledCode);
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
        String sql = "INSERT INTO Classes(ClassName, Functions, ClassFileName) VALUES(?,?,NULL)";

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
                                   rs.getString("Functions"));
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void updateFunctionDecompilation(String functionName, String className, String decompiledCode) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode) "
                   + "VALUES(?, ?, ?) "
                   + "ON CONFLICT(FunctionName, ParentClass) "
                   + "DO UPDATE SET DecompilationCode = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            pstmt.setString(3, decompiledCode);
            pstmt.setString(4, decompiledCode);
            int rowsAffected = pstmt.executeUpdate();
            System.out.println("Database update for " + functionName + " affected " + rowsAffected + " rows");
            
            // Verify the update
            String verifySQL = "SELECT DecompilationCode FROM Functions WHERE FunctionName = ? AND ParentClass = ?";
            try (PreparedStatement verifyStmt = conn.prepareStatement(verifySQL)) {
                verifyStmt.setString(1, functionName);
                verifyStmt.setString(2, className);
                try (ResultSet rs = verifyStmt.executeQuery()) {
                    if (rs.next()) {
                        String storedCode = rs.getString("DecompilationCode");
                        System.out.println("Verification - Stored code matches input: " + 
                            storedCode.equals(decompiledCode));
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("Error updating function decompilation: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public String getFunctionDecompilation(String functionName, String className) {
        String sql = "SELECT DecompilationCode FROM Functions WHERE FunctionName = ? AND ParentClass = ?";
        
        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            
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

    public void insertMachoString(String address, String value, String segment, String label) {
        String sql = "INSERT INTO MachoStrings(address, value, segment, label) VALUES(?,?,?,?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, address);
            pstmt.setString(2, value);
            pstmt.setString(3, segment);
            pstmt.setString(4, label);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public List<Map<String, String>> getMachoStrings() {
        List<Map<String, String>> strings = new ArrayList<>();
        String sql = "SELECT * FROM MachoStrings";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, String> string = new HashMap<>();
                string.put("address", rs.getString("address"));
                string.put("value", rs.getString("value"));
                string.put("segment", rs.getString("segment"));
                string.put("label", rs.getString("label"));
                strings.add(string);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return strings;
    }

    public void insertResourceString(String resourceId, String value, String type) {
        String sql = "INSERT INTO ResourceStrings(resourceId, value, type) VALUES(?,?,?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, resourceId);
            pstmt.setString(2, value);
            pstmt.setString(3, type);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public List<Map<String, String>> getResourceStrings() {
        List<Map<String, String>> strings = new ArrayList<>();
        String sql = "SELECT * FROM ResourceStrings";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, String> string = new HashMap<>();
                string.put("resourceId", rs.getString("resourceId"));
                string.put("value", rs.getString("value"));
                string.put("type", rs.getString("type"));
                strings.add(string);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return strings;
    }
}
