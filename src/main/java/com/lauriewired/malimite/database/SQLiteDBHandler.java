package com.lauriewired.malimite.database;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.lauriewired.malimite.decompile.SyntaxParser;

public class SQLiteDBHandler { 
    private String url;
    private static final Logger LOGGER = Logger.getLogger(SQLiteDBHandler.class.getName());

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
                + "ExecutableName TEXT);";

        String sqlFunctions = "CREATE TABLE IF NOT EXISTS Functions ("
                + "FunctionName TEXT,"
                + "ParentClass TEXT,"
                + "DecompilationCode TEXT,"
                + "ExecutableName TEXT,"
                + "PRIMARY KEY (FunctionName, ParentClass));";

        String sqlMachoStrings = "CREATE TABLE IF NOT EXISTS MachoStrings ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "address TEXT,"
                + "value TEXT,"
                + "segment TEXT,"
                + "label TEXT,"
                + "ExecutableName TEXT);";

        String sqlResourceStrings = "CREATE TABLE IF NOT EXISTS ResourceStrings ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "resourceId TEXT,"
                + "value TEXT,"
                + "type TEXT,"
                + "ExecutableName TEXT);";

        String sqlFunctionReferences = "CREATE TABLE IF NOT EXISTS FunctionReferences ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "sourceFunction TEXT,"
            + "sourceClass TEXT,"
            + "targetFunction TEXT,"
            + "targetClass TEXT,"
            + "lineNumber INTEGER,"
            + "ExecutableName TEXT,"
            + "FOREIGN KEY(sourceFunction, sourceClass) REFERENCES Functions(FunctionName, ParentClass),"
            + "FOREIGN KEY(targetFunction, targetClass) REFERENCES Functions(FunctionName, ParentClass)"
            + ");";

        String sqlLocalVariableReferences = "CREATE TABLE IF NOT EXISTS LocalVariableReferences ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "variableName TEXT,"
            + "containingFunction TEXT,"
            + "containingClass TEXT,"
            + "lineNumber INTEGER,"
            + "ExecutableName TEXT,"
            + "FOREIGN KEY(containingFunction, containingClass) REFERENCES Functions(FunctionName, ParentClass)"
            + ");";

        String sqlTypeInformation = "CREATE TABLE IF NOT EXISTS TypeInformation ("
            + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            + "variableName TEXT,"
            + "variableType TEXT,"
            + "functionName TEXT,"
            + "className TEXT,"
            + "lineNumber INTEGER,"
            + "ExecutableName TEXT,"
            + "FOREIGN KEY(functionName, className) REFERENCES Functions(FunctionName, ParentClass)"
            + ");";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sqlClasses);
            stmt.execute(sqlFunctions);
            stmt.execute(sqlMachoStrings);
            stmt.execute(sqlResourceStrings);
            stmt.execute(sqlFunctionReferences);
            stmt.execute(sqlLocalVariableReferences);
            stmt.execute(sqlTypeInformation);
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Database initialization error", e);
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
            LOGGER.log(Level.SEVERE, "Error getting all classes and functions", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting function", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting function", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting class", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting class", e);
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
            LOGGER.log(Level.SEVERE, "Error getting classes", e);
        }
    }

    public void updateFunctionDecompilation(String functionName, String className, String decompiledCode) {
        // First, clear all existing references for this function
        clearFunctionReferences(functionName, className);
        
        // Update the function's decompilation code
        String sql = "UPDATE Functions SET DecompilationCode = ? "
                   + "WHERE FunctionName = ? AND ParentClass = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, decompiledCode);
            pstmt.setString(2, functionName);
            pstmt.setString(3, className);
            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected == 0) {
                // If no rows were updated, insert a new record
                sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode) VALUES(?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(sql)) {
                    insertStmt.setString(1, functionName);
                    insertStmt.setString(2, className);
                    insertStmt.setString(3, decompiledCode);
                    rowsAffected = insertStmt.executeUpdate();
                }
            }
            
            // Create a new SyntaxParser and reparse the updated function
            if (decompiledCode != null && !decompiledCode.trim().isEmpty()) {
                SyntaxParser parser = new SyntaxParser(this);
                parser.setContext(functionName, className);
                parser.collectCrossReferences(decompiledCode);
            }
            
            LOGGER.info("Database update for " + functionName + " affected " + rowsAffected + " rows");
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error updating function decompilation", e);
            e.printStackTrace();
        }
    }

    private void clearFunctionReferences(String functionName, String className) {
        // Delete from FunctionReferences where this function is the source
        String sqlFuncRefs = "DELETE FROM FunctionReferences WHERE sourceFunction = ? AND sourceClass = ?";
        
        // Delete from LocalVariableReferences for this function
        String sqlVarRefs = "DELETE FROM LocalVariableReferences WHERE containingFunction = ? AND containingClass = ?";
        
        // Delete from TypeInformation for this function
        String sqlTypeInfo = "DELETE FROM TypeInformation WHERE functionName = ? AND className = ?";
        
        try (Connection conn = DriverManager.getConnection(url)) {
            // Clear function references
            try (PreparedStatement pstmt = conn.prepareStatement(sqlFuncRefs)) {
                pstmt.setString(1, functionName);
                pstmt.setString(2, className);
                pstmt.executeUpdate();
            }
            
            // Clear variable references
            try (PreparedStatement pstmt = conn.prepareStatement(sqlVarRefs)) {
                pstmt.setString(1, functionName);
                pstmt.setString(2, className);
                pstmt.executeUpdate();
            }
            
            // Clear type information
            try (PreparedStatement pstmt = conn.prepareStatement(sqlTypeInfo)) {
                pstmt.setString(1, functionName);
                pstmt.setString(2, className);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error clearing function references", e);
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
            LOGGER.log(Level.SEVERE, "Error getting function decompilation", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting Mach-O string", e);
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
            LOGGER.log(Level.SEVERE, "Error getting Mach-O strings", e);
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
            LOGGER.log(Level.SEVERE, "Error inserting resource string", e);
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
            LOGGER.log(Level.SEVERE, "Error getting resource strings", e);
        }
        return strings;
    }

    public void insertFunctionReference(String sourceFunction, String sourceClass, 
                                      String targetFunction, String targetClass, int lineNumber) {
        String sql = "INSERT INTO FunctionReferences(sourceFunction, sourceClass, "
                   + "targetFunction, targetClass, lineNumber) "
                   + "SELECT ?, ?, ?, ?, ? "
                   + "WHERE NOT EXISTS (SELECT 1 FROM FunctionReferences "
                   + "WHERE sourceFunction = ? AND sourceClass = ? "
                   + "AND targetFunction = ? AND targetClass = ? "
                   + "AND lineNumber = ?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            // Parameters for INSERT
            pstmt.setString(1, sourceFunction);
            pstmt.setString(2, sourceClass);
            pstmt.setString(3, targetFunction);
            pstmt.setString(4, targetClass);
            pstmt.setInt(5, lineNumber);
            // Parameters for WHERE NOT EXISTS
            pstmt.setString(6, sourceFunction);
            pstmt.setString(7, sourceClass);
            pstmt.setString(8, targetFunction);
            pstmt.setString(9, targetClass);
            pstmt.setInt(10, lineNumber);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function reference", e);
        }
    }

    public void insertLocalVariableReference(String variableName, String containingFunction, 
                                           String containingClass, int lineNumber) {
        String sql = "INSERT INTO LocalVariableReferences(variableName, containingFunction, "
                   + "containingClass, lineNumber) "
                   + "SELECT ?, ?, ?, ? "
                   + "WHERE NOT EXISTS (SELECT 1 FROM LocalVariableReferences "
                   + "WHERE variableName = ? AND containingFunction = ? "
                   + "AND containingClass = ? AND lineNumber = ?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            // Parameters for INSERT
            pstmt.setString(1, variableName);
            pstmt.setString(2, containingFunction);
            pstmt.setString(3, containingClass);
            pstmt.setInt(4, lineNumber);
            // Parameters for WHERE NOT EXISTS
            pstmt.setString(5, variableName);
            pstmt.setString(6, containingFunction);
            pstmt.setString(7, containingClass);
            pstmt.setInt(8, lineNumber);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting local variable reference", e);
        }
    }

    public List<Map<String, String>> getFunctionCrossReferences(String functionName) {
        List<Map<String, String>> references = new ArrayList<>();
        
        String sql = "SELECT 'FUNCTION' as refType, sourceFunction, sourceClass, "
                  + "targetFunction as target, targetClass, lineNumber FROM FunctionReferences WHERE "
                  + "targetFunction = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, functionName);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> reference = new HashMap<>();
                    reference.put("referenceType", rs.getString("refType"));
                    reference.put("sourceFunction", rs.getString("sourceFunction"));
                    reference.put("sourceClass", rs.getString("sourceClass"));
                    reference.put("targetFunction", rs.getString("target"));
                    reference.put("targetClass", rs.getString("targetClass"));
                    reference.put("lineNumber", String.valueOf(rs.getInt("lineNumber")));
                    references.add(reference);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting function cross references", e);
        }
        return references;
    }

    public List<Map<String, String>> getTypeInformation(String functionName, String className) {
        List<Map<String, String>> types = new ArrayList<>();
        String sql = "SELECT * FROM TypeInformation WHERE functionName = ? AND className = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> type = new HashMap<>();
                    type.put("variableName", rs.getString("variableName"));
                    type.put("variableType", rs.getString("variableType"));
                    type.put("lineNumber", String.valueOf(rs.getInt("lineNumber")));
                    types.add(type);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting type information", e);
        }
        return types;
    }

    public void insertTypeInformation(String variableName, String variableType, 
                                    String functionName, String className, int lineNumber) {
        String sql = "INSERT INTO TypeInformation(variableName, variableType, functionName, "
                   + "className, lineNumber) VALUES(?,?,?,?,?)";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, variableName);
            pstmt.setString(2, variableType);
            pstmt.setString(3, functionName);
            pstmt.setString(4, className);
            pstmt.setInt(5, lineNumber);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting type information", e);
        }
    }

    public List<Map<String, String>> getLocalVariableReferences(String variableName, String className, String functionName) {
        List<Map<String, String>> references = new ArrayList<>();
        String sql = "SELECT * FROM LocalVariableReferences WHERE variableName = ? "
                   + "AND containingClass = ? "
                   + "AND containingFunction = ?";

        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, variableName);
            pstmt.setString(2, className);
            pstmt.setString(3, functionName);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> reference = new HashMap<>();
                    reference.put("variableName", rs.getString("variableName"));
                    reference.put("containingFunction", rs.getString("containingFunction"));
                    reference.put("containingClass", rs.getString("containingClass"));
                    reference.put("lineNumber", String.valueOf(rs.getInt("lineNumber")));
                    references.add(reference);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting local variable references", e);
            e.printStackTrace();
        }
        return references;
    }

    public boolean isFunctionName(String functionName) {
        String sql = "SELECT 1 FROM Functions WHERE FunctionName = ?";
        
        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error checking function name", e);
            return false;
        }
    }
}
