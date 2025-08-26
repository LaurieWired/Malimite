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
    private Connection transaction;

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
        try {

            Connection transaction = DriverManager.getConnection(url);
            try (Statement walStmt = transaction.createStatement()) {
                walStmt.execute("PRAGMA journal_mode=WAL;");
                walStmt.execute("PRAGMA synchronous=OFF;");
            }
            transaction.setAutoCommit(false);
            this.transaction = transaction;
        } catch (SQLException e) {
            String msg = "Failed to create database transaction connection";
            LOGGER.log(Level.SEVERE, msg, e);
            throw new RuntimeException(msg, e);
        }

        String sqlClasses = "CREATE TABLE IF NOT EXISTS Classes ("
                + "ClassName TEXT,"
                + "Functions TEXT,"
                + "ExecutableName TEXT,"
                + "PRIMARY KEY (ClassName, ExecutableName));";

        String sqlFunctions = "CREATE TABLE IF NOT EXISTS Functions ("
                + "FunctionName TEXT,"
                + "ParentClass TEXT,"
                + "DecompilationCode TEXT,"
                + "ExecutableName TEXT,"
                + "PRIMARY KEY (FunctionName, ParentClass, ExecutableName));";

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
                + "type TEXT"
                + ");";

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

    public Connection GetTransaction() {
        return this.transaction;
    }

    public Map<String, List<String>> getAllClassesAndFunctions() {
        Map<String, List<String>> classFunctionMap = new HashMap<>();
        String sql = "SELECT ClassName, Functions, ExecutableName FROM Classes";

        try (Statement stmt = this.transaction.createStatement();
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
                String executableName = classObject.getString("executableFile");

                // Insert each function into the database
                insertFunction(functionName, className, executableName);
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error reading or parsing JSON class data file: " + e.getMessage());
        }
    }

    public void insertFunction(String functionName, String parentClass, String decompiledCode, String executableName) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode, ExecutableName) "
                + "VALUES(?,?,?,?) "
                + "ON CONFLICT(FunctionName, ParentClass, ExecutableName) "
                + "DO UPDATE SET DecompilationCode = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setString(3, decompiledCode);
            pstmt.setString(4, executableName);
            pstmt.setString(5, decompiledCode);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function", e);
        }
    }

    public void insertFunction(String functionName, String parentClass, int decompilationLine) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationLine) VALUES(?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setInt(3, decompilationLine);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function", e);
        }
    }

    public void insertClass(String className, String functions, String executableName) {
        String sql = "INSERT INTO Classes(ClassName, Functions, ExecutableName) VALUES(?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, className);
            pstmt.setString(2, functions);
            pstmt.setString(3, executableName);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting class", e);
        }
    }

    public void readClasses() {
        String sql = "SELECT * FROM Classes";

        try (Statement stmt = this.transaction.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                System.out.println(rs.getString("ExecutableName") + "\t" +
                        rs.getString("ClassName") + "\t" +
                        rs.getString("Functions"));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting classes", e);
        }
    }

    public static class DecompilationResult {
        public String functionName;
        public String className;
        public String decompiledCode;
        public String executableName;

        public DecompilationResult(String functionName, String className, String decompiledCode, String executableName) {
            this.functionName = functionName;
            this.className = className;
            this.decompiledCode = decompiledCode;
            this.executableName = executableName;
        }
    }

    public void insertFunctionDecompilations(List<DecompilationResult> results) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode, ExecutableName) "
                + "VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(FunctionName, ParentClass, ExecutableName) "
                + "DO UPDATE SET DecompilationCode = excluded.DecompilationCode";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            for (DecompilationResult result : results) {
                pstmt.setString(1, result.functionName);
                pstmt.setString(2, result.className);
                pstmt.setString(3, result.decompiledCode);
                pstmt.setString(4, result.executableName);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function decompilations", e);
        }
    }

    public void updateFunctionDecompilation(String functionName, String className, String decompiledCode,
            String executableName) {
        updateFunctionDecompilation(this.transaction, functionName, className, decompiledCode, executableName);
    }

    public void updateFunctionDecompilation(Connection transaction, String functionName, String className,
            String decompiledCode, String executableName) {
        // First, clear all existing references for this function
        clearFunctionReferences(transaction, functionName, className, executableName);

        // Update the function's decompilation code
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode, ExecutableName) "
                + "VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(FunctionName, ParentClass, ExecutableName) "
                + "DO UPDATE SET DecompilationCode = excluded.DecompilationCode";

        try (PreparedStatement pstmt = transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            pstmt.setString(3, decompiledCode);
            pstmt.setString(4, executableName);
            pstmt.executeUpdate();

            // Create a new SyntaxParser and reparse the updated function
            if (decompiledCode != null && !decompiledCode.trim().isEmpty()) {
                SyntaxParser parser = new SyntaxParser(executableName);
                parser.setContext(functionName, className);
                parser.collectCrossReferences(decompiledCode);
                this.insertFunctionReferences(parser.getFunctionRefResults());
                this.insertLocalVariableReferences(parser.getVariableRefResults());
                this.insertTypeInformations(parser.getTypeInfoResults());
            }

            transaction.commit();

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error updating function decompilation", e);
            e.printStackTrace();
        }
    }

    private void clearFunctionReferences(Connection transaction, String functionName, String className, String executableName) {
        String sqlFuncRefs = "DELETE FROM FunctionReferences WHERE sourceFunction = ? AND sourceClass = ? AND ExecutableName = ?";
        String sqlVarRefs = "DELETE FROM LocalVariableReferences WHERE containingFunction = ? AND containingClass = ? AND ExecutableName = ?";
        String sqlTypeInfo = "DELETE FROM TypeInformation WHERE functionName = ? AND className = ? AND ExecutableName = ?";

        for (String sql : new String[] { sqlFuncRefs, sqlVarRefs, sqlTypeInfo }) {
            try (PreparedStatement pstmt = transaction.prepareStatement(sql)) {
                pstmt.setString(1, functionName);
                pstmt.setString(2, className);
                pstmt.setString(3, executableName);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Error clearing function references", e);
                e.printStackTrace();
            }
        }
    }

    public String getFunctionDecompilation(String functionName, String className, String executableName) {
        String sql = "SELECT DecompilationCode FROM Functions WHERE FunctionName = ? AND ParentClass = ? AND ExecutableName = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            pstmt.setString(3, executableName);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("DecompilationCode");
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error retrieving function decompilation", e);
        }
        return null;
    }

    public void insertMachoString(String address, String value, String segment, String label, String executableName) {
        String sql = "INSERT INTO MachoStrings(address, value, segment, label, ExecutableName) VALUES(?,?,?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, address);
            pstmt.setString(2, value);
            pstmt.setString(3, segment);
            pstmt.setString(4, label);
            pstmt.setString(5, executableName);
            pstmt.executeUpdate();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting Mach-O string", e);
        }
    }

    public List<Map<String, String>> getMachoStrings() {
        List<Map<String, String>> strings = new ArrayList<>();
        String sql = "SELECT * FROM MachoStrings";

        try (Statement stmt = this.transaction.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, String> string = new HashMap<>();
                string.put("address", rs.getString("address"));
                string.put("value", rs.getString("value"));
                string.put("segment", rs.getString("segment"));
                string.put("label", rs.getString("label"));
                string.put("ExecutableName", rs.getString("ExecutableName"));
                strings.add(string);
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting Mach-O strings", e);
        }
        return strings;
    }

    public void insertResourceString(String resourceId, String value, String type) {
        String sql = "INSERT INTO ResourceStrings(resourceId, value, type) VALUES(?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, resourceId);
            pstmt.setString(2, value);
            pstmt.setString(3, type);
            pstmt.executeUpdate();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting resource string", e);
        }
    }

    public List<Map<String, String>> getResourceStrings() {
        List<Map<String, String>> strings = new ArrayList<>();
        String sql = "SELECT * FROM ResourceStrings";

        try (Statement stmt = this.transaction.createStatement();
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

    public void insertFunctionReferences(List<SyntaxParser.FunctionRefResult> functionRefs) {
        Connection conn = this.transaction;
        try {
            String sql = "INSERT INTO FunctionReferences(sourceFunction, sourceClass, "
                    + "targetFunction, targetClass, lineNumber, ExecutableName) "
                    + "SELECT ?, ?, ?, ?, ?, ? "
                    + "WHERE NOT EXISTS (SELECT 1 FROM FunctionReferences "
                    + "WHERE sourceFunction = ? AND sourceClass = ? "
                    + "AND targetFunction = ? AND targetClass = ? "
                    + "AND lineNumber = ? AND ExecutableName = ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                for (SyntaxParser.FunctionRefResult ref : functionRefs) {
                    // Parameters for INSERT
                    pstmt.setString(1, ref.sourceFunction);
                    pstmt.setString(2, ref.sourceClass);
                    pstmt.setString(3, ref.targetFunction);
                    pstmt.setString(4, ref.targetClass);
                    pstmt.setInt(5, ref.lineNumber);
                    pstmt.setString(6, ref.executableName);
                    // Parameters for WHERE NOT EXISTS
                    pstmt.setString(7, ref.sourceFunction);
                    pstmt.setString(8, ref.sourceClass);
                    pstmt.setString(9, ref.targetFunction);
                    pstmt.setString(10, ref.targetClass);
                    pstmt.setInt(11, ref.lineNumber);
                    pstmt.setString(12, ref.executableName);
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }

            conn.commit();
        } catch (

        SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function references", e);
        }
    }

    public void insertFunctionReference(Connection transaction, String sourceFunction, String sourceClass,
            String targetFunction, String targetClass, int lineNumber, String executableName) {
        String sql = "INSERT INTO FunctionReferences(sourceFunction, sourceClass, "
                + "targetFunction, targetClass, lineNumber, ExecutableName) "
                + "SELECT ?, ?, ?, ?, ?, ? "
                + "WHERE NOT EXISTS (SELECT 1 FROM FunctionReferences "
                + "WHERE sourceFunction = ? AND sourceClass = ? "
                + "AND targetFunction = ? AND targetClass = ? "
                + "AND lineNumber = ? AND ExecutableName = ?)";

        try (PreparedStatement pstmt = transaction.prepareStatement(sql)) {
            // Parameters for INSERT
            pstmt.setString(1, sourceFunction);
            pstmt.setString(2, sourceClass);
            pstmt.setString(3, targetFunction);
            pstmt.setString(4, targetClass);
            pstmt.setInt(5, lineNumber);
            pstmt.setString(6, executableName);
            // Parameters for WHERE NOT EXISTS
            pstmt.setString(7, sourceFunction);
            pstmt.setString(8, sourceClass);
            pstmt.setString(9, targetFunction);
            pstmt.setString(10, targetClass);
            pstmt.setInt(11, lineNumber);
            pstmt.setString(12, executableName);
            pstmt.executeUpdate();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function reference", e);
        }
    }

    public void insertLocalVariableReferences(List<SyntaxParser.VariableRefResult> refs) {
        String sql = "INSERT OR IGNORE INTO LocalVariableReferences(variableName, containingFunction, "
                + "containingClass, lineNumber, ExecutableName) VALUES (?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            for (SyntaxParser.VariableRefResult ref : refs) {
                pstmt.setString(1, ref.variableName);
                pstmt.setString(2, ref.functionName);
                pstmt.setString(3, ref.className);
                pstmt.setInt(4, ref.lineNumber);
                pstmt.setString(5, ref.executableName);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting local variable references", e);
        }
    }

    public void insertLocalVariableReference(Connection transaction, String variableName, String containingFunction,
            String containingClass, int lineNumber, String executableName) {
        String sql = "INSERT INTO LocalVariableReferences(variableName, containingFunction, "
                + "containingClass, lineNumber, ExecutableName) "
                + "SELECT ?, ?, ?, ?, ? "
                + "WHERE NOT EXISTS (SELECT 1 FROM LocalVariableReferences "
                + "WHERE variableName = ? AND containingFunction = ? "
                + "AND containingClass = ? AND lineNumber = ? AND ExecutableName = ?)";

        try (PreparedStatement pstmt = transaction.prepareStatement(sql)) {
            // Parameters for INSERT
            pstmt.setString(1, variableName);
            pstmt.setString(2, containingFunction);
            pstmt.setString(3, containingClass);
            pstmt.setInt(4, lineNumber);
            pstmt.setString(5, executableName);
            // Parameters for WHERE NOT EXISTS
            pstmt.setString(6, variableName);
            pstmt.setString(7, containingFunction);
            pstmt.setString(8, containingClass);
            pstmt.setInt(9, lineNumber);
            pstmt.setString(10, executableName);
            pstmt.executeUpdate();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting local variable reference", e);
        }
    }

    public List<Map<String, String>> getFunctionCrossReferences(String functionName) {
        List<Map<String, String>> references = new ArrayList<>();

        String sql = "SELECT 'FUNCTION' as refType, sourceFunction, sourceClass, "
                + "targetFunction as target, targetClass, lineNumber FROM FunctionReferences WHERE "
                + "targetFunction = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {

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

    public List<Map<String, String>> getTypeInformation(String functionName, String className, String executableName) {
        List<Map<String, String>> types = new ArrayList<>();
        String sql = "SELECT * FROM TypeInformation WHERE functionName = ? AND className = ? AND ExecutableName = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, className);
            pstmt.setString(3, executableName);

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

    public void insertTypeInformations(List<SyntaxParser.TypeInfoResult> typeInfos) {
        String sql = "INSERT INTO TypeInformation(variableName, variableType, functionName, "
                + "className, lineNumber, ExecutableName) VALUES(?,?,?,?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            for (SyntaxParser.TypeInfoResult info : typeInfos) {
                pstmt.setString(1, info.variableName);
                pstmt.setString(2, info.variableType);
                pstmt.setString(3, info.functionName);
                pstmt.setString(4, info.className);
                pstmt.setInt(5, info.lineNumber);
                pstmt.setString(6, info.executableName);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            this.transaction.commit();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting type information", e);
        }
    }

    public void insertTypeInformation(Connection transaction, String variableName, String variableType,
            String functionName, String className, int lineNumber, String executableName) {
        String sql = "INSERT INTO TypeInformation(variableName, variableType, functionName, "
                + "className, lineNumber, ExecutableName) VALUES(?,?,?,?,?,?)";

        try (PreparedStatement pstmt = transaction.prepareStatement(sql)) {
            pstmt.setString(1, variableName);
            pstmt.setString(2, variableType);
            pstmt.setString(3, functionName);
            pstmt.setString(4, className);
            pstmt.setInt(5, lineNumber);
            pstmt.setString(6, executableName);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting type information", e);
        }
    }

    public List<Map<String, String>> getLocalVariableReferences(String variableName, String className,
            String functionName, String executableName) {
        List<Map<String, String>> references = new ArrayList<>();
        String sql = "SELECT * FROM LocalVariableReferences WHERE variableName = ? "
                + "AND containingClass = ? "
                + "AND containingFunction = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
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

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);

            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error checking function name", e);
            return false;
        }
    }

    public void insertFunction(String functionName, String parentClass, String executableName) {
        String sql = "INSERT INTO Functions(FunctionName, ParentClass, ExecutableName) VALUES(?,?,?)";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, functionName);
            pstmt.setString(2, parentClass);
            pstmt.setString(3, executableName);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error inserting function", e);
        }
    }

    public String getExecutableNameForClass(String className) {
        String sql = "SELECT ExecutableName FROM Classes WHERE ClassName = ?";

        try (PreparedStatement pstmt = this.transaction.prepareStatement(sql)) {
            pstmt.setString(1, className);

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("ExecutableName");
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error retrieving executable name for class", e);
        }
        return null;
    }

    public List<Map<String, String>> searchCodebase(String searchTerm) {
        List<Map<String, String>> results = new ArrayList<>();
        String termPattern = "%" + searchTerm.toLowerCase() + "%";

        // Search in Functions
        String sqlFunctions = "SELECT 'Function' as type, FunctionName as name, "
                + "ParentClass as container, ExecutableName "
                + "FROM Functions WHERE LOWER(FunctionName) LIKE ?";

        // Search in LocalVariableReferences
        String sqlVariables = "SELECT 'Variable' as type, variableName as name, "
                + "containingFunction || ' in ' || containingClass as container, "
                + "ExecutableName, lineNumber "
                + "FROM LocalVariableReferences WHERE LOWER(variableName) LIKE ?";

        // Search in Classes
        String sqlClasses = "SELECT 'Class' as type, ClassName as name, "
                + "ExecutableName as container, ExecutableName "
                + "FROM Classes WHERE LOWER(ClassName) LIKE ?";

        Connection conn = this.transaction;
        try {
            // Search Functions
            try (PreparedStatement pstmt = this.transaction.prepareStatement(sqlFunctions)) {
                pstmt.setString(1, termPattern);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, String> result = new HashMap<>();
                        result.put("type", rs.getString("type"));
                        result.put("name", rs.getString("name"));
                        result.put("container", rs.getString("container"));
                        result.put("executable", rs.getString("ExecutableName"));
                        result.put("line", "");
                        results.add(result);
                    }
                }
            }

            // Search Variables
            try (PreparedStatement pstmt = conn.prepareStatement(sqlVariables)) {
                pstmt.setString(1, termPattern);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, String> result = new HashMap<>();
                        result.put("type", rs.getString("type"));
                        result.put("name", rs.getString("name"));
                        result.put("container", rs.getString("container"));
                        result.put("executable", rs.getString("ExecutableName"));
                        result.put("line", rs.getString("lineNumber"));
                        results.add(result);
                    }
                }
            }

            // Search Classes
            try (PreparedStatement pstmt = conn.prepareStatement(sqlClasses)) {
                pstmt.setString(1, termPattern);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, String> result = new HashMap<>();
                        result.put("type", rs.getString("type"));
                        result.put("name", rs.getString("name"));
                        result.put("container", rs.getString("container"));
                        result.put("executable", rs.getString("ExecutableName"));
                        result.put("line", "");
                        results.add(result);
                    }
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error searching codebase", e);
        }

        return results;
    }

    public Map<String, List<String>> getMainExecutableClasses(String infoPlistExecutableName) {
        Map<String, List<String>> classFunctionMap = new HashMap<>();
        String sql = "SELECT ClassName, Functions FROM Classes WHERE ExecutableName = ?";

        Connection conn = this.transaction;
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, infoPlistExecutableName);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    String className = rs.getString("ClassName");
                    String functionsJson = rs.getString("Functions");
                    List<String> functions = parseFunctions(functionsJson);
                    classFunctionMap.put(className, functions);
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Error getting main executable classes", e);
        }
        return classFunctionMap;
    }
}
