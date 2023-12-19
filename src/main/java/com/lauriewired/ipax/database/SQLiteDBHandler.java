package com.lauriewired.ipax.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SQLiteDBHandler { 
    private String url;

    /*
     *  SQLiteDBHandler dbHandler = new SQLiteDBHandler("mydatabase.db");
        dbHandler.insertClass("example.c", "ExampleClass", "[function1, function2]", "void function1() {...}");
        dbHandler.readClasses();
     */

    public SQLiteDBHandler(String dbName) {
        this.url = "jdbc:sqlite:" + dbName;
        initializeDatabase();
    }

    private void initializeDatabase() {
        String sqlClasses = "CREATE TABLE IF NOT EXISTS Classes ("
                + "ClassFileName TEXT PRIMARY KEY,"
                + "ClassName TEXT,"
                + "Functions TEXT,"  // Assuming a serialized list of function names
                + "DecompilationCode TEXT);";  // Application file format

        String sqlFunctions = "CREATE TABLE IF NOT EXISTS Functions ("
                + "FunctionName TEXT PRIMARY KEY,"
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

    public void populateFromProjectDirectory() {
        //TODO: read in the json  and .c files from the project directory and populate DB
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
}
