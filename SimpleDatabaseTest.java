package com.security.threatmonitor;

import java.sql.*;
import java.time.LocalDateTime;

public class SimpleDatabaseTest {
    public static void main(String[] args) {
        System.out.println("Testing SQLite JDBC Connection...");
        
        try {
            // Load the SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            System.out.println("SQLite JDBC driver loaded successfully!");
            
            // Connect to a test database
            String url = "jdbc:sqlite:test.db";
            try (Connection conn = DriverManager.getConnection(url)) {
                System.out.println("Connected to SQLite database successfully!");
                
                // Create a test table
                try (Statement stmt = conn.createStatement()) {
                    // Create a test table if it doesn't exist
                    String createTableSQL = "CREATE TABLE IF NOT EXISTS test_alerts (" +
                            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                            "timestamp TEXT, " +
                            "source TEXT, " +
                            "message TEXT, " +
                            "severity TEXT)";
                    stmt.execute(createTableSQL);
                    System.out.println("Test table created successfully!");
                    
                    // Insert a test record
                    String timestamp = LocalDateTime.now().toString();
                    String insertSQL = "INSERT INTO test_alerts (timestamp, source, message, severity) " +
                            "VALUES ('" + timestamp + "', 'Test', 'Test alert message', 'MEDIUM')";
                    stmt.execute(insertSQL);
                    System.out.println("Test record inserted successfully!");
                    
                    // Query the data
                    String selectSQL = "SELECT * FROM test_alerts";
                    try (ResultSet rs = stmt.executeQuery(selectSQL)) {
                        System.out.println("\nRecords in test_alerts table:");
                        while (rs.next()) {
                            int id = rs.getInt("id");
                            String ts = rs.getString("timestamp");
                            String source = rs.getString("source");
                            String message = rs.getString("message");
                            String severity = rs.getString("severity");
                            
                            System.out.println(id + " | " + ts + " | " + source + " | " + 
                                    message + " | " + severity);
                        }
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC driver not found: " + e.getMessage());
            e.printStackTrace();
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 