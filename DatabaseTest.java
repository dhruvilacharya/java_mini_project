package com.security.threatmonitor;

import java.time.LocalDateTime;

public class DatabaseTest {
    public static void main(String[] args) {
        System.out.println("Testing database connection...");
        
        try {
            // Create and initialize database manager
            DatabaseManager dbManager = new DatabaseManager("jdbc:sqlite:threatmonitor.db", "", "");
            dbManager.initialize();
            System.out.println("Database initialized successfully!");
            
            // Create and store a test alert
            Alert testAlert = new Alert(
                LocalDateTime.now(),
                "Database Test",
                "This is a test alert to verify database connection",
                Alert.Severity.MEDIUM
            );
            
            dbManager.storeAlert(testAlert);
            System.out.println("Test alert stored successfully!");
            
            // Retrieve alerts to verify storage
            System.out.println("Retrieving alerts from database:");
            for (DatabaseManager.AlertEntry entry : dbManager.getRecentAlerts(10)) {
                System.out.println(entry.getTimestamp() + " [" + entry.getSeverity() + "] " + 
                                  entry.getSource() + ": " + entry.getMessage());
            }
            
            // Print alert counts by severity
            int[] counts = dbManager.getAlertCountsBySeverity();
            System.out.println("\nAlert counts by severity:");
            System.out.println("LOW: " + counts[0]);
            System.out.println("MEDIUM: " + counts[1]);
            System.out.println("HIGH: " + counts[2]);
            System.out.println("CRITICAL: " + counts[3]);
            
            // Close the database connection
            dbManager.close();
            System.out.println("\nDatabase connection closed successfully!");
            
        } catch (Exception e) {
            System.err.println("Error during database test: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 