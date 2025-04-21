package com.security.threatmonitor;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.sql.*;
import java.time.LocalDateTime;

public class GraphicalDatabaseTest extends Application {
    
    private TextArea logsArea;
    
    public static void main(String[] args) {
        launch(args);
    }
    
    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("SQLite Database Test");
        
        BorderPane root = new BorderPane();
        
        // Create controls
        logsArea = new TextArea();
        logsArea.setEditable(false);
        logsArea.setPrefHeight(400);
        
        Button testConnectionButton = new Button("Test SQLite Connection");
        testConnectionButton.setOnAction(e -> testSqliteConnection());
        
        Button createTableButton = new Button("Create Test Table");
        createTableButton.setOnAction(e -> createTestTable());
        
        Button insertDataButton = new Button("Insert Test Data");
        insertDataButton.setOnAction(e -> insertTestData());
        
        Button queryDataButton = new Button("Query Data");
        queryDataButton.setOnAction(e -> queryData());
        
        // Create layout
        VBox buttonBox = new VBox(10);
        buttonBox.setPadding(new Insets(10));
        buttonBox.getChildren().addAll(
                testConnectionButton,
                createTableButton,
                insertDataButton,
                queryDataButton
        );
        
        root.setCenter(logsArea);
        root.setRight(buttonBox);
        
        Scene scene = new Scene(root, 800, 500);
        primaryStage.setScene(scene);
        primaryStage.show();
        
        // Print initial message
        log("SQLite Database Test Application Started");
    }
    
    private void testSqliteConnection() {
        try {
            // Load the SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            log("SQLite JDBC driver loaded successfully!");
            
            // Connect to the database
            String url = "jdbc:sqlite:graphical_test.db";
            try (Connection connection = DriverManager.getConnection(url)) {
                log("Connected to SQLite database: " + url);
                log("Database connection test successful!");
            }
        } catch (ClassNotFoundException e) {
            logError("SQLite JDBC driver not found: " + e.getMessage());
        } catch (SQLException e) {
            logError("Database error: " + e.getMessage());
        }
    }
    
    private void createTestTable() {
        String url = "jdbc:sqlite:graphical_test.db";
        
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            
            // Create a test table
            String sql = "CREATE TABLE IF NOT EXISTS alerts (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "timestamp TEXT, " + 
                    "source TEXT, " +
                    "message TEXT, " +
                    "severity TEXT)";
            
            statement.execute(sql);
            log("Test table 'alerts' created successfully!");
            
        } catch (SQLException e) {
            logError("Error creating table: " + e.getMessage());
        }
    }
    
    private void insertTestData() {
        String url = "jdbc:sqlite:graphical_test.db";
        
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            
            // Insert test data
            String timestamp = LocalDateTime.now().toString();
            String sql = "INSERT INTO alerts (timestamp, source, message, severity) " +
                    "VALUES ('" + timestamp + "', 'System', 'Test alert from UI', 'LOW')";
            
            statement.execute(sql);
            log("Test record inserted successfully!");
            
        } catch (SQLException e) {
            logError("Error inserting data: " + e.getMessage());
        }
    }
    
    private void queryData() {
        String url = "jdbc:sqlite:graphical_test.db";
        
        try (Connection connection = DriverManager.getConnection(url);
             Statement statement = connection.createStatement()) {
            
            // Query data
            String sql = "SELECT * FROM alerts ORDER BY id DESC";
            try (ResultSet resultSet = statement.executeQuery(sql)) {
                log("\nRecords in alerts table:");
                log("ID | Timestamp | Source | Message | Severity");
                log("-----------------------------------------");
                
                int count = 0;
                while (resultSet.next()) {
                    int id = resultSet.getInt("id");
                    String timestamp = resultSet.getString("timestamp");
                    String source = resultSet.getString("source");
                    String message = resultSet.getString("message");
                    String severity = resultSet.getString("severity");
                    
                    log(id + " | " + timestamp + " | " + source + " | " + message + " | " + severity);
                    count++;
                }
                
                log("\nTotal records: " + count);
            }
            
        } catch (SQLException e) {
            logError("Error querying data: " + e.getMessage());
        }
    }
    
    private void log(String message) {
        Platform.runLater(() -> {
            logsArea.appendText(message + "\n");
        });
    }
    
    private void logError(String message) {
        Platform.runLater(() -> {
            logsArea.appendText("ERROR: " + message + "\n");
        });
    }
} 