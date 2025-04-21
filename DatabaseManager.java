package com.security.threatmonitor;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DatabaseManager {
    private static final Logger logger = Logger.getLogger(DatabaseManager.class.getName());
    private Connection connection;
    private final String dbUrl;
    private final String username;
    private final String password;

    // SQL statements
    private static final String CREATE_ALERTS_TABLE =
            "CREATE TABLE IF NOT EXISTS alerts (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "timestamp TIMESTAMP, " +
                    "source VARCHAR(100), " +
                    "message TEXT, " +
                    "severity VARCHAR(20))";

    private static final String INSERT_ALERT =
            "INSERT INTO alerts (timestamp, source, message, severity) " +
                    "VALUES (?, ?, ?, ?)";

    private static final String SELECT_ALERTS =
            "SELECT timestamp, source, message, severity FROM alerts " +
                    "ORDER BY timestamp DESC LIMIT ?";

    private static final String COUNT_ALERTS_BY_SEVERITY =
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity";

    private static final String DELETE_OLD_ALERTS =
            "DELETE FROM alerts WHERE timestamp < ?";

    public DatabaseManager(String dbUrl, String username, String password) {
        this.dbUrl = dbUrl;
        this.username = username;
        this.password = password;
    }

    public void initialize() {
        try {
            // Load the SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");

            // Create connection (will create the database if it doesn't exist)
            connection = DriverManager.getConnection(dbUrl);
            logger.info("Connected to database: " + dbUrl);

            // Create tables if they don't exist
            try (Statement statement = connection.createStatement()) {
                statement.execute(CREATE_ALERTS_TABLE);
                logger.info("Alerts table created or already exists");
            }
        } catch (ClassNotFoundException e) {
            logger.log(Level.SEVERE, "JDBC driver not found", e);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error initializing database", e);
        }
    }

    public void storeAlert(Alert alert) {
        try (PreparedStatement statement = connection.prepareStatement(INSERT_ALERT)) {
            statement.setTimestamp(1, Timestamp.valueOf(alert.getTimestamp()));
            statement.setString(2, alert.getSource());
            statement.setString(3, alert.getMessage());
            statement.setString(4, alert.getSeverity().toString());
            statement.executeUpdate();
        } catch (SQLException e) {
            logger.log(Level.WARNING, "Error storing alert in database", e);
        }
    }

    public List<AlertEntry> getRecentAlerts(int limit) {
        List<AlertEntry> alerts = new ArrayList<>();

        try (PreparedStatement statement = connection.prepareStatement(SELECT_ALERTS)) {
            statement.setInt(1, limit);

            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    LocalDateTime timestamp = resultSet.getTimestamp("timestamp").toLocalDateTime();
                    String source = resultSet.getString("source");
                    String message = resultSet.getString("message");
                    Alert.Severity severity = Alert.Severity.valueOf(resultSet.getString("severity"));

                    alerts.add(new AlertEntry(
                            timestamp, source, message, severity));
                }
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "Error retrieving alerts from database", e);
        }

        return alerts;
    }

    public void cleanupOldAlerts(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);

        try (PreparedStatement statement = connection.prepareStatement(DELETE_OLD_ALERTS)) {
            statement.setTimestamp(1, Timestamp.valueOf(cutoffDate));
            int rowsDeleted = statement.executeUpdate();
            logger.info("Deleted " + rowsDeleted + " alerts older than " + daysToKeep + " days");
        } catch (SQLException e) {
            logger.log(Level.WARNING, "Error cleaning up old alerts", e);
        }
    }

    public void close() {
        if (connection != null) {
            try {
                connection.close();
                logger.info("Database connection closed");
            } catch (SQLException e) {
                logger.log(Level.WARNING, "Error closing database connection", e);
            }
        }
    }

    public int[] getAlertCountsBySeverity() {
        int[] counts = new int[4]; // LOW, MEDIUM, HIGH, CRITICAL

        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(COUNT_ALERTS_BY_SEVERITY)) {

            while (resultSet.next()) {
                String severity = resultSet.getString("severity");
                int count = resultSet.getInt("count");

                switch (Alert.Severity.valueOf(severity)) {
                    case LOW:
                        counts[0] = count;
                        break;
                    case MEDIUM:
                        counts[1] = count;
                        break;
                    case HIGH:
                        counts[2] = count;
                        break;
                    case CRITICAL:
                        counts[3] = count;
                        break;
                }
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "Error retrieving alert counts by severity", e);
        }

        return counts;
    }
    
    public static class AlertEntry {
        private final LocalDateTime timestamp;
        private final String source;
        private final String message;
        private final Alert.Severity severity;

        public AlertEntry(LocalDateTime timestamp, String source, String message, Alert.Severity severity) {
            this.timestamp = timestamp;
            this.source = source;
            this.message = message;
            this.severity = severity;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        public String getSource() {
            return source;
        }

        public String getMessage() {
            return message;
        }

        public Alert.Severity getSeverity() {
            return severity;
        }
    }
} 