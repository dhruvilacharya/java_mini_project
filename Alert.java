package com.security.threatmonitor;

import java.time.LocalDateTime;

public class Alert {
    private final LocalDateTime timestamp;
    private final String source;
    private final String message;
    private final Severity severity;

    public void setTitle(String databaseStatus) {

    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public Alert(LocalDateTime timestamp, String source, String message, Severity severity) {
        this.timestamp = timestamp;
        this.source = source;
        this.message = message;
        this.severity = severity;
    }

    // Getters
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getSource() {
        return source;
    }

    public String getMessage() {
        return message;
    }

    public Severity getSeverity() {
        return severity;
    }
} 