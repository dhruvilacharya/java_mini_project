package com.security.threatmonitor;

import javafx.application.Platform;
import javafx.collections.ObservableList;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AlertManager {
    private static final Logger logger = Logger.getLogger(AlertManager.class.getName());
    
    private final BlockingQueue<Alert> alertQueue;
    private final Map<Alert.Severity, List<AlertHandler>> handlers;
    private final ObservableList<DatabaseManager.AlertEntry> alertTableData;
    private final Runnable chartUpdater;
    private final DatabaseManager dbManager;
    private ExecutorService processingService;
    private final AtomicBoolean isRunning;
    
    public AlertManager(ObservableList<DatabaseManager.AlertEntry> alertTableData,
                         Runnable chartUpdater, DatabaseManager dbManager) {
        this.alertQueue = new LinkedBlockingQueue<>();
        this.handlers = new EnumMap<>(Alert.Severity.class);
        this.isRunning = new AtomicBoolean(false);
        this.alertTableData = alertTableData;
        this.chartUpdater = chartUpdater;
        this.dbManager = dbManager;

        // Initialize handlers for each severity level
        for (Alert.Severity severity : Alert.Severity.values()) {
            handlers.put(severity, new ArrayList<>());
        }

        // Register default handlers
        registerDefaultHandlers();
    }
    
    // Define the AlertHandler interface
    @FunctionalInterface
    public interface AlertHandler {
        void handleAlert(Alert alert);
    }
    
    public void registerHandler(Alert.Severity severity, AlertHandler handler) {
        handlers.get(severity).add(handler);
    }
    
    private void registerDefaultHandlers() {
        // Register default handlers for each severity level
        registerHandler(Alert.Severity.LOW, alert -> 
            logger.info("Low severity alert: " + alert.getMessage()));
        
        registerHandler(Alert.Severity.MEDIUM, alert -> 
            logger.warning("Medium severity alert: " + alert.getMessage()));
        
        registerHandler(Alert.Severity.HIGH, alert -> {
            logger.severe("HIGH SEVERITY ALERT: " + alert.getMessage());
            // Add more actions for high severity alerts (email notifications, etc.)
        });
        
        registerHandler(Alert.Severity.CRITICAL, alert -> {
            logger.severe("CRITICAL SEVERITY ALERT: " + alert.getMessage());
            // Add more actions for critical alerts (SMS, phone calls, etc.)
        });
    }
    
    public void queueAlert(Alert alert) {
        try {
            alertQueue.put(alert);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.log(Level.WARNING, "Interrupted while queuing alert", e);
        }
    }
    
    public void startProcessing() {
        if (isRunning.get()) {
            return;
        }
        
        isRunning.set(true);
        processingService = Executors.newSingleThreadExecutor();
        
        processingService.submit(() -> {
            logger.info("Alert processing started");
            
            while (isRunning.get()) {
                try {
                    Alert alert = alertQueue.take();
                    processAlert(alert);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.log(Level.WARNING, "Alert processing interrupted", e);
                    break;
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error processing alert", e);
                }
            }
            
            logger.info("Alert processing stopped");
        });
    }
    
    private void processAlert(Alert alert) {
        // Store alert in database
        if (dbManager != null) {
            dbManager.storeAlert(alert);
        }
        
        // Update UI with the new alert
        Platform.runLater(() -> {
            alertTableData.add(0, new DatabaseManager.AlertEntry(
                alert.getTimestamp(), alert.getSource(), alert.getMessage(), alert.getSeverity()));
            
            // Update chart data
            chartUpdater.run();
        });
        
        // Process through all handlers
        List<AlertHandler> handlersForSeverity = handlers.get(alert.getSeverity());
        for (AlertHandler handler : handlersForSeverity) {
            try {
                handler.handleAlert(alert);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error in alert handler: " + e.getMessage(), e);
            }
        }
    }
    
    public void stopProcessing() {
        if (!isRunning.get()) {
            return;
        }
        
        isRunning.set(false);
        
        if (processingService != null) {
            processingService.shutdown();
            try {
                if (!processingService.awaitTermination(5, TimeUnit.SECONDS)) {
                    processingService.shutdownNow();
                }
            } catch (InterruptedException e) {
                processingService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
} 