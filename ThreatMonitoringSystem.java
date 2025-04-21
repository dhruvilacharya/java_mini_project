package com.security.threatmonitor;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.util.Callback;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.*;
import java.util.logging.*;

public class ThreatMonitoringSystem extends Application {
    private static final Logger logger = Logger.getLogger(ThreatMonitoringSystem.class.getName());
    
    private DatabaseManager dbManager;
    private ObservableList<DatabaseManager.AlertEntry> alertData;
    private PieChart alertSeverityChart;
    private int lowAlerts = 0;
    private int mediumAlerts = 0;
    private int highAlerts = 0;
    private int criticalAlerts = 0;
    private Label statusLabel;
    private Label lowCountLabel;
    private Label mediumCountLabel;
    private Label highCountLabel;
    private Label criticalCountLabel;
    private Label totalAlertsLabel;
    private Button startStopButton;
    
    private List<Monitor> monitors;
    private AlertManager alertManager;
    private ExecutorService executorService;
    private boolean isRunning;

    public static void main(String[] args) {
        launch(args);
    }

    public ThreatMonitoringSystem() {
        // Initialize the system components
        this.executorService = Executors.newCachedThreadPool();
        this.monitors = new ArrayList<>();
        this.isRunning = false;

        // Configure logging
        configureLogging();
        
        // Print the working directory to help locate the database file
        logger.info("Working directory: " + System.getProperty("user.dir"));

        // Initialize database manager with absolute path to ensure it's created in a known location
        String dbPath = new File(System.getProperty("user.dir"), "threatmonitor.db").getAbsolutePath();
        dbManager = new DatabaseManager("jdbc:sqlite:" + dbPath, "", "");
        dbManager.initialize();
        
        logger.info("Database should be created at: " + dbPath);

        // Schedule database cleanup task (runs daily)
        ScheduledExecutorService cleanupScheduler = Executors.newScheduledThreadPool(1);
        cleanupScheduler.scheduleAtFixedRate(() -> {
            dbManager.cleanupOldAlerts(30); // Keep 30 days of alerts
        }, 1, 24, TimeUnit.HOURS);
    }

    private void configureLogging() {
        Handler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);
        Logger.getLogger("").addHandler(consoleHandler);
        Logger.getLogger("").setLevel(Level.INFO);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Threat Monitoring System");

        // Initialize UI components
        alertData = FXCollections.observableArrayList();
        initializeUI(primaryStage);

        // Create and configure the alert manager
        alertManager = new AlertManager(alertData, this::updateChart, dbManager);

        // Load existing alerts from database
        loadAlertsFromDatabase();

        // Register different types of monitors
        registerMonitors();

        // Show the scene
        primaryStage.setOnCloseRequest(e -> {
            stop();
            Platform.exit();
        });

        primaryStage.show();

        // Start the system automatically
        start();
    }
    
    private void initializeUI(Stage primaryStage) {
        BorderPane root = new BorderPane();
        
        // Create components
        VBox topPanel = createTopPanel();
        VBox chartPanel = createChartPanel();
        VBox alertPanel = createAlertPanel();
        
        // Layout the components
        root.setTop(topPanel);
        root.setLeft(chartPanel);
        root.setCenter(alertPanel);
        
        // Create the scene
        Scene scene = new Scene(root, 1200, 800);
        primaryStage.setScene(scene);
    }
    
    private VBox createTopPanel() {
        VBox topPanel = new VBox(10);
        topPanel.setPadding(new Insets(10));
        topPanel.setStyle("-fx-background-color: #e0e0e0;");
        
        HBox statusBar = new HBox(20);
        statusBar.setPadding(new Insets(5));
        
        statusLabel = new Label("Status: Stopped");
        statusLabel.setTextFill(Color.RED);
        
        startStopButton = new Button("Start Monitoring");
        startStopButton.setOnAction(e -> {
            if (isRunning) {
                stop();
            } else {
                start();
            }
        });
        
        statusBar.getChildren().addAll(new Label("Threat Monitoring System"), statusLabel, startStopButton);
        
        topPanel.getChildren().add(statusBar);
        
        return topPanel;
    }
    
    private VBox createChartPanel() {
        VBox chartPanel = new VBox(10);
        chartPanel.setPadding(new Insets(10));
        chartPanel.setPrefWidth(300);
        chartPanel.setStyle("-fx-background-color: #f8f8f8;");

        // Create alert severity distribution chart
        alertSeverityChart = new PieChart();
        alertSeverityChart.setTitle("Alert Severity Distribution");
        resetChartData();

        Label summaryLabel = new Label("System Summary");
        summaryLabel.setStyle("-fx-font-weight: bold;");

        // Create labels for alert counts
        lowCountLabel = new Label("Low: 0");
        mediumCountLabel = new Label("Medium: 0");
        highCountLabel = new Label("High: 0");
        criticalCountLabel = new Label("Critical: 0");
        totalAlertsLabel = new Label("Total Alerts: 0");
        totalAlertsLabel.setStyle("-fx-font-weight: bold;");

        // Add a separator
        Separator separator = new Separator();
        separator.setPadding(new Insets(5, 0, 5, 0));

        chartPanel.getChildren().addAll(
                summaryLabel,
                alertSeverityChart,
                new VBox(5, lowCountLabel, mediumCountLabel, highCountLabel, criticalCountLabel),
                separator,
                totalAlertsLabel,
                new Label("Active Monitors:"),
                new Label(" • File System Monitor"),
                new Label(" • Network Monitor"),
                new Label(" • System Resource Monitor"),
                new Label(" • Login Monitor")
        );

        return chartPanel;
    }
    
    private VBox createAlertPanel() {
        VBox alertPanel = new VBox(10);
        alertPanel.setPadding(new Insets(10));
        
        Label alertsLabel = new Label("Recent Alerts");
        alertsLabel.setStyle("-fx-font-weight: bold;");
        
        TableView<DatabaseManager.AlertEntry> alertTable = new TableView<>();
        alertTable.setItems(alertData);
        
        TableColumn<DatabaseManager.AlertEntry, LocalDateTime> timestampCol = new TableColumn<>("Timestamp");
        TableColumn<DatabaseManager.AlertEntry, String> sourceCol = new TableColumn<>("Source");
        TableColumn<DatabaseManager.AlertEntry, String> messageCol = new TableColumn<>("Message");
        TableColumn<DatabaseManager.AlertEntry, Alert.Severity> severityCol = new TableColumn<>("Severity");
        
        // Set cell value factories to display alert data
        timestampCol.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        // Format the timestamp for better display
        timestampCol.setCellFactory(column -> {
            return new TableCell<DatabaseManager.AlertEntry, LocalDateTime>() {
                private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                
                @Override
                protected void updateItem(LocalDateTime item, boolean empty) {
                    super.updateItem(item, empty);
                    
                    if (item == null || empty) {
                        setText(null);
                    } else {
                        setText(formatter.format(item));
                    }
                }
            };
        });
        
        sourceCol.setCellValueFactory(new PropertyValueFactory<>("source"));
        messageCol.setCellValueFactory(new PropertyValueFactory<>("message"));
        severityCol.setCellValueFactory(new PropertyValueFactory<>("severity"));
        
        // Add color coding for severity
        severityCol.setCellFactory(column -> {
            return new TableCell<DatabaseManager.AlertEntry, Alert.Severity>() {
                @Override
                protected void updateItem(Alert.Severity item, boolean empty) {
                    super.updateItem(item, empty);
                    
                    if (item == null || empty) {
                        setText(null);
                        setStyle("");
                    } else {
                        setText(item.toString());
                        
                        switch (item) {
                            case LOW:
                                setTextFill(Color.GREEN);
                                break;
                            case MEDIUM:
                                setTextFill(Color.ORANGE);
                                break;
                            case HIGH:
                                setTextFill(Color.RED);
                                break;
                            case CRITICAL:
                                setStyle("-fx-font-weight: bold;");
                                setTextFill(Color.DARKRED);
                                break;
                        }
                    }
                }
            };
        });
        
        // Adjust column widths
        timestampCol.setPrefWidth(150);
        sourceCol.setPrefWidth(120);
        messageCol.setPrefWidth(350);
        severityCol.setPrefWidth(80);
        
        alertTable.getColumns().addAll(timestampCol, sourceCol, messageCol, severityCol);
        alertTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        
        alertPanel.getChildren().addAll(alertsLabel, alertTable);
        VBox.setVgrow(alertTable, Priority.ALWAYS);
        
        return alertPanel;
    }
    
    private void resetChartData() {
        ObservableList<PieChart.Data> pieChartData = FXCollections.observableArrayList(
                new PieChart.Data("Low (0)", 0.1),  // Use 0.1 to ensure slice visibility
                new PieChart.Data("Medium (0)", 0.1),
                new PieChart.Data("High (0)", 0.1),
                new PieChart.Data("Critical (0)", 0.1)
        );
        alertSeverityChart.setData(pieChartData);
        
        // Set colors for the chart slices
        pieChartData.get(0).getNode().setStyle("-fx-pie-color: lightgreen;");
        pieChartData.get(1).getNode().setStyle("-fx-pie-color: yellow;");
        pieChartData.get(2).getNode().setStyle("-fx-pie-color: orange;");
        pieChartData.get(3).getNode().setStyle("-fx-pie-color: red;");
    }
    
    private void updateChart() {
        ObservableList<PieChart.Data> pieChartData = FXCollections.observableArrayList(
                new PieChart.Data("Low (" + lowAlerts + ")", lowAlerts > 0 ? lowAlerts : 0.1), // Use 0.1 to ensure slice visibility
                new PieChart.Data("Medium (" + mediumAlerts + ")", mediumAlerts > 0 ? mediumAlerts : 0.1),
                new PieChart.Data("High (" + highAlerts + ")", highAlerts > 0 ? highAlerts : 0.1),
                new PieChart.Data("Critical (" + criticalAlerts + ")", criticalAlerts > 0 ? criticalAlerts : 0.1)
        );

        Platform.runLater(() -> {
            alertSeverityChart.setData(pieChartData);

            // Set colors for the chart slices
            pieChartData.get(0).getNode().setStyle("-fx-pie-color: lightgreen;");
            pieChartData.get(1).getNode().setStyle("-fx-pie-color: yellow;");
            pieChartData.get(2).getNode().setStyle("-fx-pie-color: orange;");
            pieChartData.get(3).getNode().setStyle("-fx-pie-color: red;");

            // Update summary labels
            lowCountLabel.setText("Low: " + lowAlerts);
            mediumCountLabel.setText("Medium: " + mediumAlerts);
            highCountLabel.setText("High: " + highAlerts);
            criticalCountLabel.setText("Critical: " + criticalAlerts);

            int totalAlerts = lowAlerts + mediumAlerts + highAlerts + criticalAlerts;
            totalAlertsLabel.setText("Total Alerts: " + totalAlerts);
        });
    }
    
    private void updateSeverityCounts(Alert.Severity severity) {
        switch (severity) {
            case LOW:
                lowAlerts++;
                break;
            case MEDIUM:
                mediumAlerts++;
                break;
            case HIGH:
                highAlerts++;
                break;
            case CRITICAL:
                criticalAlerts++;
                break;
        }

        // Update the chart with new data
        updateChart();
    }
    
    private void registerMonitors() {
        // Create and register file system monitor
        FileSystemMonitor fileSystemMonitor = new FileSystemMonitor(alertManager);
        monitors.add(fileSystemMonitor);
        
        // Create and register network monitor
        NetworkMonitor networkMonitor = new NetworkMonitor(alertManager);
        monitors.add(networkMonitor);
        
        // Create and register system resource monitor
        SystemResourceMonitor resourceMonitor = new SystemResourceMonitor(alertManager);
        monitors.add(resourceMonitor);
        
        // Create and register login monitor
        LoginMonitor loginMonitor = new LoginMonitor(alertManager);
        monitors.add(loginMonitor);
        
        logger.info("Registered " + monitors.size() + " monitors");
    }
    
    private void loadAlertsFromDatabase() {
        if (dbManager != null) {
            List<DatabaseManager.AlertEntry> storedAlerts = dbManager.getRecentAlerts(1000);

            // Update chart data based on stored alerts
            for (DatabaseManager.AlertEntry entry : storedAlerts) {
                switch (entry.getSeverity()) {
                    case LOW:
                        lowAlerts++;
                        break;
                    case MEDIUM:
                        mediumAlerts++;
                        break;
                    case HIGH:
                        highAlerts++;
                        break;
                    case CRITICAL:
                        criticalAlerts++;
                        break;
                }
            }

            // Add to UI
            Platform.runLater(() -> {
                alertData.addAll(storedAlerts);
                updateChart();
            });
        }
    }
    
    public void start() {
        if (isRunning) {
            logger.info("Threat monitoring system is already running");
            return;
        }

        logger.info("Starting threat monitoring system...");
        isRunning = true;

        // Start alert manager
        alertManager.startProcessing();

        // Start all monitors
        for (Monitor monitor : monitors) {
            monitor.startMonitoring();
        }

        logger.info("Threat monitoring system started");

        // Update UI
        Platform.runLater(() -> {
            statusLabel.setText("Status: Running");
            statusLabel.setTextFill(Color.GREEN);
            startStopButton.setText("Stop Monitoring");
        });
    }
    
    @Override
    public void stop() {
        if (!isRunning) {
            logger.info("Threat monitoring system is not running");
            return;
        }

        logger.info("Stopping threat monitoring system...");
        isRunning = false;

        // Stop all monitors
        for (Monitor monitor : monitors) {
            monitor.stopMonitoring();
        }

        // Stop alert manager
        alertManager.stopProcessing();

        // Close database connection
        if (dbManager != null) {
            dbManager.close();
        }

        // Shutdown executor service
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }

        logger.info("Threat monitoring system stopped");

        // Update UI
        Platform.runLater(() -> {
            statusLabel.setText("Status: Stopped");
            statusLabel.setTextFill(Color.RED);
            startStopButton.setText("Start Monitoring");
        });
    }
    
    public interface Monitor {
        void startMonitoring();
        void stopMonitoring();
    }
    
    // File System Monitor implementation
    private class FileSystemMonitor implements Monitor {
        private final AlertManager alertManager;
        private ScheduledExecutorService scheduler;
        private final Random random = new Random();
        private final Path monitoredPath = Paths.get(System.getProperty("user.home"));
        
        public FileSystemMonitor(AlertManager alertManager) {
            this.alertManager = alertManager;
        }
        
        @Override
        public void startMonitoring() {
            logger.info("Starting file system monitor for path: " + monitoredPath);
            scheduler = Executors.newScheduledThreadPool(1);
            
            // Schedule periodic file system checks
            scheduler.scheduleAtFixedRate(this::checkFileSystem, 2, 15, TimeUnit.SECONDS);
        }
        
        @Override
        public void stopMonitoring() {
            logger.info("Stopping file system monitor");
            if (scheduler != null) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                }
            }
        }
        
        private void checkFileSystem() {
            // For demonstration, generate random file system alerts
            if (random.nextInt(10) < 3) {  // 30% chance of alert
                Alert.Severity severity;
                String message;
                
                int type = random.nextInt(4);
                switch (type) {
                    case 0:
                        severity = Alert.Severity.LOW;
                        message = "Suspicious file access in " + monitoredPath.resolve("Documents");
                        break;
                    case 1:
                        severity = Alert.Severity.MEDIUM; 
                        message = "Unusual file modification pattern detected in " + monitoredPath.resolve("Downloads");
                        break;
                    case 2:
                        severity = Alert.Severity.HIGH;
                        message = "Possible ransomware activity: rapid file changes in " + monitoredPath;
                        break;
                    default:
                        severity = Alert.Severity.CRITICAL;
                        message = "Critical: Multiple system files modified in " + Paths.get(System.getProperty("user.dir"));
                        break;
                }
                
                Alert alert = new Alert(LocalDateTime.now(), "File Monitor", message, severity);
                alertManager.queueAlert(alert);
                logger.info("File system alert generated: " + severity + " - " + message);
            }
        }
    }
    
    // Network Monitor implementation
    private class NetworkMonitor implements Monitor {
        private final AlertManager alertManager;
        private ScheduledExecutorService scheduler;
        private final Random random = new Random();
        
        public NetworkMonitor(AlertManager alertManager) {
            this.alertManager = alertManager;
        }
        
        @Override
        public void startMonitoring() {
            logger.info("Starting network monitor");
            scheduler = Executors.newScheduledThreadPool(1);
            
            // Schedule periodic network checks
            scheduler.scheduleAtFixedRate(this::checkNetwork, 5, 20, TimeUnit.SECONDS);
        }
        
        @Override
        public void stopMonitoring() {
            logger.info("Stopping network monitor");
            if (scheduler != null) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                }
            }
        }
        
        private void checkNetwork() {
            // For demonstration, generate random network alerts
            if (random.nextInt(10) < 4) {  // 40% chance of alert
                Alert.Severity severity;
                String message;
                
                int type = random.nextInt(4);
                switch (type) {
                    case 0:
                        severity = Alert.Severity.LOW;
                        message = "Unusual outbound connection to port 8080";
                        break;
                    case 1:
                        severity = Alert.Severity.MEDIUM;
                        message = "Multiple connection attempts to blacklisted IP: 192.168." + random.nextInt(255) + "." + random.nextInt(255);
                        break;
                    case 2:
                        severity = Alert.Severity.HIGH;
                        message = "Possible data exfiltration detected: Large upload to unknown host";
                        break;
                    default:
                        severity = Alert.Severity.CRITICAL;
                        message = "Critical: Port scan detected from external network";
                        break;
                }
                
                Alert alert = new Alert(LocalDateTime.now(), "Network Monitor", message, severity);
                alertManager.queueAlert(alert);
                logger.info("Network alert generated: " + severity + " - " + message);
            }
        }
    }
    
    // System Resource Monitor implementation
    private class SystemResourceMonitor implements Monitor {
        private final AlertManager alertManager;
        private ScheduledExecutorService scheduler;
        private final Random random = new Random();
        
        public SystemResourceMonitor(AlertManager alertManager) {
            this.alertManager = alertManager;
        }
        
        @Override
        public void startMonitoring() {
            logger.info("Starting system resource monitor");
            scheduler = Executors.newScheduledThreadPool(1);
            
            // Schedule periodic resource checks
            scheduler.scheduleAtFixedRate(this::checkResources, 10, 25, TimeUnit.SECONDS);
        }
        
        @Override
        public void stopMonitoring() {
            logger.info("Stopping system resource monitor");
            if (scheduler != null) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                }
            }
        }
        
        private void checkResources() {
            // For demonstration, generate random resource alerts
            if (random.nextInt(10) < 3) {  // 30% chance of alert
                Alert.Severity severity;
                String message;
                
                int type = random.nextInt(4);
                switch (type) {
                    case 0:
                        severity = Alert.Severity.LOW;
                        message = "CPU usage spike: " + (70 + random.nextInt(20)) + "% for process: java";
                        break;
                    case 1:
                        severity = Alert.Severity.MEDIUM;
                        message = "Memory leak detected in process ID: " + (1000 + random.nextInt(9000));
                        break;
                    case 2:
                        severity = Alert.Severity.HIGH;
                        message = "Disk I/O overload: Possible DoS attack";
                        break;
                    default:
                        severity = Alert.Severity.CRITICAL;
                        message = "Critical: System resources exhausted, possible crypto-mining activity";
                        break;
                }
                
                Alert alert = new Alert(LocalDateTime.now(), "Resource Monitor", message, severity);
                alertManager.queueAlert(alert);
                logger.info("Resource alert generated: " + severity + " - " + message);
            }
        }
    }
    
    // Login Monitor implementation
    private class LoginMonitor implements Monitor {
        private final AlertManager alertManager;
        private ScheduledExecutorService scheduler;
        private final Random random = new Random();
        
        public LoginMonitor(AlertManager alertManager) {
            this.alertManager = alertManager;
        }
        
        @Override
        public void startMonitoring() {
            logger.info("Starting login monitor");
            scheduler = Executors.newScheduledThreadPool(1);
            
            // Schedule periodic login checks
            scheduler.scheduleAtFixedRate(this::checkLogins, 7, 30, TimeUnit.SECONDS);
        }
        
        @Override
        public void stopMonitoring() {
            logger.info("Stopping login monitor");
            if (scheduler != null) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                }
            }
        }
        
        private void checkLogins() {
            // For demonstration, generate random login alerts
            if (random.nextInt(10) < 2) {  // 20% chance of alert
                Alert.Severity severity;
                String message;
                
                int type = random.nextInt(4);
                switch (type) {
                    case 0:
                        severity = Alert.Severity.LOW;
                        message = "Failed login attempt for user: guest";
                        break;
                    case 1:
                        severity = Alert.Severity.MEDIUM;
                        message = "Multiple failed login attempts from IP: 10.0." + random.nextInt(255) + "." + random.nextInt(255);
                        break;
                    case 2:
                        severity = Alert.Severity.HIGH;
                        message = "Successful login from unusual location: " + getRandomLocation();
                        break;
                    default:
                        severity = Alert.Severity.CRITICAL;
                        message = "Critical: Admin account login attempt after hours";
                        break;
                }
                
                Alert alert = new Alert(LocalDateTime.now(), "Login Monitor", message, severity);
                alertManager.queueAlert(alert);
                logger.info("Login alert generated: " + severity + " - " + message);
            }
        }
        
        private String getRandomLocation() {
            String[] locations = {
                "Moscow, Russia", 
                "Beijing, China", 
                "Pyongyang, North Korea", 
                "Tehran, Iran", 
                "Lagos, Nigeria",
                "Bucharest, Romania",
                "Kiev, Ukraine",
                "São Paulo, Brazil"
            };
            return locations[random.nextInt(locations.length)];
        }
    }
}