# Threat Monitoring System

A comprehensive security monitoring system with database capabilities for tracking security threats and alerts.

## Project Structure

- `src/com/security/threatmonitor/` - Source code directory
  - `Alert.java` - Basic alert class
  - `DatabaseManager.java` - Database connection and management
  - `ThreatMonitoringSystem.java` - Main application
  - `SimpleDatabaseTest.java` - Text-based database test utility
  - `GraphicalDatabaseTest.java` - GUI-based database test utility

## Setup and Running

### Prerequisites

- Java Development Kit (JDK) 17 or higher
- JavaFX SDK (for GUI components)

### Project Setup

1. Make sure you have the SQLite JDBC driver in the `lib` directory
2. Configure your IDE to use the libraries in the `lib` directory

### Running the Database Test

To verify the SQLite connection is working:

```bash
# Compile the test class
javac -d out/production -classpath "lib/sqlite-jdbc-3.41.2.2.jar" src/com/security/threatmonitor/SimpleDatabaseTest.java

# Run the test
java -cp "out/production;lib/sqlite-jdbc-3.41.2.2.jar" com.security.threatmonitor.SimpleDatabaseTest
```

### Running the Graphical Test

To test the database with a graphical interface:

```bash
# Compile the graphical test class
javac -d out/production -classpath "lib/sqlite-jdbc-3.41.2.2.jar;path/to/javafx-sdk/lib/*" src/com/security/threatmonitor/GraphicalDatabaseTest.java

# Run the graphical test
java --module-path "path/to/javafx-sdk/lib" --add-modules javafx.controls,javafx.fxml -cp "out/production;lib/sqlite-jdbc-3.41.2.2.jar" com.security.threatmonitor.GraphicalDatabaseTest
```

### Running the Main Application

To run the main Threat Monitoring System:

```bash
# Compile the application
javac -d out/production -classpath "lib/sqlite-jdbc-3.41.2.2.jar;path/to/javafx-sdk/lib/*" src/com/security/threatmonitor/*.java

# Run the application
java --module-path "path/to/javafx-sdk/lib" --add-modules javafx.controls,javafx.fxml -cp "out/production;lib/sqlite-jdbc-3.41.2.2.jar" com.security.threatmonitor.ThreatMonitoringSystem
```

## Database Information

The system uses SQLite database for storing alerts. The database file is created automatically when the application runs. 

- Database file: `threatmonitor.db`
- Test database: `test.db`
- Graphical test database: `graphical_test.db`

## Configuration

You can modify the database connection in the `DatabaseManager` class:

```java
dbManager = new DatabaseManager("jdbc:sqlite:threatmonitor.db", "", "");
``` 