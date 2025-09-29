package com.networkmonitor;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Database Manager with connection pooling and thread-safe operations
 */
public class DatabaseManager {
    private static final Logger LOGGER = Logger.getLogger(DatabaseManager.class.getName());
    private static final String DB_URL = "jdbc:sqlite:network_monitor.db";
    private static final int POOL_SIZE = 10;
    
    private BlockingQueue<Connection> connectionPool;
    
    public DatabaseManager() {
        initializeDatabase();
        createConnectionPool();
    }
    
    private void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL); 
             Statement stmt = conn.createStatement()) {
            
            // 1. Devices Table
            String sqlDevices = "CREATE TABLE IF NOT EXISTS devices (" +
                                "ip TEXT PRIMARY KEY," +
                                "hostname TEXT NOT NULL," +
                                "os_type TEXT," +
                                "status TEXT," +
                                "monitoring_enabled BOOLEAN," +
                                "configured BOOLEAN," +
                                "last_update TEXT" +
                                ");";
            stmt.execute(sqlDevices);
            
            // 2. Metrics Table (for history)
            String sqlMetrics = "CREATE TABLE IF NOT EXISTS metrics (" +
                                "ip TEXT NOT NULL," +
                                "timestamp TEXT NOT NULL," +
                                "cpu_usage REAL," +
                                "memory_usage REAL," +
                                "disk_usage REAL," +
                                "PRIMARY KEY (ip, timestamp)," +
                                "FOREIGN KEY (ip) REFERENCES devices(ip)" +
                                ");";
            stmt.execute(sqlMetrics);

            LOGGER.info("Database and tables initialized successfully.");

        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Database initialization failed", e);
        }
    }

    private void createConnectionPool() {
        connectionPool = new ArrayBlockingQueue<>(POOL_SIZE);
        for (int i = 0; i < POOL_SIZE; i++) {
            try {
                Connection conn = DriverManager.getConnection(DB_URL);
                connectionPool.offer(conn);
            } catch (SQLException e) {
                LOGGER.log(Level.SEVERE, "Failed to create database connection", e);
            }
        }
    }

    private Connection getConnection() throws InterruptedException {
        // Block until a connection is available
        return connectionPool.take();
    }

    private void releaseConnection(Connection conn) {
        if (conn != null) {
            connectionPool.offer(conn);
        }
    }

    /**
     * Saves a NetworkDevice to the database (INSERT or UPDATE).
     */
    public void saveDevice(NetworkDevice device) {
        String sql = "INSERT INTO devices (ip, hostname, os_type, status, monitoring_enabled, configured, last_update) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(ip) DO UPDATE SET " +
                     "hostname=excluded.hostname, os_type=excluded.os_type, status=excluded.status, " +
                     "monitoring_enabled=excluded.monitoring_enabled, configured=excluded.configured, last_update=excluded.last_update;";
        
        Connection conn = null;
        try {
            conn = getConnection();
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, device.getIp());
                pstmt.setString(2, device.getHostname());
                pstmt.setString(3, device.getOsType());
                pstmt.setString(4, device.getStatus());
                pstmt.setBoolean(5, device.isMonitoringEnabled());
                pstmt.setBoolean(6, device.isConfigured());
                pstmt.setString(7, device.getLastUpdate() != null ? device.getLastUpdate().toString() : null);
                pstmt.executeUpdate();
            }
        } catch (InterruptedException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to save device: " + device.getIp(), e);
        } finally {
            releaseConnection(conn);
        }
    }

    /**
     * Removes a device and its associated metrics from the database.
     */
    public void removeDevice(String ip) {
        Connection conn = null;
        try {
            conn = getConnection();
            // Remove from devices table
            try (PreparedStatement pstmt = conn.prepareStatement("DELETE FROM devices WHERE ip = ?")) {
                pstmt.setString(1, ip);
                pstmt.executeUpdate();
            }
            // Remove from metrics table
            try (PreparedStatement pstmt = conn.prepareStatement("DELETE FROM metrics WHERE ip = ?")) {
                pstmt.setString(1, ip);
                pstmt.executeUpdate();
            }
            LOGGER.info("Removed device and metrics for IP: " + ip);
        } catch (InterruptedException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to remove device: " + ip, e);
        } finally {
            releaseConnection(conn);
        }
    }

    /**
     * Loads all devices from the database.
     */
    public Map<String, NetworkDevice> loadDevices() {
        Map<String, NetworkDevice> devices = new ConcurrentHashMap<>();
        String sql = "SELECT ip, hostname, os_type, status, monitoring_enabled, configured, last_update FROM devices";
        
        Connection conn = null;
        try {
            conn = getConnection();
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                
                while (rs.next()) {
                    String ip = rs.getString("ip");
                    String hostname = rs.getString("hostname");
                    String osType = rs.getString("os_type");
                    String status = rs.getString("status");
                    boolean monitoringEnabled = rs.getBoolean("monitoring_enabled");
                    boolean configured = rs.getBoolean("configured");
                    String lastUpdateStr = rs.getString("last_update");

                    NetworkDevice device = new NetworkDevice(ip, hostname, osType, status);
                    device.setMonitoringEnabled(monitoringEnabled);
                    device.setConfigured(configured);
                    if (lastUpdateStr != null) {
                        device.setLastUpdate(LocalDateTime.parse(lastUpdateStr));
                    }
                    // Note: Metrics history is NOT loaded here as it would be too large.
                    // It's fetched on-demand or during active monitoring.

                    devices.put(ip, device);
                }
            }
            LOGGER.info(String.format("Loaded %d devices from database.", devices.size()));
        } catch (InterruptedException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to load devices from database", e);
        } finally {
            releaseConnection(conn);
        }
        return devices;
    }

    /**
     * Saves a new metric data point for a device.
     */
    public void saveMetric(NetworkDevice device, double cpu, double memory, double disk) {
        String sql = "INSERT INTO metrics (ip, timestamp, cpu_usage, memory_usage, disk_usage) VALUES (?, ?, ?, ?, ?)";
        
        Connection conn = null;
        try {
            conn = getConnection();
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, device.getIp());
                pstmt.setString(2, LocalDateTime.now().toString());
                pstmt.setDouble(3, cpu);
                pstmt.setDouble(4, memory);
                pstmt.setDouble(5, disk);
                pstmt.executeUpdate();
            }
        } catch (InterruptedException | SQLException e) {
            LOGGER.log(Level.WARNING, "Failed to save metric for device: " + device.getIp(), e);
        } finally {
            releaseConnection(conn);
        }
    }

    /**
     * Removes metric history older than a specified number of days.
     */
    public void cleanupOldData(int days) {
        LocalDateTime threshold = LocalDateTime.now().minusDays(days);
        String sql = "DELETE FROM metrics WHERE timestamp < ?";
        
        Connection conn = null;
        try {
            conn = getConnection();
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, threshold.toString());
                int rowsDeleted = pstmt.executeUpdate();
                LOGGER.info(String.format("Database cleanup: Removed %d old metric records.", rowsDeleted));
            }
        } catch (InterruptedException | SQLException e) {
            LOGGER.log(Level.SEVERE, "Failed to clean up old database data", e);
        } finally {
            releaseConnection(conn);
        }
    }

    /**
     * Shuts down the database manager and closes all connections in the pool.
     */
    public void shutdown() {
        for (Connection conn : connectionPool) {
            try {
                conn.close();
            } catch (SQLException e) {
                LOGGER.log(Level.WARNING, "Failed to close database connection", e);
            }
        }
        LOGGER.info("Database connection pool shut down.");
    }

    // You would need a method to load historical metrics for charting, 
    // but the in-memory history in NetworkDevice is a good start.
}
