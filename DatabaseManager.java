package com.networkmonitor;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
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
    
    private void initializeDatabase
