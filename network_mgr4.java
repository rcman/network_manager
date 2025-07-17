import javax.swing.*;
import javax.swing.table.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.*;

/**
 * Enterprise Network PC Management System
 * Java implementation without external dependencies
 * 
 * Features:
 * - Network device discovery
 * - Real-time monitoring simulation
 * - Alert management
 * - Modern GUI with themes
 * - Performance tracking
 * - Security monitoring
 */

// Main Application Class
public class NetworkManagementSystem extends JFrame {
    private static final Logger logger = Logger.getLogger(NetworkManagementSystem.class.getName());
    
    // GUI Components
    private JTable deviceTable;
    private DefaultTableModel deviceTableModel;
    private JTable alertTable;
    private DefaultTableModel alertTableModel;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JLabel deviceCountLabel;
    private JLabel alertCountLabel;
    private JTextField searchField;
    private JTextField networkField;
    private JProgressBar progressBar;
    
    // Data structures
    private Map<String, NetworkDevice> devices;
    private List<Alert> alerts;
    private NetworkScanner scanner;
    private MonitoringService monitoringService;
    private AlertManager alertManager;
    private DatabaseManager dbManager;
    private ConfigManager configManager;
    private ThemeManager themeManager;
    
    // Configuration
    private boolean isDarkTheme = false;
    private boolean autoRefresh = true;
    private int monitoringInterval = 5000; // 5 seconds
    
    public NetworkManagementSystem() {
        initializeComponents();
        initializeServices();
        setupGUI();
        startServices();
        
        setTitle("Enterprise Network PC Management System v2.0 (Java)");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1400, 900);
        setLocationRelativeTo(null);
        
        // Load saved configuration
        loadConfiguration();
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
    }
    
    private void initializeComponents() {
        devices = new ConcurrentHashMap<>();
        alerts = new ArrayList<>();
        scanner = new NetworkScanner();
        monitoringService = new MonitoringService();
        alertManager = new AlertManager();
        dbManager = new DatabaseManager();
        configManager = new ConfigManager();
        themeManager = new ThemeManager();
        
        // Setup logging
        setupLogging();
    }
    
    private void setupLogging() {
        try {
            Handler fileHandler = new FileHandler("network_monitor.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }
    
    private void initializeServices() {
        // Initialize monitoring service
        monitoringService.addMonitoringListener(new MonitoringListener() {
            @Override
            public void onMetricUpdate(String deviceIP, String metric, double value) {
                SwingUtilities.invokeLater(() -> {
                    updateDeviceMetric(deviceIP, metric, value);
                    alertManager.checkThreshold(deviceIP, metric, value);
                });
            }
            
            @Override
            public void onDeviceStatusChange(String deviceIP, DeviceStatus status) {
                SwingUtilities.invokeLater(() -> updateDeviceStatus(deviceIP, status));
            }
        });
        
        // Initialize alert manager
        alertManager.addAlertListener(new AlertListener() {
            @Override
            public void onAlertTriggered(Alert alert) {
                SwingUtilities.invokeLater(() -> {
                    alerts.add(alert);
                    updateAlertDisplay();
                    logMessage("ALERT: " + alert.toString(), LogLevel.WARNING);
                });
            }
            
            @Override
            public void onAlertResolved(Alert alert) {
                SwingUtilities.invokeLater(() -> updateAlertDisplay());
            }
        });
    }
    
    private void setupGUI() {
        setLayout(new BorderLayout());
        
        // Create menu bar
        createMenuBar();
        
        // Create toolbar
        JPanel toolbar = createToolbar();
        add(toolbar, BorderLayout.NORTH);
        
        // Create main content area
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setLeftComponent(createDevicePanel());
        mainSplit.setRightComponent(createMonitoringPanel());
        mainSplit.setDividerLocation(600);
        add(mainSplit, BorderLayout.CENTER);
        
        // Create status bar
        JPanel statusBar = createStatusBar();
        add(statusBar, BorderLayout.SOUTH);
        
        // Apply initial theme
        themeManager.applyTheme(this, isDarkTheme);
    }
    
    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        
        // File menu
        JMenu fileMenu = new JMenu("File");
        fileMenu.add(createMenuItem("Quick Scan", this::quickScan, KeyEvent.VK_Q));
        fileMenu.add(createMenuItem("Full Network Scan", this::fullNetworkScan, KeyEvent.VK_S));
        fileMenu.addSeparator();
        fileMenu.add(createMenuItem("Import Devices", this::importDevices, 0));
        fileMenu.add(createMenuItem("Export Report", this::exportReport, 0));
        fileMenu.addSeparator();
        fileMenu.add(createMenuItem("Preferences", this::showPreferences, KeyEvent.VK_P));
        fileMenu.addSeparator();
        fileMenu.add(createMenuItem("Exit", this::exitApplication, 0));
        
        // View menu
        JMenu viewMenu = new JMenu("View");
        viewMenu.add(createMenuItem("Toggle Theme", this::toggleTheme, KeyEvent.VK_T));
        viewMenu.add(createMenuItem("Refresh All", this::refreshAll, KeyEvent.VK_F5));
        viewMenu.add(createMenuItem("Alerts Dashboard", this::showAlertsDashboard, 0));
        
        // Tools menu
        JMenu toolsMenu = new JMenu("Tools");
        toolsMenu.add(createMenuItem("Device Setup", this::showDeviceSetup, 0));
        toolsMenu.add(createMenuItem("Alert Configuration", this::configureAlerts, 0));
        toolsMenu.add(createMenuItem("Performance Monitor", this::showPerformanceMonitor, 0));
        
        // Help menu
        JMenu helpMenu = new JMenu("Help");
        helpMenu.add(createMenuItem("Keyboard Shortcuts", this::showShortcuts, 0));
        helpMenu.add(createMenuItem("About", this::showAbout, 0));
        
        menuBar.add(fileMenu);
        menuBar.add(viewMenu);
        menuBar.add(toolsMenu);
        menuBar.add(helpMenu);
        
        setJMenuBar(menuBar);
    }
    
    private JMenuItem createMenuItem(String text, Runnable action, int keyCode) {
        JMenuItem item = new JMenuItem(text);
        item.addActionListener(e -> action.run());
        if (keyCode != 0) {
            item.setAccelerator(KeyStroke.getKeyStroke(keyCode, InputEvent.CTRL_DOWN_MASK));
        }
        return item;
    }
    
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Action buttons
        toolbar.add(createButton("🔍 Quick Scan", this::quickScan));
        toolbar.add(createButton("🔄 Refresh", this::refreshAll));
        toolbar.add(createButton("⚙️ Setup", this::showDeviceSetup));
        toolbar.add(createButton("🚨 Alerts", this::showAlertsDashboard));
        
        toolbar.add(Box.createHorizontalStrut(20));
        
        // Search field
        toolbar.add(new JLabel("🔍 Search:"));
        searchField = new JTextField(20);
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                filterDevices();
            }
        });
        toolbar.add(searchField);
        
        toolbar.add(Box.createHorizontalStrut(10));
        
        // Network field
        toolbar.add(new JLabel("🌐 Network:"));
        networkField = new JTextField("192.168.1.0/24", 15);
        toolbar.add(networkField);
        
        toolbar.add(Box.createHorizontalGlue());
        
        // Status indicators
        deviceCountLabel = new JLabel("Devices: 0");
        toolbar.add(deviceCountLabel);
        
        toolbar.add(Box.createHorizontalStrut(10));
        
        alertCountLabel = new JLabel("🔴 Alerts: 0");
        toolbar.add(alertCountLabel);
        
        toolbar.add(Box.createHorizontalStrut(10));
        
        // Theme toggle
        toolbar.add(createButton("🌙", this::toggleTheme));
        
        return toolbar;
    }
    
    private JButton createButton(String text, Runnable action) {
        JButton button = new JButton(text);
        button.addActionListener(e -> action.run());
        return button;
    }
    
    private JPanel createDevicePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Network Devices"));
        
        // Device table
        String[] columnNames = {"Status", "IP Address", "Hostname", "OS", "CPU %", "Memory %", "Last Update", "Alerts"};
        deviceTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        deviceTable = new JTable(deviceTableModel);
        deviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        deviceTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showDeviceProperties();
                }
            }
        });
        
        // Custom renderer for status column
        deviceTable.getColumnModel().getColumn(0).setCellRenderer(new StatusCellRenderer());
        
        JScrollPane scrollPane = new JScrollPane(deviceTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Device actions panel
        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actionsPanel.add(createButton("Start Monitoring", this::startMonitoringSelected));
        actionsPanel.add(createButton("Stop Monitoring", this::stopMonitoringSelected));
        actionsPanel.add(createButton("Remove", this::removeSelectedDevice));
        
        panel.add(actionsPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createMonitoringPanel() {
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Monitoring tab
        tabbedPane.addTab("📊 Live Monitoring", createLiveMonitoringPanel());
        
        // Alerts tab
        tabbedPane.addTab("🚨 Alerts", createAlertsPanel());
        
        // Security tab
        tabbedPane.addTab("🔒 Security", createSecurityPanel());
        
        // Logs tab
        tabbedPane.addTab("📝 Logs", createLogsPanel());
        
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLiveMonitoringPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Summary cards
        JPanel summaryPanel = createSummaryCards();
        panel.add(summaryPanel, BorderLayout.NORTH);
        
        // Charts placeholder (would use external charting library in real implementation)
        JPanel chartsPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        chartsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        chartsPanel.add(createChartPlaceholder("CPU Usage", Color.BLUE));
        chartsPanel.add(createChartPlaceholder("Memory Usage", Color.GREEN));
        chartsPanel.add(createChartPlaceholder("Network Activity", Color.ORANGE));
        chartsPanel.add(createChartPlaceholder("Disk Usage", Color.RED));
        
        panel.add(chartsPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createSummaryCards() {
        JPanel panel = new JPanel(new GridLayout(1, 4, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        panel.add(createMetricCard("Total Devices", "0", Color.BLUE));
        panel.add(createMetricCard("Monitored", "0", Color.GREEN));
        panel.add(createMetricCard("Active Alerts", "0", Color.RED));
        panel.add(createMetricCard("Avg CPU", "0%", Color.ORANGE));
        
        return panel;
    }
    
    private JPanel createMetricCard(String title, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 2),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        JLabel titleLabel = new JLabel(title, JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(12f));
        
        JLabel valueLabel = new JLabel(value, JLabel.CENTER);
        valueLabel.setFont(valueLabel.getFont().deriveFont(Font.BOLD, 24f));
        valueLabel.setForeground(color);
        
        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        
        return card;
    }
    
    private JPanel createChartPlaceholder(String title, Color color) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        
        // Simple chart simulation
        ChartPanel chartPanel = new ChartPanel(title, color);
        panel.add(chartPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAlertsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Alert controls
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlsPanel.add(createButton("🔧 Configure", this::configureAlerts));
        controlsPanel.add(createButton("✅ Acknowledge All", this::acknowledgeAllAlerts));
        controlsPanel.add(createButton("🔄 Refresh", this::refreshAlerts));
        
        panel.add(controlsPanel, BorderLayout.NORTH);
        
        // Alert table
        String[] alertColumns = {"Severity", "Device", "Metric", "Value", "Threshold", "Time", "Status"};
        alertTableModel = new DefaultTableModel(alertColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        alertTable = new JTable(alertTableModel);
        alertTable.getColumnModel().getColumn(0).setCellRenderer(new AlertSeverityRenderer());
        
        JScrollPane alertScrollPane = new JScrollPane(alertTable);
        panel.add(alertScrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createSecurityPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Security summary
        JPanel summaryPanel = new JPanel(new GridLayout(1, 3, 10, 10));
        summaryPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        summaryPanel.add(createMetricCard("Failed Logins (24h)", "0", Color.RED));
        summaryPanel.add(createMetricCard("Suspicious Activity", "0", Color.ORANGE));
        summaryPanel.add(createMetricCard("Security Events", "0", Color.BLUE));
        
        panel.add(summaryPanel, BorderLayout.NORTH);
        
        // Security events placeholder
        JTextArea securityArea = new JTextArea();
        securityArea.setEditable(false);
        securityArea.setText("Security monitoring active...\nNo security events detected.");
        
        JScrollPane securityScrollPane = new JScrollPane(securityArea);
        panel.add(securityScrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLogsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Log controls
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        controlsPanel.add(new JLabel("Filter:"));
        JTextField logFilterField = new JTextField(20);
        controlsPanel.add(logFilterField);
        
        controlsPanel.add(new JLabel("Level:"));
        JComboBox<String> levelCombo = new JComboBox<>(new String[]{"All", "ERROR", "WARNING", "INFO", "DEBUG"});
        controlsPanel.add(levelCombo);
        
        controlsPanel.add(createButton("🗑️ Clear", this::clearLogs));
        controlsPanel.add(createButton("💾 Export", this::exportLogs));
        
        panel.add(controlsPanel, BorderLayout.NORTH);
        
        // Log area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(logScrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createLoweredBevelBorder());
        
        statusLabel = new JLabel("Ready - Enterprise Network Management System");
        statusBar.add(statusLabel, BorderLayout.WEST);
        
        // Progress bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        statusBar.add(progressBar, BorderLayout.CENTER);
        
        // Time display
        JLabel timeLabel = new JLabel();
        Timer timeTimer = new Timer(1000, e -> {
            timeLabel.setText(new SimpleDateFormat("HH:mm:ss").format(new Date()));
        });
        timeTimer.start();
        statusBar.add(timeLabel, BorderLayout.EAST);
        
        return statusBar;
    }
    
    private void startServices() {
        // Start monitoring service
        monitoringService.start();
        
        // Start auto-refresh timer
        if (autoRefresh) {
            Timer refreshTimer = new Timer(5000, e -> updateDisplays());
            refreshTimer.start();
        }
        
        logMessage("Services started successfully", LogLevel.INFO);
    }
    
    // Action Methods
    private void quickScan() {
        CompletableFuture.runAsync(() -> {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("Performing quick scan...");
                progressBar.setVisible(true);
                progressBar.setIndeterminate(true);
            });
            
            try {
                List<String> knownIPs = new ArrayList<>(devices.keySet());
                if (knownIPs.isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        logMessage("No known devices to scan", LogLevel.INFO);
                        statusLabel.setText("No devices to scan");
                        progressBar.setVisible(false);
                    });
                    return;
                }
                
                int activeCount = 0;
                for (String ip : knownIPs) {
                    if (scanner.pingHost(ip)) {
                        devices.get(ip).setStatus(DeviceStatus.ONLINE);
                        activeCount++;
                    } else {
                        devices.get(ip).setStatus(DeviceStatus.OFFLINE);
                    }
                }
                
                final int finalActiveCount = activeCount;
                SwingUtilities.invokeLater(() -> {
                    updateDeviceDisplay();
                    logMessage(String.format("Quick scan completed. %d/%d devices online", 
                        finalActiveCount, knownIPs.size()), LogLevel.INFO);
                    statusLabel.setText("Ready");
                    progressBar.setVisible(false);
                });
                
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    logMessage("Quick scan failed: " + e.getMessage(), LogLevel.ERROR);
                    statusLabel.setText("Quick scan failed");
                    progressBar.setVisible(false);
                });
            }
        });
    }
    
    private void fullNetworkScan() {
        CompletableFuture.runAsync(() -> {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("Scanning network...");
                progressBar.setVisible(true);
                progressBar.setIndeterminate(true);
            });
            
            try {
                String networkRange = networkField.getText();
                List<NetworkDevice> discoveredDevices = scanner.scanNetwork(networkRange);
                
                int newDevices = 0;
                for (NetworkDevice device : discoveredDevices) {
                    if (!devices.containsKey(device.getIpAddress())) {
                        newDevices++;
                    }
                    devices.put(device.getIpAddress(), device);
                }
                
                final int finalNewDevices = newDevices;
                SwingUtilities.invokeLater(() -> {
                    updateDeviceDisplay();
                    logMessage(String.format("Network scan completed. Found %d devices (%d new)", 
                        discoveredDevices.size(), finalNewDevices), LogLevel.INFO);
                    statusLabel.setText("Ready");
                    progressBar.setVisible(false);
                });
                
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    logMessage("Network scan failed: " + e.getMessage(), LogLevel.ERROR);
                    statusLabel.setText("Network scan failed");
                    progressBar.setVisible(false);
                });
            }
        });
    }
    
    private void toggleTheme() {
        isDarkTheme = !isDarkTheme;
        themeManager.applyTheme(this, isDarkTheme);
        logMessage("Theme toggled to " + (isDarkTheme ? "dark" : "light"), LogLevel.INFO);
    }
    
    private void refreshAll() {
        updateDeviceDisplay();
        updateAlertDisplay();
        logMessage("All displays refreshed", LogLevel.INFO);
    }
    
    private void showDeviceSetup() {
        DeviceSetupDialog dialog = new DeviceSetupDialog(this, devices);
        dialog.setVisible(true);
    }
    
    private void showAlertsDashboard() {
        AlertsDashboardDialog dialog = new AlertsDashboardDialog(this, alerts);
        dialog.setVisible(true);
    }
    
    private void configureAlerts() {
        AlertConfigDialog dialog = new AlertConfigDialog(this, alertManager);
        dialog.setVisible(true);
    }
    
    private void showPerformanceMonitor() {
        PerformanceMonitorDialog dialog = new PerformanceMonitorDialog(this, devices);
        dialog.setVisible(true);
    }
    
    private void showPreferences() {
        PreferencesDialog dialog = new PreferencesDialog(this, configManager);
        dialog.setVisible(true);
    }
    
    private void importDevices() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV Files", "csv"));
        
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                int imported = importDevicesFromFile(file);
                JOptionPane.showMessageDialog(this, 
                    "Successfully imported " + imported + " devices.");
                updateDeviceDisplay();
                logMessage("Imported " + imported + " devices from " + file.getName(), LogLevel.INFO);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, 
                    "Failed to import devices: " + e.getMessage(), 
                    "Import Error", JOptionPane.ERROR_MESSAGE);
                logMessage("Import failed: " + e.getMessage(), LogLevel.ERROR);
            }
        }
    }
    
    private void exportReport() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("HTML Files", "html"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                generateReport(file);
                JOptionPane.showMessageDialog(this, "Report exported to " + file.getName());
                logMessage("Report exported to " + file.getName(), LogLevel.INFO);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, 
                    "Failed to export report: " + e.getMessage(), 
                    "Export Error", JOptionPane.ERROR_MESSAGE);
                logMessage("Export failed: " + e.getMessage(), LogLevel.ERROR);
            }
        }
    }
    
    private void showShortcuts() {
        String shortcuts = """
            Keyboard Shortcuts:
            
            Ctrl+Q - Quick Scan
            Ctrl+S - Full Network Scan
            Ctrl+P - Preferences
            Ctrl+T - Toggle Theme
            F5 - Refresh All
            
            Mouse Actions:
            Double-click device - Show properties
            Right-click device - Context menu
            """;
        
        JOptionPane.showMessageDialog(this, shortcuts, "Keyboard Shortcuts", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void showAbout() {
        String about = """
            Enterprise Network PC Management System v2.0 (Java)
            
            A comprehensive network monitoring and management solution
            built with Java Swing for cross-platform compatibility.
            
            Features:
            • Network device discovery
            • Real-time monitoring simulation
            • Alert management system
            • Modern GUI with theme support
            • Performance tracking
            • Security monitoring
            
            Built with pure Java - no external dependencies
            """;
        
        JOptionPane.showMessageDialog(this, about, "About", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void exitApplication() {
        if (JOptionPane.showConfirmDialog(this, 
                "Are you sure you want to exit?", 
                "Exit Application", 
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            cleanup();
            System.exit(0);
        }
    }
    
    // Display Update Methods
    private void updateDeviceDisplay() {
        deviceTableModel.setRowCount(0);
        
        String searchTerm = searchField.getText().toLowerCase();
        int deviceCount = 0;
        int monitoredCount = 0;
        
        for (NetworkDevice device : devices.values()) {
            // Apply search filter
            if (!searchTerm.isEmpty() && 
                !device.getIpAddress().toLowerCase().contains(searchTerm) &&
                !device.getHostname().toLowerCase().contains(searchTerm)) {
                continue;
            }
            
            deviceCount++;
            if (device.isMonitoringEnabled()) {
                monitoredCount++;
            }
            
            String statusIcon = getStatusIcon(device.getStatus());
            String cpuValue = device.getCpuUsage() > 0 ? String.format("%.1f%%", device.getCpuUsage()) : "N/A";
            String memoryValue = device.getMemoryUsage() > 0 ? String.format("%.1f%%", device.getMemoryUsage()) : "N/A";
            String lastUpdate = device.getLastUpdate() != null ? 
                formatTimeDifference(device.getLastUpdate()) : "Never";
            
            long deviceAlerts = alerts.stream()
                .filter(alert -> alert.getDeviceIP().equals(device.getIpAddress()) && !alert.isResolved())
                .count();
            String alertText = deviceAlerts > 0 ? "🚨 " + deviceAlerts : "✅";
            
            deviceTableModel.addRow(new Object[]{
                statusIcon,
                device.getIpAddress(),
                device.getHostname(),
                device.getOsType(),
                cpuValue,
                memoryValue,
                lastUpdate,
                alertText
            });
        }
        
        deviceCountLabel.setText(String.format("Devices: %d | Monitored: %d", deviceCount, monitoredCount));
    }
    
    private void updateAlertDisplay() {
        alertTableModel.setRowCount(0);
        
        List<Alert> activeAlerts = alerts.stream()
            .filter(alert -> !alert.isResolved())
            .sorted((a1, a2) -> a2.getTimestamp().compareTo(a1.getTimestamp()))
            .toList();
        
        for (Alert alert : activeAlerts) {
            String severityIcon = getSeverityIcon(alert.getSeverity());
            String status = alert.isAcknowledged() ? "Acknowledged" : "Active";
            String timeStr = new SimpleDateFormat("HH:mm:ss").format(alert.getTimestamp());
            
            alertTableModel.addRow(new Object[]{
                severityIcon + " " + alert.getSeverity().toString().toUpperCase(),
                alert.getDeviceIP(),
                alert.getMetric().toUpperCase(),
                String.format("%.1f", alert.getValue()),
                String.format("%.1f", alert.getThreshold()),
                timeStr,
                status
            });
        }
        
        long criticalCount = activeAlerts.stream()
            .filter(alert -> alert.getSeverity() == AlertSeverity.CRITICAL)
            .count();
        
        if (criticalCount > 0) {
            alertCountLabel.setText("🔴 " + criticalCount + " Critical");
        } else if (!activeAlerts.isEmpty()) {
            alertCountLabel.setText("🟡 " + activeAlerts.size() + " Alerts");
        } else {
            alertCountLabel.setText("✅ No Alerts");
        }
    }
    
    private void updateDisplays() {
        updateDeviceDisplay();
        updateAlertDisplay();
    }
    
    private void updateDeviceMetric(String deviceIP, String metric, double value) {
        NetworkDevice device = devices.get(deviceIP);
        if (device != null) {
            switch (metric.toLowerCase()) {
                case "cpu" -> device.setCpuUsage(value);
                case "memory" -> device.setMemoryUsage(value);
                case "disk" -> device.setDiskUsage(value);
            }
            device.setLastUpdate(new Date());
            updateDeviceDisplay();
        }
    }
    
    private void updateDeviceStatus(String deviceIP, DeviceStatus status) {
        NetworkDevice device = devices.get(deviceIP);
        if (device != null) {
            device.setStatus(status);
            updateDeviceDisplay();
        }
    }
    
    // Device Management Methods
    private void startMonitoringSelected() {
        int selectedRow = deviceTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) deviceTableModel.getValueAt(selectedRow, 1);
            NetworkDevice device = devices.get(ip);
            if (device != null) {
                device.setMonitoringEnabled(true);
                monitoringService.addDevice(device);
                updateDeviceDisplay();
                logMessage("Started monitoring for " + ip, LogLevel.INFO);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Please select a device to monitor.");
        }
    }
    
    private void stopMonitoringSelected() {
        int selectedRow = deviceTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) deviceTableModel.getValueAt(selectedRow, 1);
            NetworkDevice device = devices.get(ip);
            if (device != null) {
                device.setMonitoringEnabled(false);
                monitoringService.removeDevice(device);
                updateDeviceDisplay();
                logMessage("Stopped monitoring for " + ip, LogLevel.INFO);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Please select a device to stop monitoring.");
        }
    }
    
    private void removeSelectedDevice() {
        int selectedRow = deviceTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) deviceTableModel.getValueAt(selectedRow, 1);
            if (JOptionPane.showConfirmDialog(this, 
                    "Remove device " + ip + "?", 
                    "Confirm Removal", 
                    JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                
                devices.remove(ip);
                updateDeviceDisplay();
                logMessage("Removed device " + ip, LogLevel.INFO);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Please select a device to remove.");
        }
    }
    
    private void showDeviceProperties() {
        int selectedRow = deviceTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) deviceTableModel.getValueAt(selectedRow, 1);
            NetworkDevice device = devices.get(ip);
            if (device != null) {
                DevicePropertiesDialog dialog = new DevicePropertiesDialog(this, device);
                dialog.setVisible(true);
            }
        }
    }
    
    private void filterDevices() {
        updateDeviceDisplay();
    }
    
    // Alert Management Methods
    private void acknowledgeAllAlerts() {
        alerts.stream()
            .filter(alert -> !alert.isResolved())
            .forEach(alert -> alert.setAcknowledged(true));
        
        updateAlertDisplay();
        logMessage("Acknowledged all alerts", LogLevel.INFO);
    }
    
    private void refreshAlerts() {
        updateAlertDisplay();
        logMessage("Alerts refreshed", LogLevel.INFO);
    }
    
    // Log Management Methods
    private void logMessage(String message, LogLevel level) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String logEntry = String.format("[%s] [%s] %s%n", timestamp, level, message);
        
        SwingUtilities.invokeLater(() -> {
            logArea.append(logEntry);
            logArea.setCaretPosition(logArea.getDocument().getLength());
            
            // Keep log size manageable
            String text = logArea.getText();
            String[] lines = text.split("\n");
            if (lines.length > 1000) {
                // Remove first 100 lines
                StringBuilder sb = new StringBuilder();
                for (int i = 100; i < lines.length; i++) {
                    sb.append(lines[i]).append("\n");
                }
                logArea.setText(sb.toString());
            }
        });
        
        // Also log to Java logger
        switch (level) {
            case ERROR -> logger.severe(message);
            case WARNING -> logger.warning(message);
            case INFO -> logger.info(message);
            case DEBUG -> logger.fine(message);
        }
        
        statusLabel.setText(message);
    }
    
    private void clearLogs() {
        if (JOptionPane.showConfirmDialog(this, 
                "Clear all logs?", 
                "Clear Logs", 
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            logArea.setText("");
            logMessage("Logs cleared", LogLevel.INFO);
        }
    }
    
    private void exportLogs() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text Files", "txt"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (PrintWriter writer = new PrintWriter(file)) {
                writer.print(logArea.getText());
                JOptionPane.showMessageDialog(this, "Logs exported to " + file.getName());
                logMessage("Logs exported to " + file.getName(), LogLevel.INFO);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, 
                    "Failed to export logs: " + e.getMessage(), 
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    // Utility Methods
    private String getStatusIcon(DeviceStatus status) {
        return switch (status) {
            case ONLINE -> "🟢";
            case OFFLINE -> "🔴";
            case UNKNOWN -> "🟡";
        };
    }
    
    private String getSeverityIcon(AlertSeverity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case WARNING -> "🟡";
            case INFO -> "🔵";
        };
    }
    
    private String formatTimeDifference(Date lastUpdate) {
        long diff = System.currentTimeMillis() - lastUpdate.getTime();
        long seconds = diff / 1000;
        
        if (seconds < 60) {
            return seconds + "s ago";
        } else if (seconds < 3600) {
            return (seconds / 60) + "m ago";
        } else {
            return (seconds / 3600) + "h ago";
        }
    }
    
    // File I/O Methods
    private int importDevicesFromFile(File file) throws IOException {
        int imported = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                
                String[] parts = line.split(",");
                if (parts.length >= 1) {
                    String ip = parts[0].trim();
                    String hostname = parts.length > 1 ? parts[1].trim() : "Imported";
                    String osType = parts.length > 2 ? parts[2].trim() : "Unknown";
                    
                    try {
                        InetAddress.getByName(ip); // Validate IP
                        NetworkDevice device = new NetworkDevice(ip, hostname, osType);
                        devices.put(ip, device);
                        imported++;
                    } catch (UnknownHostException e) {
                        logMessage("Invalid IP address: " + ip, LogLevel.WARNING);
                    }
                }
            }
        }
        return imported;
    }
    
    private void generateReport(File file) throws IOException {
        try (PrintWriter writer = new PrintWriter(file)) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html><head><title>Network Management Report</title>");
            writer.println("<style>");
            writer.println("body { font-family: Arial, sans-serif; margin: 20px; }");
            writer.println(".header { background-color: #007bff; color: white; padding: 20px; }");
            writer.println(".summary { display: flex; justify-content: space-around; margin: 20px 0; }");
            writer.println(".metric { text-align: center; padding: 15px; background-color: #f8f9fa; }");
            writer.println("table { width: 100%; border-collapse: collapse; margin-top: 20px; }");
            writer.println("th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }");
            writer.println("th { background-color: #007bff; color: white; }");
            writer.println("</style></head><body>");
            
            writer.println("<div class='header'>");
            writer.println("<h1>Network Management System Report</h1>");
            writer.println("<p>Generated on: " + new Date() + "</p>");
            writer.println("</div>");
            
            writer.println("<div class='summary'>");
            writer.println("<div class='metric'><h3>" + devices.size() + "</h3><p>Total Devices</p></div>");
            
            long monitored = devices.values().stream().filter(NetworkDevice::isMonitoringEnabled).count();
            writer.println("<div class='metric'><h3>" + monitored + "</h3><p>Monitored Devices</p></div>");
            
            long activeAlerts = alerts.stream().filter(alert -> !alert.isResolved()).count();
            writer.println("<div class='metric'><h3>" + activeAlerts + "</h3><p>Active Alerts</p></div>");
            writer.println("</div>");
            
            writer.println("<h2>Device Details</h2>");
            writer.println("<table>");
            writer.println("<tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Status</th><th>Monitoring</th><th>CPU %</th><th>Memory %</th></tr>");
            
            for (NetworkDevice device : devices.values()) {
                writer.printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.1f</td><td>%.1f</td></tr>%n",
                    device.getIpAddress(),
                    device.getHostname(),
                    device.getOsType(),
                    device.getStatus(),
                    device.isMonitoringEnabled() ? "Yes" : "No",
                    device.getCpuUsage(),
                    device.getMemoryUsage()
                );
            }
            
            writer.println("</table>");
            writer.println("</body></html>");
        }
    }
    
    private void loadConfiguration() {
        // Load configuration from file or use defaults
        try {
            configManager.loadConfiguration();
            isDarkTheme = configManager.getBoolean("gui.darkTheme", false);
            autoRefresh = configManager.getBoolean("gui.autoRefresh", true);
            monitoringInterval = configManager.getInt("monitoring.interval", 5000);
            
            // Apply loaded theme
            themeManager.applyTheme(this, isDarkTheme);
            
        } catch (Exception e) {
            logMessage("Failed to load configuration: " + e.getMessage(), LogLevel.WARNING);
        }
    }
    
    private void cleanup() {
        try {
            monitoringService.stop();
            configManager.saveConfiguration();
            logMessage("Application shutdown completed", LogLevel.INFO);
        } catch (Exception e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        // Set system look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeel());
        } catch (Exception e) {
            // Fall back to default look and feel
        }
        
        // Create and show the application
        SwingUtilities.invokeLater(() -> {
            new NetworkManagementSystem().setVisible(true);
        });
    }
}

// Supporting Classes

// Enums
enum DeviceStatus {
    ONLINE, OFFLINE, UNKNOWN
}

enum AlertSeverity {
    CRITICAL, WARNING, INFO
}

enum LogLevel {
    ERROR, WARNING, INFO, DEBUG
}

// Data Classes
class NetworkDevice {
    private String ipAddress;
    private String hostname;
    private String osType;
    private DeviceStatus status;
    private boolean monitoringEnabled;
    private double cpuUsage;
    private double memoryUsage;
    private double diskUsage;
    private Date lastUpdate;
    
    public NetworkDevice(String ipAddress, String hostname, String osType) {
        this.ipAddress = ipAddress;
        this.hostname = hostname;
        this.osType = osType;
        this.status = DeviceStatus.UNKNOWN;
        this.monitoringEnabled = false;
        this.cpuUsage = 0.0;
        this.memoryUsage = 0.0;
        this.diskUsage = 0.0;
    }
    
    // Getters and setters
    public String getIpAddress() { return ipAddress; }
    public String getHostname() { return hostname; }
    public String getOsType() { return osType; }
    public DeviceStatus getStatus() { return status; }
    public void setStatus(DeviceStatus status) { this.status = status; }
    public boolean isMonitoringEnabled() { return monitoringEnabled; }
    public void setMonitoringEnabled(boolean enabled) { this.monitoringEnabled = enabled; }
    public double getCpuUsage() { return cpuUsage; }
    public void setCpuUsage(double cpuUsage) { this.cpuUsage = cpuUsage; }
    public double getMemoryUsage() { return memoryUsage; }
    public void setMemoryUsage(double memoryUsage) { this.memoryUsage = memoryUsage; }
    public double getDiskUsage() { return diskUsage; }
    public void setDiskUsage(double diskUsage) { this.diskUsage = diskUsage; }
    public Date getLastUpdate() { return lastUpdate; }
    public void setLastUpdate(Date lastUpdate) { this.lastUpdate = lastUpdate; }
}

class Alert {
    private String id;
    private String deviceIP;
    private String metric;
    private AlertSeverity severity;
    private double value;
    private double threshold;
    private Date timestamp;
    private boolean acknowledged;
    private boolean resolved;
    
    public Alert(String deviceIP, String metric, AlertSeverity severity, double value, double threshold) {
        this.id = UUID.randomUUID().toString();
        this.deviceIP = deviceIP;
        this.metric = metric;
        this.severity = severity;
        this.value = value;
        this.threshold = threshold;
        this.timestamp = new Date();
        this.acknowledged = false;
        this.resolved = false;
    }
    
    // Getters and setters
    public String getId() { return id; }
    public String getDeviceIP() { return deviceIP; }
    public String getMetric() { return metric; }
    public AlertSeverity getSeverity() { return severity; }
    public double getValue() { return value; }
    public double getThreshold() { return threshold; }
    public Date getTimestamp() { return timestamp; }
    public boolean isAcknowledged() { return acknowledged; }
    public void setAcknowledged(boolean acknowledged) { this.acknowledged = acknowledged; }
    public boolean isResolved() { return resolved; }
    public void setResolved(boolean resolved) { this.resolved = resolved; }
    
    @Override
    public String toString() {
        return String.format("%s alert for %s: %s = %.1f (threshold: %.1f)", 
            severity, deviceIP, metric, value, threshold);
    }
}

// Service Classes
class NetworkScanner {
    public boolean pingHost(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.isReachable(3000); // 3 second timeout
        } catch (Exception e) {
            return false;
        }
    }
    
    public List<NetworkDevice> scanNetwork(String networkRange) {
        List<NetworkDevice> devices = new ArrayList<>();
        
        try {
            // Simple implementation for common network ranges
            String baseIP = networkRange.split("/")[0];
            String[] parts = baseIP.split("\\.");
            
            if (parts.length == 4) {
                String network = parts[0] + "." + parts[1] + "." + parts[2] + ".";
                
                // Scan first 254 addresses
                for (int i = 1; i <= 254; i++) {
                    String ip = network + i;
                    if (pingHost(ip)) {
                        String hostname = getHostname(ip);
                        String osType = detectOS(ip);
                        NetworkDevice device = new NetworkDevice(ip, hostname, osType);
                        device.setStatus(DeviceStatus.ONLINE);
                        devices.add(device);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Network scan error: " + e.getMessage());
        }
        
        return devices;
    }
    
    private String getHostname(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            String hostname = address.getHostName();
            return hostname.equals(ip) ? "Unknown" : hostname;
        } catch (Exception e) {
            return "Unknown";
        }
    }
    
    private String detectOS(String ip) {
        // Simple OS detection would require more complex implementation
        // For now, return "Unknown"
        return "Unknown";
    }
}

class MonitoringService {
    private final List<NetworkDevice> monitoredDevices;
    private final List<MonitoringListener> listeners;
    private final ScheduledExecutorService scheduler;
    private final Random random;
    private boolean running;
    
    public MonitoringService() {
        this.monitoredDevices = new ArrayList<>();
        this.listeners = new ArrayList<>();
        this.scheduler = Executors.newScheduledThreadPool(2);
        this.random = new Random();
        this.running = false;
    }
    
    public void start() {
        if (!running) {
            running = true;
            scheduler.scheduleAtFixedRate(this::simulateMetrics, 0, 5, TimeUnit.SECONDS);
        }
    }
    
    public void stop() {
        running = false;
        scheduler.shutdown();
    }
    
    public void addDevice(NetworkDevice device) {
        synchronized (monitoredDevices) {
            if (!monitoredDevices.contains(device)) {
                monitoredDevices.add(device);
            }
        }
    }
    
    public void removeDevice(NetworkDevice device) {
        synchronized (monitoredDevices) {
            monitoredDevices.remove(device);
        }
    }
    
    public void addMonitoringListener(MonitoringListener listener) {
        listeners.add(listener);
    }
    
    private void simulateMetrics() {
        synchronized (monitoredDevices) {
            for (NetworkDevice device : monitoredDevices) {
                if (device.isMonitoringEnabled()) {
                    // Simulate realistic metrics
                    double cpu = Math.max(0, Math.min(100, device.getCpuUsage() + (random.nextGaussian() * 5)));
                    double memory = Math.max(0, Math.min(100, device.getMemoryUsage() + (random.nextGaussian() * 3)));
                    double disk = Math.max(0, Math.min(100, device.getDiskUsage() + (random.nextGaussian() * 1)));
                    
                    // Notify listeners
                    for (MonitoringListener listener : listeners) {
                        listener.onMetricUpdate(device.getIpAddress(), "cpu", cpu);
                        listener.onMetricUpdate(device.getIpAddress(), "memory", memory);
                        listener.onMetricUpdate(device.getIpAddress(), "disk", disk);
                    }
                }
            }
        }
    }
}

interface MonitoringListener {
    void onMetricUpdate(String deviceIP, String metric, double value);
    void onDeviceStatusChange(String deviceIP, DeviceStatus status);
}

class AlertManager {
    private final Map<String, Double> cpuThresholds;
    private final Map<String, Double> memoryThresholds;
    private final List<AlertListener> listeners;
    
    public AlertManager() {
        this.cpuThresholds = new HashMap<>();
        this.memoryThresholds = new HashMap<>();
        this.listeners = new ArrayList<>();
        
        // Default thresholds
        cpuThresholds.put("warning", 80.0);
        cpuThresholds.put("critical", 95.0);
        memoryThresholds.put("warning", 85.0);
        memoryThresholds.put("critical", 95.0);
    }
    
    public void checkThreshold(String deviceIP, String metric, double value) {
        Map<String, Double> thresholds = switch (metric.toLowerCase()) {
            case "cpu" -> cpuThresholds;
            case "memory" -> memoryThresholds;
            default -> null;
        };
        
        if (thresholds != null) {
            if (value >= thresholds.get("critical")) {
                Alert alert = new Alert(deviceIP, metric, AlertSeverity.CRITICAL, value, thresholds.get("critical"));
                notifyListeners(alert);
            } else if (value >= thresholds.get("warning")) {
                Alert alert = new Alert(deviceIP, metric, AlertSeverity.WARNING, value, thresholds.get("warning"));
                notifyListeners(alert);
            }
        }
    }
    
    public void addAlertListener(AlertListener listener) {
        listeners.add(listener);
    }
    
    private void notifyListeners(Alert alert) {
        for (AlertListener listener : listeners) {
            listener.onAlertTriggered(alert);
        }
    }
    
    public void setThreshold(String metric, String level, double value) {
        switch (metric.toLowerCase()) {
            case "cpu" -> cpuThresholds.put(level, value);
            case "memory" -> memoryThresholds.put(level, value);
        }
    }
    
    public double getThreshold(String metric, String level) {
        return switch (metric.toLowerCase()) {
            case "cpu" -> cpuThresholds.getOrDefault(level, 0.0);
            case "memory" -> memoryThresholds.getOrDefault(level, 0.0);
            default -> 0.0;
        };
    }
}

interface AlertListener {
    void onAlertTriggered(Alert alert);
    void onAlertResolved(Alert alert);
}

class DatabaseManager {
    // Simplified database simulation using in-memory storage
    private final Map<String, String> properties;
    
    public DatabaseManager() {
        this.properties = new HashMap<>();
    }
    
    public void saveProperty(String key, String value) {
        properties.put(key, value);
    }
    
    public String getProperty(String key, String defaultValue) {
        return properties.getOrDefault(key, defaultValue);
    }
}

class ConfigManager {
    private final Properties config;
    private final String configFile = "network_monitor.properties";
    
    public ConfigManager() {
        this.config = new Properties();
    }
    
    public void loadConfiguration() throws IOException {
        File file = new File(configFile);
        if (file.exists()) {
            try (FileInputStream fis = new FileInputStream(file)) {
                config.load(fis);
            }
        }
    }
    
    public void saveConfiguration() throws IOException {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            config.store(fos, "Network Monitor Configuration");
        }
    }
    
    public boolean getBoolean(String key, boolean defaultValue) {
        String value = config.getProperty(key);
        return value != null ? Boolean.parseBoolean(value) : defaultValue;
    }
    
    public int getInt(String key, int defaultValue) {
        String value = config.getProperty(key);
        try {
            return value != null ? Integer.parseInt(value) : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
    
    public void setProperty(String key, String value) {
        config.setProperty(key, value);
    }
}

class ThemeManager {
    public void applyTheme(JFrame frame, boolean isDark) {
        Color bgColor = isDark ? new Color(45, 45, 45) : Color.WHITE;
        Color fgColor = isDark ? Color.WHITE : Color.BLACK;
        Color accentColor = isDark ? new Color(0, 188, 242) : new Color(0, 123, 255);
        
        // Apply colors recursively to all components
        applyThemeToComponent(frame, bgColor, fgColor, accentColor);
        frame.repaint();
    }
    
    private void applyThemeToComponent(Container container, Color bg, Color fg, Color accent) {
        container.setBackground(bg);
        container.setForeground(fg);
        
        for (Component component : container.getComponents()) {
            component.setBackground(bg);
            component.setForeground(fg);
            
            if (component instanceof JButton) {
                component.setBackground(accent);
                component.setForeground(Color.WHITE);
            }
            
            if (component instanceof Container) {
                applyThemeToComponent((Container) component, bg, fg, accent);
            }
        }
    }
}

// Custom Renderers
class StatusCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, 
            boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        setHorizontalAlignment(CENTER);
        return this;
    }
}

class AlertSeverityRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, 
            boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        String text = value.toString();
        if (text.contains("CRITICAL")) {
            setForeground(Color.RED);
        } else if (text.contains("WARNING")) {
            setForeground(Color.ORANGE);
        } else {
            setForeground(Color.BLUE);
        }
        
        return this;
    }
}

// Custom Chart Panel (simplified)
class ChartPanel extends JPanel {
    private final String title;
    private final Color color;
    private final List<Double> values;
    private final Random random;
    
    public ChartPanel(String title, Color color) {
        this.title = title;
        this.color = color;
        this.values = new ArrayList<>();
        this.random = new Random();
        
        // Initialize with some random data
        for (int i = 0; i < 50; i++) {
            values.add(random.nextDouble() * 100);
        }
        
        // Update chart periodically
        Timer timer = new Timer(2000, e -> {
            values.add(random.nextDouble() * 100);
            if (values.size() > 50) {
                values.remove(0);
            }
            repaint();
        });
        timer.start();
    }
    
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        int width = getWidth();
        int height = getHeight();
        int margin = 40;
        
        // Draw background
        g2d.setColor(getBackground());
        g2d.fillRect(0, 0, width, height);
        
        // Draw title
        g2d.setColor(getForeground());
        g2d.setFont(getFont().deriveFont(Font.BOLD, 14f));
        FontMetrics fm = g2d.getFontMetrics();
        int titleWidth = fm.stringWidth(title);
        g2d.drawString(title, (width - titleWidth) / 2, 20);
        
        // Draw chart
        if (values.size() > 1) {
            g2d.setColor(color);
            g2d.setStroke(new BasicStroke(2f));
            
            int chartWidth = width - 2 * margin;
            int chartHeight = height - 2 * margin;
            
            for (int i = 1; i < values.size(); i++) {
                int x1 = margin + (i - 1) * chartWidth / (values.size() - 1);
                int y1 = margin + chartHeight - (int) (values.get(i - 1) * chartHeight / 100);
                int x2 = margin + i * chartWidth / (values.size() - 1);
                int y2 = margin + chartHeight - (int) (values.get(i) * chartHeight / 100);
                
                g2d.drawLine(x1, y1, x2, y2);
            }
        }
        
        g2d.dispose();
    }
}

// Dialog Classes
class DeviceSetupDialog extends JDialog {
    public DeviceSetupDialog(JFrame parent, Map<String, NetworkDevice> devices) {
        super(parent, "Device Setup", true);
        setSize(400, 300);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel label = new JLabel("Device Setup Configuration", JLabel.CENTER);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 16f));
        panel.add(label, BorderLayout.NORTH);
        
        JTextArea infoArea = new JTextArea();
        infoArea.setText("Device setup functionality would be implemented here.\n\n" +
                        "Features would include:\n" +
                        "- SSH connection setup\n" +
                        "- Credential management\n" +
                        "- Monitoring configuration\n" +
                        "- Bulk device setup");
        infoArea.setEditable(false);
        infoArea.setOpaque(false);
        panel.add(new JScrollPane(infoArea), BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());
        buttonPanel.add(closeButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
}

class AlertsDashboardDialog extends JDialog {
    public AlertsDashboardDialog(JFrame parent, List<Alert> alerts) {
        super(parent, "Alerts Dashboard", true);
        setSize(800, 600);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("Alerts Dashboard", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Summary panel
        JPanel summaryPanel = new JPanel(new GridLayout(1, 3, 10, 10));
        summaryPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        long criticalCount = alerts.stream().filter(a -> a.getSeverity() == AlertSeverity.CRITICAL && !a.isResolved()).count();
        long warningCount = alerts.stream().filter(a -> a.getSeverity() == AlertSeverity.WARNING && !a.isResolved()).count();
        long totalCount = alerts.stream().filter(a -> !a.isResolved()).count();
        
        summaryPanel.add(createSummaryCard("Critical", String.valueOf(criticalCount), Color.RED));
        summaryPanel.add(createSummaryCard("Warning", String.valueOf(warningCount), Color.ORANGE));
        summaryPanel.add(createSummaryCard("Total", String.valueOf(totalCount), Color.BLUE));
        
        panel.add(summaryPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());
        buttonPanel.add(closeButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
    
    private JPanel createSummaryCard(String title, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(color, 2),
            BorderFactory.createEmptyBorder(20, 20, 20, 20)
        ));
        
        JLabel titleLabel = new JLabel(title, JLabel.CENTER);
        JLabel valueLabel = new JLabel(value, JLabel.CENTER);
        valueLabel.setFont(valueLabel.getFont().deriveFont(Font.BOLD, 32f));
        valueLabel.setForeground(color);
        
        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        
        return card;
    }
}

class AlertConfigDialog extends JDialog {
    private final AlertManager alertManager;
    
    public AlertConfigDialog(JFrame parent, AlertManager alertManager) {
        super(parent, "Alert Configuration", true);
        this.alertManager = alertManager;
        setSize(500, 400);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("Alert Threshold Configuration", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Configuration panel
        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // CPU thresholds
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("CPU Warning Threshold:"), gbc);
        gbc.gridx = 1;
        JSpinner cpuWarningSpinner = new JSpinner(new SpinnerNumberModel(
            alertManager.getThreshold("cpu", "warning"), 0.0, 100.0, 1.0));
        configPanel.add(cpuWarningSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("CPU Critical Threshold:"), gbc);
        gbc.gridx = 1;
        JSpinner cpuCriticalSpinner = new JSpinner(new SpinnerNumberModel(
            alertManager.getThreshold("cpu", "critical"), 0.0, 100.0, 1.0));
        configPanel.add(cpuCriticalSpinner, gbc);
        
        // Memory thresholds
        gbc.gridx = 0; gbc.gridy = 2;
        configPanel.add(new JLabel("Memory Warning Threshold:"), gbc);
        gbc.gridx = 1;
        JSpinner memoryWarningSpinner = new JSpinner(new SpinnerNumberModel(
            alertManager.getThreshold("memory", "warning"), 0.0, 100.0, 1.0));
        configPanel.add(memoryWarningSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        configPanel.add(new JLabel("Memory Critical Threshold:"), gbc);
        gbc.gridx = 1;
        JSpinner memoryCriticalSpinner = new JSpinner(new SpinnerNumberModel(
            alertManager.getThreshold("memory", "critical"), 0.0, 100.0, 1.0));
        configPanel.add(memoryCriticalSpinner, gbc);
        
        panel.add(configPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            alertManager.setThreshold("cpu", "warning", (Double) cpuWarningSpinner.getValue());
            alertManager.setThreshold("cpu", "critical", (Double) cpuCriticalSpinner.getValue());
            alertManager.setThreshold("memory", "warning", (Double) memoryWarningSpinner.getValue());
            alertManager.setThreshold("memory", "critical", (Double) memoryCriticalSpinner.getValue());
            
            JOptionPane.showMessageDialog(this, "Alert configuration saved successfully!");
            dispose();
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
}

class PerformanceMonitorDialog extends JDialog {
    public PerformanceMonitorDialog(JFrame parent, Map<String, NetworkDevice> devices) {
        super(parent, "Performance Monitor", true);
        setSize(900, 700);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("Performance Monitor", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Performance charts
        JPanel chartsPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        chartsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        chartsPanel.add(new ChartPanel("System CPU Usage", Color.BLUE));
        chartsPanel.add(new ChartPanel("Memory Usage", Color.GREEN));
        chartsPanel.add(new ChartPanel("Network Throughput", Color.ORANGE));
        chartsPanel.add(new ChartPanel("Disk I/O", Color.RED));
        
        panel.add(chartsPanel, BorderLayout.CENTER);
        
        // Controls
        JPanel controlPanel = new JPanel(new FlowLayout());
        
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> {
            // Refresh charts
            chartsPanel.repaint();
        });
        
        JButton exportButton = new JButton("Export Data");
        exportButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(this, "Export functionality would be implemented here.");
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());
        
        controlPanel.add(refreshButton);
        controlPanel.add(exportButton);
        controlPanel.add(closeButton);
        panel.add(controlPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
}

class PreferencesDialog extends JDialog {
    private final ConfigManager configManager;
    
    public PreferencesDialog(JFrame parent, ConfigManager configManager) {
        super(parent, "Preferences", true);
        this.configManager = configManager;
        setSize(400, 300);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("Application Preferences", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Preferences panel
        JPanel prefsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Dark theme checkbox
        gbc.gridx = 0; gbc.gridy = 0;
        JCheckBox darkThemeBox = new JCheckBox("Dark Theme");
        darkThemeBox.setSelected(configManager.getBoolean("gui.darkTheme", false));
        prefsPanel.add(darkThemeBox, gbc);
        
        // Auto refresh checkbox
        gbc.gridy = 1;
        JCheckBox autoRefreshBox = new JCheckBox("Auto Refresh");
        autoRefreshBox.setSelected(configManager.getBoolean("gui.autoRefresh", true));
        prefsPanel.add(autoRefreshBox, gbc);
        
        // Monitoring interval
        gbc.gridy = 2;
        prefsPanel.add(new JLabel("Monitoring Interval (seconds):"), gbc);
        gbc.gridx = 1;
        JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(
            configManager.getInt("monitoring.interval", 5000) / 1000, 1, 300, 1));
        prefsPanel.add(intervalSpinner, gbc);
        
        panel.add(prefsPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            configManager.setProperty("gui.darkTheme", String.valueOf(darkThemeBox.isSelected()));
            configManager.setProperty("gui.autoRefresh", String.valueOf(autoRefreshBox.isSelected()));
            configManager.setProperty("monitoring.interval", String.valueOf((Integer) intervalSpinner.getValue() * 1000));
            
            try {
                configManager.saveConfiguration();
                JOptionPane.showMessageDialog(this, "Preferences saved successfully!");
                dispose();
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Failed to save preferences: " + ex.getMessage());
            }
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
}

class DevicePropertiesDialog extends JDialog {
    public DevicePropertiesDialog(JFrame parent, NetworkDevice device) {
        super(parent, "Device Properties - " + device.getIpAddress(), true);
        setSize(500, 400);
        setLocationRelativeTo(parent);
        
        JPanel panel = new JPanel(new BorderLayout());
        
        JLabel titleLabel = new JLabel("Device Properties", JLabel.CENTER);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        titleLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(titleLabel, BorderLayout.NORTH);
        
        // Properties panel
        JPanel propsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        String[][] properties = {
            {"IP Address:", device.getIpAddress()},
            {"Hostname:", device.getHostname()},
            {"Operating System:", device.getOsType()},
            {"Status:", device.getStatus().toString()},
            {"Monitoring:", device.isMonitoringEnabled() ? "Enabled" : "Disabled"},
            {"CPU Usage:", String.format("%.1f%%", device.getCpuUsage())},
            {"Memory Usage:", String.format("%.1f%%", device.getMemoryUsage())},
            {"Disk Usage:", String.format("%.1f%%", device.getDiskUsage())},
            {"Last Update:", device.getLastUpdate() != null ? device.getLastUpdate().toString() : "Never"}
        };
        
        for (int i = 0; i < properties.length; i++) {
            gbc.gridx = 0; gbc.gridy = i;
            JLabel label = new JLabel(properties[i][0]);
            label.setFont(label.getFont().deriveFont(Font.BOLD));
            propsPanel.add(label, gbc);
            
            gbc.gridx = 1;
            propsPanel.add(new JLabel(properties[i][1]), gbc);
        }
        
        panel.add(propsPanel, BorderLayout.CENTER);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> {
            // Refresh device properties
            dispose();
            new DevicePropertiesDialog(parent, device).setVisible(true);
        });
        
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());
        
        buttonPanel.add(refreshButton);
        buttonPanel.add(closeButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        add(panel);
    }
}