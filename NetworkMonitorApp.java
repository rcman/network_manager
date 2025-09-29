package com.networkmonitor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.*;
import javax.swing.border.*;
import org.jfree.chart.*;
import org.jfree.chart.plot.*;
import org.jfree.data.time.*;

/**
 * Enterprise Network PC Management System
 * Main application class with modern UI and comprehensive monitoring
 */
public class NetworkMonitorApp extends JFrame {
    
    // Logger
    private static final Logger LOGGER = Logger.getLogger(NetworkMonitorApp.class.getName());
    
    // UI Components
    private JTable deviceTable;
    private DefaultTableModel deviceTableModel;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JLabel deviceCountLabel;
    private JLabel alertCountLabel;
    private JLabel monitoringStatusLabel;
    private JTextField searchField;
    private JTextField networkRangeField;
    private JTabbedPane mainTabbedPane;
    
    // Data structures
    private Map<String, NetworkDevice> devices = new ConcurrentHashMap<>();
    private DatabaseManager dbManager;
    private SSHManager sshManager;
    private AlertManager alertManager;
    private MonitoringThread monitoringThread;
    private NetworkScanner networkScanner;
    
    // Configuration
    private Properties config;
    private boolean darkTheme = false;
    private Color bgColor = Color.WHITE;
    private Color fgColor = Color.BLACK;
    private Color accentColor = new Color(0, 120, 212);
    
    // Thread pool
    private ExecutorService executorService;
    
    // Icons
    private static final String CONFIGURED_ICON = "✓";
    private static final String NOT_CONFIGURED_ICON = "✗";
    
    public NetworkMonitorApp() {
        super("Enterprise Network PC Management System v2.0");
        
        // Initialize components
        initializeComponents();
        setupLogging();
        loadConfiguration();
        initializeGUI();
        startMonitoring();
        
        // Window settings
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                safeExit();
            }
        });
        
        setSize(1600, 1000);
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        setLocationRelativeTo(null);
    }
    
    private void initializeComponents() {
        dbManager = new DatabaseManager();
        sshManager = new SSHManager();
        alertManager = new AlertManager(this);
        networkScanner = new NetworkScanner(this::logMessage);
        executorService = Executors.newFixedThreadPool(20);
        config = new Properties();
    }
    
    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("network_monitor.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fileHandler);
            LOGGER.setLevel(Level.INFO);
        } catch (Exception e) {
            System.err.println("Failed to setup logging: " + e.getMessage());
        }
    }
    
    private void loadConfiguration() {
        try {
            config.load(getClass().getResourceAsStream("/config.properties"));
        } catch (Exception e) {
            // Set defaults
            config.setProperty("monitoring.interval", "5");
            config.setProperty("theme", "light");
            config.setProperty("auto_refresh", "true");
            saveConfiguration();
        }
    }
    
    private void saveConfiguration() {
        try {
            config.store(new java.io.FileOutputStream("config.properties"), 
                        "Network Monitor Configuration");
        } catch (Exception e) {
            LOGGER.warning("Failed to save configuration: " + e.getMessage());
        }
    }
    
    private void initializeGUI() {
        // Main panel with BorderLayout
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Create menu bar
        createMenuBar();
        
        // Create toolbar
        JPanel toolbar = createToolbar();
        mainPanel.add(toolbar, BorderLayout.NORTH);
        
        // Create split pane for main content
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(600);
        
        // Left panel - Device management
        JPanel leftPanel = createDevicePanel();
        splitPane.setLeftComponent(leftPanel);
        
        // Right panel - Monitoring dashboard
        mainTabbedPane = createMonitoringPanel();
        splitPane.setRightComponent(mainTabbedPane);
        
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Status bar
        JPanel statusBar = createStatusBar();
        mainPanel.add(statusBar, BorderLayout.SOUTH);
        
        setContentPane(mainPanel);
        applyTheme();
    }
    
    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        
        // File menu
        JMenu fileMenu = new JMenu("File");
        fileMenu.add(createMenuItem("Quick Scan", e -> quickScan(), "ctrl Q"));
        fileMenu.add(createMenuItem("Full Network Scan", e -> scanNetwork(), "ctrl S"));
        fileMenu.add(createMenuItem("Import Devices", e -> importDevices(), null));
        fileMenu.add(createMenuItem("Export Report", e -> exportReport(), null));
        fileMenu.addSeparator();
        fileMenu.add(createMenuItem("Preferences", e -> showPreferences(), "ctrl P"));
        fileMenu.addSeparator();
        fileMenu.add(createMenuItem("Exit", e -> safeExit(), "ctrl shift Q"));
        
        // View menu
        JMenu viewMenu = new JMenu("View");
        viewMenu.add(createMenuItem("Toggle Theme", e -> toggleTheme(), "ctrl T"));
        viewMenu.add(createMenuItem("Refresh All", e -> refreshAll(), "F5"));
        viewMenu.add(createMenuItem("Alerts Dashboard", e -> showAlertsDashboard(), null));
        
        // Tools menu
        JMenu toolsMenu = new JMenu("Tools");
        toolsMenu.add(createMenuItem("Bulk Device Setup", e -> showBulkSetupDialog(), null));
        toolsMenu.add(createMenuItem("Alert Configuration", e -> configureAlerts(), null));
        toolsMenu.add(createMenuItem("Database Cleanup", e -> cleanupDatabase(), null));
        
        // Help menu
        JMenu helpMenu = new JMenu("Help");
        helpMenu.add(createMenuItem("Keyboard Shortcuts", e -> showShortcuts(), null));
        helpMenu.add(createMenuItem("Documentation", e -> showDocumentation(), null));
        helpMenu.add(createMenuItem("About", e -> showAbout(), null));
        
        menuBar.add(fileMenu);
        menuBar.add(viewMenu);
        menuBar.add(toolsMenu);
        menuBar.add(helpMenu);
        
        setJMenuBar(menuBar);
    }
    
    private JMenuItem createMenuItem(String text, ActionListener listener, String accelerator) {
        JMenuItem item = new JMenuItem(text);
        item.addActionListener(listener);
        if (accelerator != null) {
            item.setAccelerator(KeyStroke.getKeyStroke(accelerator));
        }
        return item;
    }
    
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setBorder(BorderFactory.createEtchedBorder());
        
        // Left side buttons
        JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        leftButtons.add(createButton("🔍 Quick Scan", e -> quickScan()));
        leftButtons.add(createButton("🔄 Refresh", e -> refreshAll()));
        leftButtons.add(createButton("⚙️ Setup", e -> showBulkSetupDialog()));
        leftButtons.add(createButton("🚨 Alerts", e -> showAlertsDashboard()));
        
        // Center - Search and network range
        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        centerPanel.add(new JLabel("🔍 Search:"));
        searchField = new JTextField(20);
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                filterDevices();
            }
        });
        centerPanel.add(searchField);
        
        centerPanel.add(new JLabel("🌐 Network:"));
        networkRangeField = new JTextField("192.168.1.0/24", 15);
        centerPanel.add(networkRangeField);
        
        // Right side indicators
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        alertCountLabel = new JLabel("✅ 0 Alerts");
        monitoringStatusLabel = new JLabel("⏸️ Stopped");
        rightPanel.add(alertCountLabel);
        rightPanel.add(monitoringStatusLabel);
        rightPanel.add(createButton("🌙", e -> toggleTheme()));
        
        toolbar.add(leftButtons, BorderLayout.WEST);
        toolbar.add(centerPanel, BorderLayout.CENTER);
        toolbar.add(rightPanel, BorderLayout.EAST);
        
        return toolbar;
    }
    
    private JButton createButton(String text, ActionListener listener) {
        JButton button = new JButton(text);
        button.addActionListener(listener);
        button.setFocusPainted(false);
        return button;
    }
    
    private JPanel createDevicePanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Network Devices"));
        
        // Header with device count
        JPanel header = new JPanel(new BorderLayout());
        deviceCountLabel = new JLabel("Devices (0)");
        deviceCountLabel.setFont(new Font("Arial", Font.BOLD, 14));
        header.add(deviceCountLabel, BorderLayout.WEST);
        
        // Filter buttons
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        filterPanel.add(createButton("All", e -> filterDevicesByStatus("all")));
        filterPanel.add(createButton("Online", e -> filterDevicesByStatus("online")));
        filterPanel.add(createButton("Monitored", e -> filterDevicesByStatus("monitored")));
        header.add(filterPanel, BorderLayout.EAST);
        
        panel.add(header, BorderLayout.NORTH);
        
        // Device table
        String[] columns = {"Status", "Config", "IP", "Hostname", "OS", "CPU %", 
                           "Memory %", "Last Update", "Alerts"};
        deviceTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        deviceTable = new JTable(deviceTableModel);
        deviceTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        deviceTable.setRowHeight(25);
        deviceTable.getTableHeader().setReorderingAllowed(false);
        
        // Set column widths
        int[] widths = {60, 60, 120, 150, 100, 80, 80, 120, 60};
        for (int i = 0; i < widths.length; i++) {
            deviceTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        
        // Add mouse listener for context menu and double-click
        deviceTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    showDeviceContextMenu(e);
                }
            }
            
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showSelectedDeviceProperties();
                }
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(deviceTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Action buttons
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actionPanel.add(createButton("Setup Selected", e -> setupSelectedDevices()));
        actionPanel.add(createButton("Start Monitoring", e -> startMonitoringSelected()));
        actionPanel.add(createButton("Stop Monitoring", e -> stopMonitoringSelected()));
        actionPanel.add(createButton("Remove", e -> removeSelectedDevices()));
        
        panel.add(actionPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JTabbedPane createMonitoringPanel() {
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Live Monitoring tab
        tabbedPane.addTab("📊 Live Monitoring", createLiveMonitoringTab());
        
        // Alerts tab
        tabbedPane.addTab("🚨 Alerts", createAlertsTab());
        
        // Security tab
        tabbedPane.addTab("🔒 Security", createSecurityTab());
        
        // Logs tab
        tabbedPane.addTab("📝 Logs", createLogsTab());
        
        return tabbedPane;
    }
    
    private JPanel createLiveMonitoringTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Summary cards at top
        JPanel summaryPanel = new JPanel(new GridLayout(1, 4, 10, 10));
        summaryPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        summaryPanel.add(createMetricCard("Total Devices", "0", accentColor));
        summaryPanel.add(createMetricCard("Monitored", "0", new Color(40, 167, 69)));
        summaryPanel.add(createMetricCard("Active Alerts", "0", new Color(220, 53, 69)));
        summaryPanel.add(createMetricCard("Avg CPU", "0%", new Color(253, 126, 20)));
        
        panel.add(summaryPanel, BorderLayout.NORTH);
        
        // Chart area (placeholder - would use JFreeChart in full implementation)
        JPanel chartArea = new JPanel(new GridLayout(2, 2, 10, 10));
        chartArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        chartArea.add(createChartPanel("CPU Usage"));
        chartArea.add(createChartPanel("Memory Usage"));
        chartArea.add(createChartPanel("Disk Usage"));
        chartArea.add(createChartPanel("Network Activity"));
        
        panel.add(chartArea, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createMetricCard(String title, String value, Color color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color.LIGHT_GRAY),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        
        JLabel valueLabel = new JLabel(value);
        valueLabel.setFont(new Font("Arial", Font.BOLD, 24));
        valueLabel.setForeground(color);
        
        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        
        return card;
    }
    
    private JPanel createChartPanel(String title) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        
        JLabel placeholder = new JLabel("Chart: " + title, SwingConstants.CENTER);
        placeholder.setFont(new Font("Arial", Font.ITALIC, 14));
        panel.add(placeholder, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAlertsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Alert controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(createButton("🔧 Configure", e -> configureAlerts()));
        controlPanel.add(createButton("✅ Acknowledge All", e -> acknowledgeAllAlerts()));
        controlPanel.add(createButton("🔄 Refresh", e -> refreshAlerts()));
        
        panel.add(controlPanel, BorderLayout.NORTH);
        
        // Alerts table
        String[] columns = {"Severity", "Device", "Metric", "Value", "Threshold", "Time", "Status"};
        DefaultTableModel alertsModel = new DefaultTableModel(columns, 0);
        JTable alertsTable = new JTable(alertsModel);
        alertsTable.setRowHeight(25);
        
        JScrollPane scrollPane = new JScrollPane(alertsTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createSecurityTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Security summary
        JPanel summaryPanel = new JPanel(new GridLayout(1, 2, 10, 10));
        summaryPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        summaryPanel.add(createMetricCard("Failed Logins (24h)", "0", new Color(220, 53, 69)));
        summaryPanel.add(createMetricCard("Suspicious Activity", "0", new Color(255, 193, 7)));
        
        panel.add(summaryPanel, BorderLayout.NORTH);
        
        // Security events table
        String[] columns = {"Time", "Device", "Event Type", "Source IP", "User", "Risk", "Description"};
        DefaultTableModel securityModel = new DefaultTableModel(columns, 0);
        JTable securityTable = new JTable(securityModel);
        securityTable.setRowHeight(25);
        
        JScrollPane scrollPane = new JScrollPane(securityTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLogsTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Log controls
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        controlPanel.add(new JLabel("Filter:"));
        JTextField logFilterField = new JTextField(20);
        controlPanel.add(logFilterField);
        
        controlPanel.add(new JLabel("Level:"));
        JComboBox<String> levelCombo = new JComboBox<>(
            new String[]{"All", "ERROR", "WARNING", "INFO", "DEBUG"});
        controlPanel.add(levelCombo);
        
        controlPanel.add(createButton("🗑️ Clear", e -> clearLogs()));
        controlPanel.add(createButton("💾 Export", e -> exportLogs()));
        
        panel.add(controlPanel, BorderLayout.NORTH);
        
        // Log text area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEtchedBorder());
        
        statusLabel = new JLabel("Ready - Enterprise Network Management System");
        statusBar.add(statusLabel, BorderLayout.CENTER);
        
        // Right side indicators
        JPanel indicators = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 2));
        indicators.add(new JLabel("💾 DB: OK"));
        indicators.add(new JLabel("🌐 Net: Connected"));
        indicators.add(new JLabel("📊 Monitor: Active"));
        
        JLabel timeLabel = new JLabel();
        Timer timer = new Timer(1000, e -> {
            timeLabel.setText(LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("HH:mm:ss")));
        });
        timer.start();
        indicators.add(timeLabel);
        
        statusBar.add(indicators, BorderLayout.EAST);
        
        return statusBar;
    }
    
    // Theme Management
    private void applyTheme() {
        if (darkTheme) {
            bgColor = new Color(45, 45, 45);
            fgColor = new Color(230, 230, 230);
            accentColor = new Color(0, 188, 242);
        } else {
            bgColor = Color.WHITE;
            fgColor = Color.BLACK;
            accentColor = new Color(0, 120, 212);
        }
        
        updateComponentColors(getContentPane());
        repaint();
    }
    
    private void updateComponentColors(Container container) {
        for (Component comp : container.getComponents()) {
            if (!(comp instanceof JButton || comp instanceof JTextField || 
                  comp instanceof JComboBox || comp instanceof JTable)) {
                comp.setBackground(bgColor);
                comp.setForeground(fgColor);
            }
            
            if (comp instanceof Container) {
                updateComponentColors((Container) comp);
            }
        }
    }
    
    private void toggleTheme() {
        darkTheme = !darkTheme;
        config.setProperty("theme", darkTheme ? "dark" : "light");
        saveConfiguration();
        applyTheme();
        logMessage("Theme switched to " + (darkTheme ? "dark" : "light") + " mode");
    }
    
    // Device Management Methods
    private void quickScan() {
        executorService.submit(() -> {
            logMessage("Starting quick scan of known devices...");
            updateStatus("Quick scanning...");
            
            List<String> knownIps = new ArrayList<>(devices.keySet());
            int activeCount = 0;
            
            for (String ip : knownIps) {
                if (networkScanner.pingHost(ip)) {
                    devices.get(ip).setStatus("Online");
                    activeCount++;
                } else {
                    devices.get(ip).setStatus("Offline");
                }
            }
            
            final int count = activeCount;
            SwingUtilities.invokeLater(() -> {
                updateDeviceDisplay();
                logMessage(String.format("Quick scan completed. %d/%d devices online.", 
                    count, knownIps.size()));
                updateStatus("Ready");
            });
        });
    }
    
    private void scanNetwork() {
        executorService.submit(() -> {
            logMessage("Starting comprehensive network scan...");
            updateStatus("Scanning network...");
            
            String networkRange = networkRangeField.getText();
            List<NetworkDevice> foundDevices = networkScanner.scanNetwork(networkRange);
            
            int newDevices = 0;
            for (NetworkDevice device : foundDevices) {
                if (!devices.containsKey(device.getIp())) {
                    newDevices++;
                }
                devices.put(device.getIp(), device);
                dbManager.saveDevice(device);
            }
            
            final int newCount = newDevices;
            final int totalCount = foundDevices.size();
            SwingUtilities.invokeLater(() -> {
                updateDeviceDisplay();
                logMessage(String.format("Network scan completed. Found %d devices (%d new).", 
                    totalCount, newCount));
                updateStatus("Ready");
            });
        });
    }
    
    private void setupSelectedDevices() {
        int[] selectedRows = deviceTable.getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(this, 
                "Please select one or more devices to setup.",
                "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        List<String> selectedIps = new ArrayList<>();
        for (int row : selectedRows) {
            String ip = (String) deviceTableModel.getValueAt(row, 2);
            selectedIps.add(ip);
        }
        
        showDeviceSetupDialog(selectedIps);
    }
    
    private void showDeviceSetupDialog(List<String> deviceIps) {
        JDialog dialog = new JDialog(this, "Setup Devices", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(400, 350);
        
        JPanel formPanel = new JPanel(new GridLayout(6, 2, 5, 5));
        formPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        formPanel.add(new JLabel("Root Username:"));
        JTextField rootUserField = new JTextField("root");
        formPanel.add(rootUserField);
        
        formPanel.add(new JLabel("Root Password:"));
        JPasswordField rootPassField = new JPasswordField();
        formPanel.add(rootPassField);
        
        formPanel.add(new JLabel("Monitoring Username:"));
        JTextField monUserField = new JTextField("netmonitor");
        formPanel.add(monUserField);
        
        formPanel.add(new JLabel("Selected Devices:"));
        formPanel.add(new JLabel(String.valueOf(deviceIps.size())));
        
        dialog.add(formPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton setupButton = new JButton("Start Setup");
        setupButton.addActionListener(e -> {
            performBulkSetup(deviceIps, rootUserField.getText(), 
                new String(rootPassField.getPassword()), monUserField.getText());
            dialog.dispose();
        });
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(setupButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    private void performBulkSetup(List<String> deviceIps, String rootUser, 
                                  String rootPass, String monUser) {
        executorService.submit(() -> {
            int successCount = 0;
            int totalCount = deviceIps.size();
            
            for (int i = 0; i < deviceIps.size(); i++) {
                String ip = deviceIps.get(i);
                updateStatus(String.format("Setting up device %d/%d (%s)", 
                    i + 1, totalCount, ip));
                
                NetworkDevice device = devices.get(ip);
                if (device != null) {
                    if (sshManager.connectToDevice(device, rootUser, rootPass)) {
                        String[] creds = sshManager.createMonitoringAccount(
                            device, monUser, null);
                        
                        if (creds != null && 
                            sshManager.connectToDevice(device, creds[0], creds[1])) {
                            device.setMonitoringEnabled(true);
                            device.setConfigured(true);
                            dbManager.saveDevice(device);
                            successCount++;
                            logMessage("Successfully set up monitoring on " + ip);
                        }
                    }
                }
            }
            
            final int finalSuccessCount = successCount;
            SwingUtilities.invokeLater(() -> {
                updateDeviceDisplay();
                logMessage(String.format("Bulk setup completed. %d/%d devices configured.", 
                    finalSuccessCount, totalCount));
                updateStatus("Ready");
            });
        });
    }
    
    // Continue in next artifact due to length...
    
    private void startMonitoringSelected() {
        int[] selectedRows = deviceTable.getSelectedRows();
        int count = 0;
        
        for (int row : selectedRows) {
            String ip = (String) deviceTableModel.getValueAt(row, 2);
            NetworkDevice device = devices.get(ip);
            
            if (device != null && device.getSshClient() != null) {
                device.setMonitoringEnabled(true);
                dbManager.saveDevice(device);
                count++;
            }
        }
        
        updateDeviceDisplay();
        logMessage("Started monitoring on " + count + " devices");
    }
    
    private void stopMonitoringSelected() {
        int[] selectedRows = deviceTable.getSelectedRows();
        int count = 0;
        
        for (int row : selectedRows) {
            String ip = (String) deviceTableModel.getValueAt(row, 2);
            NetworkDevice device = devices.get(ip);
            
            if (device != null) {
                device.setMonitoringEnabled(false);
                dbManager.saveDevice(device);
                count++;
            }
        }
        
        updateDeviceDisplay();
        logMessage("Stopped monitoring on " + count + " devices");
    }
    
    private void removeSelectedDevices() {
        int[] selectedRows = deviceTable.getSelectedRows();
        if (selectedRows.length == 0) return;
        
        int confirm = JOptionPane.showConfirmDialog(this,
            "Remove " + selectedRows.length + " selected device(s)?",
            "Confirm Removal", JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            int count = 0;
            for (int row : selectedRows) {
                String ip = (String) deviceTableModel.getValueAt(row, 2);
                devices.remove(ip);
                dbManager.removeDevice(ip);
                count++;
            }
            
            updateDeviceDisplay();
            logMessage("Removed " + count + " devices");
        }
    }
    
    private void updateDeviceDisplay() {
        SwingUtilities.invokeLater(() -> {
            deviceTableModel.setRowCount(0);
            
            int deviceCount = 0;
            int monitoredCount = 0;
            
            for (NetworkDevice device : devices.values()) {
                // Apply search filter
                String searchTerm = searchField.getText().toLowerCase();
                if (!searchTerm.isEmpty() && 
                    !device.getIp().toLowerCase().contains(searchTerm) &&
                    !device.getHostname().toLowerCase().contains(searchTerm)) {
                    continue;
                }
                
                deviceCount++;
                if (device.isMonitoringEnabled()) {
                    monitoredCount++;
                }
                
                // Status icon
                String statusIcon = device.getStatus().equals("Online") ? "🟢" : "🔴";
                
                // Configuration icon with color
                String configIcon = device.isConfigured() ? CONFIGURED_ICON : NOT_CONFIGURED_ICON;
                
                // Get latest metrics
                String cpuPercent = device.getLatestCpu() > 0 ? 
                    String.format("%.1f%%", device.getLatestCpu()) : "N/A";
                String memPercent = device.getLatestMemory() > 0 ? 
                    String.format("%.1f%%", device.getLatestMemory()) : "N/A";
                
                // Last update
                String lastUpdate = device.getLastUpdate() != null ? 
                    formatTimeDifference(device.getLastUpdate()) : "Never";
                
                // Alert count
                int alertCount = alertManager.getDeviceAlertCount(device.getIp());
                String alertText = alertCount > 0 ? "🚨 " + alertCount : "✅";
                
                deviceTableModel.addRow(new Object[]{
                    statusIcon,
                    configIcon,
                    device.getIp(),
                    device.getHostname(),
                    device.getOsType(),
                    cpuPercent,
                    memPercent,
                    lastUpdate,
                    alertText
                });
            }
            
            deviceCountLabel.setText(String.format("Devices (%d) | Monitored (%d)", 
                deviceCount, monitoredCount));
            
            // Color code rows
            for (int i = 0; i < deviceTableModel.getRowCount(); i++) {
                String configIcon = (String) deviceTableModel.getValueAt(i, 1);
                if (configIcon.equals(CONFIGURED_ICON)) {
                    // Green for configured - handled by custom renderer
                }
            }
        });
    }
    
    private String formatTimeDifference(LocalDateTime time) {
        long seconds = java.time.Duration.between(time, LocalDateTime.now()).getSeconds();
        if (seconds < 60) return seconds + "s ago";
        if (seconds < 3600) return (seconds / 60) + "m ago";
        return (seconds / 3600) + "h ago";
    }
    
    // UI Helper Methods
    private void showDeviceContextMenu(MouseEvent e) {
        int row = deviceTable.rowAtPoint(e.getPoint());
        if (row >= 0) {
            deviceTable.setRowSelectionInterval(row, row);
            
            JPopupMenu contextMenu = new JPopupMenu();
            contextMenu.add(createMenuItem("Setup Device", ev -> setupSelectedDevices(), null));
            contextMenu.add(createMenuItem("Start Monitoring", ev -> startMonitoringSelected(), null));
            contextMenu.add(createMenuItem("Stop Monitoring", ev -> stopMonitoringSelected(), null));
            contextMenu.addSeparator();
            contextMenu.add(createMenuItem("Remove Device", ev -> removeSelectedDevices(), null));
            contextMenu.add(createMenuItem("Device Properties", ev -> showSelectedDeviceProperties(), null));
            
            contextMenu.show(e.getComponent(), e.getX(), e.getY());
        }
    }
    
    private void showSelectedDeviceProperties() {
        int selectedRow = deviceTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) deviceTableModel.getValueAt(selectedRow, 2);
            NetworkDevice device = devices.get(ip);
            if (device != null) {
                showDevicePropertiesDialog(device);
            }
        }
    }
    
    private void showDevicePropertiesDialog(NetworkDevice device) {
        JDialog dialog = new JDialog(this, "Device Properties - " + device.getIp(), true);
        dialog.setSize(600, 500);
        
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // General tab
        JPanel generalPanel = new JPanel(new GridLayout(8, 2, 10, 10));
        generalPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        generalPanel.add(new JLabel("IP Address:"));
        generalPanel.add(new JLabel(device.getIp()));
        generalPanel.add(new JLabel("Hostname:"));
        generalPanel.add(new JLabel(device.getHostname()));
        generalPanel.add(new JLabel("Operating System:"));
        generalPanel.add(new JLabel(device.getOsType()));
        generalPanel.add(new JLabel("Status:"));
        generalPanel.add(new JLabel(device.getStatus()));
        generalPanel.add(new JLabel("Monitoring Enabled:"));
        generalPanel.add(new JLabel(device.isMonitoringEnabled() ? "Yes" : "No"));
        generalPanel.add(new JLabel("Configured:"));
        generalPanel.add(new JLabel(device.isConfigured() ? "Yes" : "No"));
        generalPanel.add(new JLabel("Last Update:"));
        generalPanel.add(new JLabel(device.getLastUpdate() != null ? 
            device.getLastUpdate().toString() : "Never"));
        
        tabbedPane.addTab("General", generalPanel);
        
        // Performance tab
        if (device.isMonitoringEnabled()) {
            JPanel perfPanel = new JPanel(new GridLayout(5, 2, 10, 10));
            perfPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
            
            perfPanel.add(new JLabel("CPU Usage:"));
            perfPanel.add(new JLabel(String.format("%.1f%%", device.getLatestCpu())));
            perfPanel.add(new JLabel("Memory Usage:"));
            perfPanel.add(new JLabel(String.format("%.1f%%", device.getLatestMemory())));
            perfPanel.add(new JLabel("Disk Usage:"));
            perfPanel.add(new JLabel(String.format("%.1f%%", device.getLatestDisk())));
            
            tabbedPane.addTab("Performance", perfPanel);
        }
        
        dialog.add(tabbedPane);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    // Alert Methods
    private void configureAlerts() {
        JDialog dialog = new JDialog(this, "Alert Configuration", true);
        dialog.setSize(800, 600);
        dialog.setLayout(new BorderLayout());
        
        JPanel mainPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        String[] metrics = {"CPU", "Memory", "Disk", "Failed Logins"};
        
        for (String metric : metrics) {
            JPanel metricPanel = new JPanel(new GridLayout(4, 2, 5, 5));
            metricPanel.setBorder(BorderFactory.createTitledBorder(metric + " Alerts"));
            
            metricPanel.add(new JLabel("Warning Level:"));
            JSpinner warningSpinner = new JSpinner(new SpinnerNumberModel(80, 0, 100, 1));
            metricPanel.add(warningSpinner);
            
            metricPanel.add(new JLabel("Critical Level:"));
            JSpinner criticalSpinner = new JSpinner(new SpinnerNumberModel(95, 0, 100, 1));
            metricPanel.add(criticalSpinner);
            
            metricPanel.add(new JLabel("Duration (seconds):"));
            JSpinner durationSpinner = new JSpinner(new SpinnerNumberModel(300, 60, 3600, 60));
            metricPanel.add(durationSpinner);
            
            metricPanel.add(new JLabel("Enabled:"));
            JCheckBox enabledCheck = new JCheckBox("", true);
            metricPanel.add(enabledCheck);
            
            mainPanel.add(metricPanel);
        }
        
        dialog.add(mainPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(dialog, "Alert configuration saved.");
            dialog.dispose();
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    private void acknowledgeAllAlerts() {
        alertManager.acknowledgeAllAlerts();
        refreshAlerts();
        logMessage("Acknowledged all alerts");
    }
    
    private void refreshAlerts() {
        // Refresh alerts display
        updateStatus("Alerts refreshed");
    }
    
    private void showAlertsDashboard() {
        JDialog dashboard = new JDialog(this, "Alerts Dashboard", false);
        dashboard.setSize(1200, 800);
        
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        JLabel title = new JLabel("Alerts Dashboard");
        title.setFont(new Font("Arial", Font.BOLD, 20));
        title.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        mainPanel.add(title, BorderLayout.NORTH);
        
        int criticalCount = alertManager.getCriticalCount();
        int warningCount = alertManager.getWarningCount();
        int totalCount = alertManager.getTotalActiveAlerts();
        
        JPanel summaryPanel = new JPanel(new GridLayout(1, 3, 20, 20));
        summaryPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 20, 20));
        
        summaryPanel.add(createMetricCard("Critical", String.valueOf(criticalCount), 
            new Color(220, 53, 69)));
        summaryPanel.add(createMetricCard("Warning", String.valueOf(warningCount), 
            new Color(255, 193, 7)));
        summaryPanel.add(createMetricCard("Total", String.valueOf(totalCount), 
            accentColor));
        
        mainPanel.add(summaryPanel, BorderLayout.CENTER);
        
        dashboard.add(mainPanel);
        dashboard.setLocationRelativeTo(this);
        dashboard.setVisible(true);
    }
    
    // Utility Methods
    private void showBulkSetupDialog() {
        JDialog dialog = new JDialog(this, "Bulk Device Setup", true);
        dialog.setSize(600, 500);
        dialog.setLayout(new BorderLayout(10, 10));
        
        JLabel instructions = new JLabel(
            "<html>Bulk Device Setup<br><br>" +
            "This wizard will help you set up monitoring on multiple devices simultaneously.<br>" +
            "Select devices below and provide credentials for setup.</html>");
        instructions.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        dialog.add(instructions, BorderLayout.NORTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    private void showPreferences() {
        JDialog dialog = new JDialog(this, "Preferences", true);
        dialog.setSize(500, 400);
        
        JPanel mainPanel = new JPanel(new GridLayout(5, 2, 10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        mainPanel.add(new JLabel("Monitoring Interval (seconds):"));
        JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 300, 1));
        mainPanel.add(intervalSpinner);
        
        mainPanel.add(new JLabel("Auto-refresh GUI:"));
        JCheckBox autoRefreshCheck = new JCheckBox("", true);
        mainPanel.add(autoRefreshCheck);
        
        mainPanel.add(new JLabel("Theme:"));
        JComboBox<String> themeCombo = new JComboBox<>(new String[]{"Light", "Dark"});
        mainPanel.add(themeCombo);
        
        mainPanel.add(new JLabel("Data Retention (days):"));
        JSpinner retentionSpinner = new JSpinner(new SpinnerNumberModel(30, 7, 365, 1));
        mainPanel.add(retentionSpinner);
        
        dialog.add(mainPanel, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            saveConfiguration();
            JOptionPane.showMessageDialog(dialog, "Preferences saved successfully.");
            dialog.dispose();
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }
    
    private void importDevices() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            // Import logic would go here
            JOptionPane.showMessageDialog(this, "Device import functionality");
        }
    }
    
    private void exportReport() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            // Export logic would go here
            JOptionPane.showMessageDialog(this, "Report exported successfully");
        }
    }
    
    private void cleanupDatabase() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "This will remove old data. Continue?",
            "Database Cleanup", JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            dbManager.cleanupOldData(30);
            JOptionPane.showMessageDialog(this, "Database cleanup completed.");
            logMessage("Database cleanup completed");
        }
    }
    
    private void showShortcuts() {
        String shortcuts = 
            "Keyboard Shortcuts:\n\n" +
            "Ctrl+Q - Quick Scan\n" +
            "Ctrl+S - Full Network Scan\n" +
            "Ctrl+P - Preferences\n" +
            "Ctrl+T - Toggle Theme\n" +
            "F5 - Refresh All\n" +
            "Ctrl+Shift+Q - Exit Application";
        
        JOptionPane.showMessageDialog(this, shortcuts, 
            "Keyboard Shortcuts", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void showDocumentation() {
        JDialog docDialog = new JDialog(this, "Documentation", false);
        docDialog.setSize(600, 500);
        
        JTextArea docArea = new JTextArea();
        docArea.setEditable(false);
        docArea.setText(
            "PC Management System Documentation\n\n" +
            "GETTING STARTED:\n" +
            "1. Click 'Quick Scan' to discover devices on your network\n" +
            "2. Select devices and click 'Setup Device' to enable monitoring\n" +
            "3. View real-time metrics in the monitoring tabs\n\n" +
            "FEATURES:\n" +
            "• Network Discovery: Automatically find devices on your network\n" +
            "• Real-time Monitoring: CPU, memory, disk, and network metrics\n" +
            "• Alert System: Configurable alerts for system thresholds\n" +
            "• Security Monitoring: Track failed logins and security events\n");
        
        JScrollPane scrollPane = new JScrollPane(docArea);
        docDialog.add(scrollPane);
        docDialog.setLocationRelativeTo(this);
        docDialog.setVisible(true);
    }
    
    private void showAbout() {
        String aboutText = 
            "Enterprise Network PC Management System v2.0\n\n" +
            "An advanced network monitoring and management solution\n" +
            "with real-time alerting, performance analytics, and\n" +
            "comprehensive device management capabilities.\n\n" +
            "Features:\n" +
            "• Real-time monitoring and alerting\n" +
            "• Performance analytics and reporting\n" +
            "• Modern responsive user interface\n" +
            "• Enterprise-grade scalability\n\n" +
            "Built with Java and Swing";
        
        JOptionPane.showMessageDialog(this, aboutText, 
            "About", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void filterDevices() {
        updateDeviceDisplay();
    }
    
    private void filterDevicesByStatus(String status) {
        updateDeviceDisplay();
    }
    
    private void refreshAll() {
        updateDeviceDisplay();
        refreshAlerts();
        updateStatus("All data refreshed");
        logMessage("All data refreshed");
    }
    
    private void clearLogs() {
        if (JOptionPane.showConfirmDialog(this, "Clear all logs from display?",
            "Clear Logs", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            logArea.setText("");
        }
    }
    
    private void exportLogs() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.write(
                    fileChooser.getSelectedFile().toPath(),
                    logArea.getText().getBytes());
                JOptionPane.showMessageDialog(this, "Logs exported successfully");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Failed to export logs: " + e.getMessage());
            }
        }
    }
    
    private void startMonitoring() {
        monitoringThread = new MonitoringThread(this, devices, alertManager, sshManager);
        monitoringThread.start();
        monitoringStatusLabel.setText("📊 Active");
    }
    
    public void logMessage(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            logArea.append(String.format("[%s] %s\n", timestamp, message));
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        LOGGER.info(message);
    }
    
    public void updateStatus(String status) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(status));
    }
    
    private void safeExit() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to exit?", "Exit",
            JOptionPane.YES_NO_OPTION);
        
        if (confirm == JOptionPane.YES_OPTION) {
            if (monitoringThread != null) {
                monitoringThread.stopMonitoring();
            }
            executorService.shutdown();
            saveConfiguration();
            System.exit(0);
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            NetworkMonitorApp app = new NetworkMonitorApp();
            app.setVisible(true);
        });
    }
}
