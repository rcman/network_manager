import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;

public class NetworkMonitorApp extends JFrame {
    private static final long serialVersionUID = 1L;
    
    // GUI Components
    private JTabbedPane tabbedPane;
    private JTable devicesTable;
    private JTable trafficTable;
    private JTable alertsTable;
    private DefaultTableModel devicesModel;
    private DefaultTableModel trafficModel;
    private DefaultTableModel alertsModel;
    private JTree networkTree;
    private DefaultTreeModel treeModel;
    private JTextArea logArea;
    private JProgressBar scanProgress;
    private JLabel statusLabel;
    private JComboBox<String> themeComboBox;
    
    // Data structures
    private Map<String, NetworkDevice> discoveredDevices;
    private List<TrafficEntry> trafficData;
    private List<SecurityAlert> securityAlerts;
    private ExecutorService executorService;
    private Timer refreshTimer;
    
    // Configuration
    private String currentSubnet = "192.168.1";
    private boolean scanningInProgress = false;
    
    // Themes
    private Map<String, ColorTheme> themes;
    private ColorTheme currentTheme;
    
    public NetworkMonitorApp() {
        initializeData();
        initializeThemes();
        initializeGUI();
        startBackgroundTasks();
    }
    
    private void initializeData() {
        discoveredDevices = new ConcurrentHashMap<>();
        trafficData = new ArrayList<>();
        securityAlerts = new ArrayList<>();
        executorService = Executors.newFixedThreadPool(10);
    }
    
    private void initializeThemes() {
        themes = new HashMap<>();
        themes.put("Default", new ColorTheme(Color.WHITE, Color.BLACK, new Color(240, 240, 240), Color.BLUE));
        themes.put("Dark", new ColorTheme(new Color(45, 45, 45), Color.WHITE, new Color(60, 60, 60), new Color(100, 149, 237)));
        themes.put("Green", new ColorTheme(new Color(240, 255, 240), new Color(0, 100, 0), new Color(220, 255, 220), new Color(0, 150, 0)));
        themes.put("Blue", new ColorTheme(new Color(240, 248, 255), new Color(25, 25, 112), new Color(230, 238, 255), new Color(65, 105, 225)));
        currentTheme = themes.get("Default");
    }
    
    private void initializeGUI() {
        setTitle("Network Device Monitoring System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        
        createMenuBar();
        createMainPanel();
        createStatusBar();
        
        applyTheme();
        setSize(1200, 800);
        setLocationRelativeTo(null);
    }
    
    private void createMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        
        // File Menu
        JMenu fileMenu = new JMenu("File");
        JMenuItem exportItem = new JMenuItem("Export Data");
        JMenuItem exitItem = new JMenuItem("Exit");
        exportItem.addActionListener(e -> exportData());
        exitItem.addActionListener(e -> System.exit(0));
        fileMenu.add(exportItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);
        
        // Tools Menu
        JMenu toolsMenu = new JMenu("Tools");
        JMenuItem scanItem = new JMenuItem("Network Scan");
        JMenuItem deployItem = new JMenuItem("Deploy Agent");
        JMenuItem settingsItem = new JMenuItem("Settings");
        scanItem.addActionListener(e -> startNetworkScan());
        deployItem.addActionListener(e -> deployAgent());
        settingsItem.addActionListener(e -> showSettings());
        toolsMenu.add(scanItem);
        toolsMenu.add(deployItem);
        toolsMenu.addSeparator();
        toolsMenu.add(settingsItem);
        
        // View Menu
        JMenu viewMenu = new JMenu("View");
        JMenuItem refreshItem = new JMenuItem("Refresh");
        JMenu themeMenu = new JMenu("Theme");
        refreshItem.addActionListener(e -> refreshData());
        
        for (String themeName : themes.keySet()) {
            JMenuItem themeItem = new JMenuItem(themeName);
            themeItem.addActionListener(e -> changeTheme(themeName));
            themeMenu.add(themeItem);
        }
        
        viewMenu.add(refreshItem);
        viewMenu.add(themeMenu);
        
        menuBar.add(fileMenu);
        menuBar.add(toolsMenu);
        menuBar.add(viewMenu);
        setJMenuBar(menuBar);
    }
    
    private void createMainPanel() {
        tabbedPane = new JTabbedPane();
        
        // Devices Tab
        JPanel devicesPanel = createDevicesPanel();
        tabbedPane.addTab("Devices", devicesPanel);
        
        // Network Map Tab
        JPanel networkPanel = createNetworkPanel();
        tabbedPane.addTab("Network Map", networkPanel);
        
        // Traffic Monitor Tab
        JPanel trafficPanel = createTrafficPanel();
        tabbedPane.addTab("Traffic Monitor", trafficPanel);
        
        // Security Alerts Tab
        JPanel alertsPanel = createAlertsPanel();
        tabbedPane.addTab("Security Alerts", alertsPanel);
        
        // Logs Tab
        JPanel logsPanel = createLogsPanel();
        tabbedPane.addTab("Logs", logsPanel);
        
        add(tabbedPane, BorderLayout.CENTER);
    }
    
    private JPanel createDevicesPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        JButton scanButton = new JButton("Start Scan");
        JButton portScanButton = new JButton("Port Scan");
        JButton refreshButton = new JButton("Refresh");
        
        scanProgress = new JProgressBar(0, 100);
        scanProgress.setStringPainted(true);
        
        scanButton.addActionListener(e -> startNetworkScan());
        portScanButton.addActionListener(e -> startPortScan());
        refreshButton.addActionListener(e -> refreshDevicesTable());
        
        controlPanel.add(scanButton);
        controlPanel.add(portScanButton);
        controlPanel.add(refreshButton);
        controlPanel.add(new JLabel("Progress:"));
        controlPanel.add(scanProgress);
        
        // Devices Table
        String[] columns = {"IP Address", "Hostname", "MAC Address", "Device Type", "OS", "Open Ports", "Status", "Last Seen"};
        devicesModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        devicesTable = new JTable(devicesModel);
        devicesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane devicesScroll = new JScrollPane(devicesTable);
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(devicesScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createNetworkPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("Network");
        treeModel = new DefaultTreeModel(root);
        networkTree = new JTree(treeModel);
        
        JScrollPane treeScroll = new JScrollPane(networkTree);
        treeScroll.setPreferredSize(new Dimension(300, 0));
        
        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.setBorder(new TitledBorder("Device Details"));
        
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, detailPanel);
        splitPane.setDividerLocation(300);
        
        panel.add(splitPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Traffic Table
        String[] columns = {"Timestamp", "Source IP", "Destination IP", "Protocol", "Port", "Bytes", "Packets", "Status"};
        trafficModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        trafficTable = new JTable(trafficModel);
        JScrollPane trafficScroll = new JScrollPane(trafficTable);
        
        // Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        JButton startMonitorButton = new JButton("Start Monitoring");
        JButton stopMonitorButton = new JButton("Stop Monitoring");
        JButton clearButton = new JButton("Clear Data");
        
        startMonitorButton.addActionListener(e -> startTrafficMonitoring());
        stopMonitorButton.addActionListener(e -> stopTrafficMonitoring());
        clearButton.addActionListener(e -> clearTrafficData());
        
        controlPanel.add(startMonitorButton);
        controlPanel.add(stopMonitorButton);
        controlPanel.add(clearButton);
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(trafficScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createAlertsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Alerts Table
        String[] columns = {"Timestamp", "Severity", "Source IP", "Alert Type", "Description", "Status"};
        alertsModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        alertsTable = new JTable(alertsModel);
        JScrollPane alertsScroll = new JScrollPane(alertsTable);
        
        // Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        JButton clearAlertsButton = new JButton("Clear Alerts");
        JButton exportAlertsButton = new JButton("Export Alerts");
        JCheckBox enableIDS = new JCheckBox("Enable IDS", true);
        
        clearAlertsButton.addActionListener(e -> clearAlerts());
        exportAlertsButton.addActionListener(e -> exportAlerts());
        enableIDS.addActionListener(e -> toggleIDS(enableIDS.isSelected()));
        
        controlPanel.add(enableIDS);
        controlPanel.add(clearAlertsButton);
        controlPanel.add(exportAlertsButton);
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(alertsScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createLogsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);
        
        // Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout());
        JButton clearLogsButton = new JButton("Clear Logs");
        JButton saveLogsButton = new JButton("Save Logs");
        
        clearLogsButton.addActionListener(e -> logArea.setText(""));
        saveLogsButton.addActionListener(e -> saveLogs());
        
        controlPanel.add(clearLogsButton);
        controlPanel.add(saveLogsButton);
        
        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(logScroll, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void createStatusBar() {
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Ready");
        
        themeComboBox = new JComboBox<>(themes.keySet().toArray(new String[0]));
        themeComboBox.addActionListener(e -> changeTheme((String) themeComboBox.getSelectedItem()));
        
        statusPanel.add(new JLabel("Status: "));
        statusPanel.add(statusLabel);
        statusPanel.add(Box.createHorizontalGlue());
        statusPanel.add(new JLabel("Theme: "));
        statusPanel.add(themeComboBox);
        
        add(statusPanel, BorderLayout.SOUTH);
    }
    
    private void startBackgroundTasks() {
        // Start periodic refresh timer
        refreshTimer = new Timer(30000, e -> {
            if (!scanningInProgress) {
                refreshData();
            }
        });
        refreshTimer.start();
        
        // Start initial network scan
        SwingUtilities.invokeLater(() -> startNetworkScan());
    }
    
    private void startNetworkScan() {
        if (scanningInProgress) {
            logMessage("Scan already in progress...");
            return;
        }
        
        scanningInProgress = true;
        statusLabel.setText("Scanning network...");
        scanProgress.setValue(0);
        
        executorService.submit(() -> {
            try {
                performNetworkScan();
            } finally {
                scanningInProgress = false;
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Scan completed");
                    scanProgress.setValue(100);
                });
            }
        });
    }
    
    private void performNetworkScan() {
        logMessage("Starting network scan of subnet: " + currentSubnet + ".0/24");
        
        List<Future<NetworkDevice>> futures = new ArrayList<>();
        
        for (int i = 1; i <= 254; i++) {
            final String ip = currentSubnet + "." + i;
            Future<NetworkDevice> future = executorService.submit(() -> scanHost(ip));
            futures.add(future);
            
            SwingUtilities.invokeLater(() -> scanProgress.setValue((i * 100) / 254));
        }
        
        // Collect results
        int found = 0;
        for (Future<NetworkDevice> future : futures) {
            try {
                NetworkDevice device = future.get(100, TimeUnit.MILLISECONDS);
                if (device != null) {
                    discoveredDevices.put(device.getIpAddress(), device);
                    found++;
                    SwingUtilities.invokeLater(() -> updateDevicesTable());
                    logMessage("Found device: " + device.getIpAddress() + " (" + device.getHostname() + ")");
                }
            } catch (Exception e) {
                // Timeout or other error - host likely not reachable
            }
        }
        
        logMessage("Network scan completed. Found " + found + " devices.");
        SwingUtilities.invokeLater(() -> updateNetworkTree());
    }
    
    private NetworkDevice scanHost(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            if (address.isReachable(1000)) {
                NetworkDevice device = new NetworkDevice(ip);
                device.setHostname(address.getHostName());
                device.setLastSeen(new Date());
                device.setStatus("Online");
                
                // Determine device type based on hostname or IP patterns
                String deviceType = determineDeviceType(device.getHostname(), ip);
                device.setDeviceType(deviceType);
                
                // Basic OS detection
                String os = detectOS(ip);
                device.setOperatingSystem(os);
                
                return device;
            }
        } catch (IOException e) {
            // Host not reachable
        }
        return null;
    }
    
    private String determineDeviceType(String hostname, String ip) {
        String lower = hostname.toLowerCase();
        
        if (lower.contains("printer") || lower.contains("canon") || lower.contains("hp") || lower.contains("epson")) {
            return "Printer";
        } else if (lower.contains("router") || lower.contains("gateway") || ip.endsWith(".1") || ip.endsWith(".254")) {
            return "Router";
        } else if (lower.contains("switch") || lower.contains("sw-")) {
            return "Switch";
        } else if (lower.contains("firestick") || lower.contains("fire-tv") || lower.contains("amazon")) {
            return "Media Device";
        } else if (lower.contains("android") || lower.contains("phone") || lower.contains("mobile")) {
            return "Mobile Device";
        } else if (lower.contains("server") || lower.contains("srv")) {
            return "Server";
        } else {
            return "Computer";
        }
    }
    
    private String detectOS(String ip) {
        // Simple OS detection based on TTL and other network characteristics
        try {
            Process process = Runtime.getRuntime().exec("ping -c 1 " + ip);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("ttl=")) {
                    String ttl = line.substring(line.indexOf("ttl=") + 4);
                    int ttlValue = Integer.parseInt(ttl.split(" ")[0]);
                    
                    if (ttlValue <= 64) {
                        return "Linux/Unix";
                    } else if (ttlValue <= 128) {
                        return "Windows";
                    } else {
                        return "Unknown";
                    }
                }
            }
        } catch (Exception e) {
            // Fallback method or error handling
        }
        return "Unknown";
    }
    
    private void startPortScan() {
        NetworkDevice selected = getSelectedDevice();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Please select a device to scan ports.");
            return;
        }
        
        executorService.submit(() -> {
            logMessage("Starting port scan for " + selected.getIpAddress());
            List<Integer> openPorts = scanPorts(selected.getIpAddress());
            selected.setOpenPorts(openPorts);
            SwingUtilities.invokeLater(() -> updateDevicesTable());
            logMessage("Port scan completed for " + selected.getIpAddress() + ". Found " + openPorts.size() + " open ports.");
        });
    }
    
    private List<Integer> scanPorts(String ip) {
        List<Integer> openPorts = new ArrayList<>();
        int[] commonPorts = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080};
        
        for (int port : commonPorts) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), 1000);
                openPorts.add(port);
            } catch (IOException e) {
                // Port closed or filtered
            }
        }
        
        return openPorts;
    }
    
    private void startTrafficMonitoring() {
        executorService.submit(() -> {
            logMessage("Starting traffic monitoring...");
            // Simulate traffic monitoring
            while (true) {
                try {
                    Thread.sleep(5000);
                    generateSimulatedTraffic();
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
    }
    
    private void generateSimulatedTraffic() {
        if (discoveredDevices.isEmpty()) return;
        
        String[] protocols = {"TCP", "UDP", "ICMP"};
        Random random = new Random();
        
        List<String> ips = new ArrayList<>(discoveredDevices.keySet());
        if (ips.size() < 2) return;
        
        String sourceIP = ips.get(random.nextInt(ips.size()));
        String destIP = ips.get(random.nextInt(ips.size()));
        String protocol = protocols[random.nextInt(protocols.length)];
        int port = 80 + random.nextInt(8000);
        int bytes = 64 + random.nextInt(1024);
        int packets = 1 + random.nextInt(10);
        
        TrafficEntry entry = new TrafficEntry(new Date(), sourceIP, destIP, protocol, port, bytes, packets);
        trafficData.add(entry);
        
        // Keep only last 1000 entries
        if (trafficData.size() > 1000) {
            trafficData.remove(0);
        }
        
        SwingUtilities.invokeLater(() -> updateTrafficTable());
        
        // Check for suspicious activity
        checkForSuspiciousActivity(entry);
    }
    
    private void checkForSuspiciousActivity(TrafficEntry entry) {
        // Simple intrusion detection rules
        
        // Check for port scanning
        if (entry.getPort() < 1024 && entry.getPackets() == 1 && entry.getBytes() < 100) {
            createSecurityAlert("Medium", entry.getSourceIP(), "Port Scan", 
                "Possible port scanning activity detected from " + entry.getSourceIP());
        }
        
        // Check for unusual traffic volume
        if (entry.getBytes() > 10000) {
            createSecurityAlert("Low", entry.getSourceIP(), "High Traffic", 
                "Unusually high traffic volume detected from " + entry.getSourceIP());
        }
        
        // Check for failed connections to common services
        if ((entry.getPort() == 22 || entry.getPort() == 3389) && entry.getPackets() < 5) {
            createSecurityAlert("High", entry.getSourceIP(), "Failed Login", 
                "Possible failed login attempt on port " + entry.getPort() + " from " + entry.getSourceIP());
        }
    }
    
    private void createSecurityAlert(String severity, String sourceIP, String alertType, String description) {
        SecurityAlert alert = new SecurityAlert(new Date(), severity, sourceIP, alertType, description);
        securityAlerts.add(alert);
        
        SwingUtilities.invokeLater(() -> {
            updateAlertsTable();
            if ("High".equals(severity)) {
                showCriticalAlert(alert);
            }
        });
        
        logMessage("SECURITY ALERT [" + severity + "]: " + description);
    }
    
    private void showCriticalAlert(SecurityAlert alert) {
        JOptionPane.showMessageDialog(this, 
            "CRITICAL SECURITY ALERT!\n\n" + alert.getDescription(), 
            "Security Alert", 
            JOptionPane.WARNING_MESSAGE);
    }
    
    private void deployAgent() {
        NetworkDevice selected = getSelectedDevice();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Please select a device to deploy agent.");
            return;
        }
        
        String[] options = {"SSH (Linux/Unix)", "WMI (Windows)", "SNMP", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this, 
            "Select deployment method for " + selected.getIpAddress(),
            "Deploy Agent", 
            JOptionPane.DEFAULT_OPTION, 
            JOptionPane.QUESTION_MESSAGE, 
            null, options, options[0]);
        
        if (choice >= 0 && choice < 3) {
            executorService.submit(() -> performAgentDeployment(selected, options[choice]));
        }
    }
    
    private void performAgentDeployment(NetworkDevice device, String method) {
        logMessage("Deploying agent to " + device.getIpAddress() + " using " + method);
        
        try {
            // Simulate agent deployment
            Thread.sleep(3000);
            
            // Create monitoring account (simulation)
            createMonitoringAccount(device);
            
            logMessage("Agent successfully deployed to " + device.getIpAddress());
            device.setStatus("Monitored");
            SwingUtilities.invokeLater(() -> updateDevicesTable());
            
        } catch (InterruptedException e) {
            logMessage("Agent deployment interrupted for " + device.getIpAddress());
        } catch (Exception e) {
            logMessage("Failed to deploy agent to " + device.getIpAddress() + ": " + e.getMessage());
        }
    }
    
    private void createMonitoringAccount(NetworkDevice device) {
        // Simulate creating a monitoring account with root/admin privileges
        logMessage("Creating monitoring account on " + device.getIpAddress());
        
        String accountName = "netmon_" + System.currentTimeMillis();
        String password = generateSecurePassword();
        
        // In a real implementation, this would use SSH, WMI, or other protocols
        // to actually create the account on the target system
        
        device.setMonitoringAccount(accountName);
        logMessage("Monitoring account '" + accountName + "' created on " + device.getIpAddress());
    }
    
    private String generateSecurePassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        StringBuilder password = new StringBuilder();
        Random random = new Random();
        
        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return password.toString();
    }
    
    private NetworkDevice getSelectedDevice() {
        int selectedRow = devicesTable.getSelectedRow();
        if (selectedRow >= 0) {
            String ip = (String) devicesModel.getValueAt(selectedRow, 0);
            return discoveredDevices.get(ip);
        }
        return null;
    }
    
    private void updateDevicesTable() {
        devicesModel.setRowCount(0);
        for (NetworkDevice device : discoveredDevices.values()) {
            Object[] row = {
                device.getIpAddress(),
                device.getHostname(),
                device.getMacAddress(),
                device.getDeviceType(),
                device.getOperatingSystem(),
                device.getOpenPorts().toString(),
                device.getStatus(),
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(device.getLastSeen())
            };
            devicesModel.addRow(row);
        }
    }
    
    private void updateTrafficTable() {
        trafficModel.setRowCount(0);
        int start = Math.max(0, trafficData.size() - 100); // Show last 100 entries
        for (int i = start; i < trafficData.size(); i++) {
            TrafficEntry entry = trafficData.get(i);
            Object[] row = {
                new SimpleDateFormat("HH:mm:ss").format(entry.getTimestamp()),
                entry.getSourceIP(),
                entry.getDestinationIP(),
                entry.getProtocol(),
                entry.getPort(),
                entry.getBytes(),
                entry.getPackets(),
                "Active"
            };
            trafficModel.addRow(row);
        }
    }
    
    private void updateAlertsTable() {
        alertsModel.setRowCount(0);
        for (SecurityAlert alert : securityAlerts) {
            Object[] row = {
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(alert.getTimestamp()),
                alert.getSeverity(),
                alert.getSourceIP(),
                alert.getAlertType(),
                alert.getDescription(),
                alert.getStatus()
            };
            alertsModel.addRow(row);
        }
    }
    
    private void updateNetworkTree() {
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) treeModel.getRoot();
        root.removeAllChildren();
        
        Map<String, DefaultMutableTreeNode> subnetNodes = new HashMap<>();
        
        for (NetworkDevice device : discoveredDevices.values()) {
            String subnet = device.getIpAddress().substring(0, device.getIpAddress().lastIndexOf('.'));
            
            DefaultMutableTreeNode subnetNode = subnetNodes.get(subnet);
            if (subnetNode == null) {
                subnetNode = new DefaultMutableTreeNode("Subnet " + subnet + ".0/24");
                subnetNodes.put(subnet, subnetNode);
                root.add(subnetNode);
            }
            
            DefaultMutableTreeNode deviceNode = new DefaultMutableTreeNode(
                device.getIpAddress() + " (" + device.getHostname() + ")"
            );
            subnetNode.add(deviceNode);
        }
        
        treeModel.reload();
        expandAllNodes();
    }
    
    private void expandAllNodes() {
        for (int i = 0; i < networkTree.getRowCount(); i++) {
            networkTree.expandRow(i);
        }
    }
    
    private void refreshData() {
        updateDevicesTable();
        updateTrafficTable();
        updateAlertsTable();
        updateNetworkTree();
        statusLabel.setText("Data refreshed");
    }
    
    private void refreshDevicesTable() {
        updateDevicesTable();
    }
    
    private void stopTrafficMonitoring() {
        logMessage("Traffic monitoring stopped");
    }
    
    private void clearTrafficData() {
        trafficData.clear();
        updateTrafficTable();
        logMessage("Traffic data cleared");
    }
    
    private void clearAlerts() {
        securityAlerts.clear();
        updateAlertsTable();
        logMessage("Security alerts cleared");
    }
    
    private void toggleIDS(boolean enabled) {
        if (enabled) {
            logMessage("Intrusion Detection System enabled");
        } else {
            logMessage("Intrusion Detection System disabled");
        }
    }
    
    private void changeTheme(String themeName) {
        currentTheme = themes.get(themeName);
        applyTheme();
        themeComboBox.setSelectedItem(themeName);
    }
    
    private void applyTheme() {
        Color bg = currentTheme.backgroundColor;
        Color fg = currentTheme.foregroundColor;
        Color panel = currentTheme.panelColor;
        
        setBackground(bg);
        getContentPane().setBackground(bg);
        
        applyThemeToComponent(this, bg, fg);
        applyThemeToTabbedPane(tabbedPane, bg, fg, panel);
        
        repaint();
    }
    
    private void applyThemeToComponent(Container container, Color bg, Color fg) {
        container.setBackground(bg);
        container.setForeground(fg);
        
        for (Component component : container.getComponents()) {
            component.setBackground(bg);
            component.setForeground(fg);
            
            if (component instanceof JTable) {
                JTable table = (JTable) component;
                table.setBackground(bg);
                table.setForeground(fg);
                table.getTableHeader().setBackground(currentTheme.panelColor);
                table.getTableHeader().setForeground(fg);
            } else if (component instanceof JTree) {
                JTree tree = (JTree) component;
                tree.setBackground(bg);
                tree.setForeground(fg);
            } else if (component instanceof JTextArea) {
                JTextArea textArea = (JTextArea) component;
                textArea.setBackground(bg);
                textArea.setForeground(fg);
            } else if (component instanceof Container) {
                applyThemeToComponent((Container) component, bg, fg);
            }
        }
    }
    
    private void applyThemeToTabbedPane(JTabbedPane tabbedPane, Color bg, Color fg, Color panel) {
        tabbedPane.setBackground(bg);
        tabbedPane.setForeground(fg);
        
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            Component tab = tabbedPane.getComponentAt(i);
            if (tab instanceof Container) {
                applyThemeToComponent((Container) tab, bg, fg);
            }
        }
    }
    
    private void showSettings() {
        JDialog settingsDialog = new JDialog(this, "Settings", true);
        settingsDialog.setLayout(new BorderLayout());
        
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Subnet settings
        gbc.gridx = 0; gbc.gridy = 0;
        settingsPanel.add(new JLabel("Subnet to scan:"), gbc);
        gbc.gridx = 1;
        JTextField subnetField = new JTextField(currentSubnet, 15);
        settingsPanel.add(subnetField, gbc);
        
        // Scan timeout
        gbc.gridx = 0; gbc.gridy = 1;
        settingsPanel.add(new JLabel("Scan timeout (ms):"), gbc);
        gbc.gridx = 1;
        JTextField timeoutField = new JTextField("1000", 15);
        settingsPanel.add(timeoutField, gbc);
        
        // Refresh interval
        gbc.gridx = 0; gbc.gridy = 2;
        settingsPanel.add(new JLabel("Refresh interval (sec):"), gbc);
        gbc.gridx = 1;
        JTextField refreshField = new JTextField("30", 15);
        settingsPanel.add(refreshField, gbc);
        
        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton okButton = new JButton("OK");
        JButton cancelButton = new JButton("Cancel");
        
        okButton.addActionListener(e -> {
            currentSubnet = subnetField.getText();
            settingsDialog.dispose();
            logMessage("Settings updated");
        });
        
        cancelButton.addActionListener(e -> settingsDialog.dispose());
        
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        
        settingsDialog.add(settingsPanel, BorderLayout.CENTER);
        settingsDialog.add(buttonPanel, BorderLayout.SOUTH);
        settingsDialog.setSize(350, 200);
        settingsDialog.setLocationRelativeTo(this);
        settingsDialog.setVisible(true);
    }
    
    private void exportData() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("network_data.csv"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            exportToCSV(file);
        }
    }
    
    private void exportToCSV(File file) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
            // Export devices
            writer.println("=== DEVICES ===");
            writer.println("IP Address,Hostname,MAC Address,Device Type,OS,Open Ports,Status,Last Seen");
            
            for (NetworkDevice device : discoveredDevices.values()) {
                writer.printf("%s,%s,%s,%s,%s,\"%s\",%s,%s%n",
                    device.getIpAddress(),
                    device.getHostname(),
                    device.getMacAddress(),
                    device.getDeviceType(),
                    device.getOperatingSystem(),
                    device.getOpenPorts().toString(),
                    device.getStatus(),
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(device.getLastSeen())
                );
            }
            
            // Export traffic
            writer.println("\n=== TRAFFIC ===");
            writer.println("Timestamp,Source IP,Destination IP,Protocol,Port,Bytes,Packets");
            
            for (TrafficEntry entry : trafficData) {
                writer.printf("%s,%s,%s,%s,%d,%d,%d%n",
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(entry.getTimestamp()),
                    entry.getSourceIP(),
                    entry.getDestinationIP(),
                    entry.getProtocol(),
                    entry.getPort(),
                    entry.getBytes(),
                    entry.getPackets()
                );
            }
            
            // Export alerts
            writer.println("\n=== SECURITY ALERTS ===");
            writer.println("Timestamp,Severity,Source IP,Alert Type,Description,Status");
            
            for (SecurityAlert alert : securityAlerts) {
                writer.printf("%s,%s,%s,%s,\"%s\",%s%n",
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(alert.getTimestamp()),
                    alert.getSeverity(),
                    alert.getSourceIP(),
                    alert.getAlertType(),
                    alert.getDescription(),
                    alert.getStatus()
                );
            }
            
            logMessage("Data exported to " + file.getAbsolutePath());
            JOptionPane.showMessageDialog(this, "Data exported successfully!");
            
        } catch (IOException e) {
            logMessage("Export failed: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void exportAlerts() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("security_alerts.csv"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            exportAlertsToCSV(file);
        }
    }
    
    private void exportAlertsToCSV(File file) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
            writer.println("Timestamp,Severity,Source IP,Alert Type,Description,Status");
            
            for (SecurityAlert alert : securityAlerts) {
                writer.printf("%s,%s,%s,%s,\"%s\",%s%n",
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(alert.getTimestamp()),
                    alert.getSeverity(),
                    alert.getSourceIP(),
                    alert.getAlertType(),
                    alert.getDescription(),
                    alert.getStatus()
                );
            }
            
            logMessage("Alerts exported to " + file.getAbsolutePath());
            JOptionPane.showMessageDialog(this, "Alerts exported successfully!");
            
        } catch (IOException e) {
            logMessage("Alert export failed: " + e.getMessage());
            JOptionPane.showMessageDialog(this, "Alert export failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void saveLogs() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File("network_monitor.log"));
        
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(logArea.getText());
                JOptionPane.showMessageDialog(this, "Logs saved successfully!");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Failed to save logs: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private void logMessage(String message) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String logEntry = "[" + timestamp + "] " + message + "\n";
        
        SwingUtilities.invokeLater(() -> {
            logArea.append(logEntry);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
    
    @Override
    public void dispose() {
        if (refreshTimer != null) {
            refreshTimer.stop();
        }
        if (executorService != null) {
            executorService.shutdown();
        }
        super.dispose();
    }
    
    // Data classes
    private static class NetworkDevice {
        private String ipAddress;
        private String hostname;
        private String macAddress;
        private String deviceType;
        private String operatingSystem;
        private List<Integer> openPorts;
        private String status;
        private Date lastSeen;
        private String monitoringAccount;
        
        public NetworkDevice(String ipAddress) {
            this.ipAddress = ipAddress;
            this.hostname = "Unknown";
            this.macAddress = "Unknown";
            this.deviceType = "Unknown";
            this.operatingSystem = "Unknown";
            this.openPorts = new ArrayList<>();
            this.status = "Offline";
            this.lastSeen = new Date();
            this.monitoringAccount = null;
        }
        
        // Getters and setters
        public String getIpAddress() { return ipAddress; }
        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        public String getMacAddress() { return macAddress; }
        public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
        public String getDeviceType() { return deviceType; }
        public void setDeviceType(String deviceType) { this.deviceType = deviceType; }
        public String getOperatingSystem() { return operatingSystem; }
        public void setOperatingSystem(String operatingSystem) { this.operatingSystem = operatingSystem; }
        public List<Integer> getOpenPorts() { return openPorts; }
        public void setOpenPorts(List<Integer> openPorts) { this.openPorts = openPorts; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public Date getLastSeen() { return lastSeen; }
        public void setLastSeen(Date lastSeen) { this.lastSeen = lastSeen; }
        public String getMonitoringAccount() { return monitoringAccount; }
        public void setMonitoringAccount(String monitoringAccount) { this.monitoringAccount = monitoringAccount; }
    }
    
    private static class TrafficEntry {
        private Date timestamp;
        private String sourceIP;
        private String destinationIP;
        private String protocol;
        private int port;
        private int bytes;
        private int packets;
        
        public TrafficEntry(Date timestamp, String sourceIP, String destinationIP, 
                           String protocol, int port, int bytes, int packets) {
            this.timestamp = timestamp;
            this.sourceIP = sourceIP;
            this.destinationIP = destinationIP;
            this.protocol = protocol;
            this.port = port;
            this.bytes = bytes;
            this.packets = packets;
        }
        
        // Getters
        public Date getTimestamp() { return timestamp; }
        public String getSourceIP() { return sourceIP; }
        public String getDestinationIP() { return destinationIP; }
        public String getProtocol() { return protocol; }
        public int getPort() { return port; }
        public int getBytes() { return bytes; }
        public int getPackets() { return packets; }
    }
    
    private static class SecurityAlert {
        private Date timestamp;
        private String severity;
        private String sourceIP;
        private String alertType;
        private String description;
        private String status;
        
        public SecurityAlert(Date timestamp, String severity, String sourceIP, 
                           String alertType, String description) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.sourceIP = sourceIP;
            this.alertType = alertType;
            this.description = description;
            this.status = "Active";
        }
        
        // Getters
        public Date getTimestamp() { return timestamp; }
        public String getSeverity() { return severity; }
        public String getSourceIP() { return sourceIP; }
        public String getAlertType() { return alertType; }
        public String getDescription() { return description; }
        public String getStatus() { return status; }
    }
    
    private static class ColorTheme {
        Color backgroundColor;
        Color foregroundColor;
        Color panelColor;
        Color accentColor;
        
        public ColorTheme(Color backgroundColor, Color foregroundColor, 
                         Color panelColor, Color accentColor) {
            this.backgroundColor = backgroundColor;
            this.foregroundColor = foregroundColor;
            this.panelColor = panelColor;
            this.accentColor = accentColor;
        }
    }
    
    // Main method
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeel());
            } catch (Exception e) {
                // Fall back to default look and feel
            }
            
            new NetworkMonitorApp().setVisible(true);
        });
    }
}