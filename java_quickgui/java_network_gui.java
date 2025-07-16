import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class NetworkSystemMonitor extends JFrame {
private JPanel dashboardPanel;
private JScrollPane scrollPane;
private Map<String, MachinePanel> machinePanels;
private ExecutorService executorService;
private Timer discoveryTimer;
private Timer updateTimer;
private Set<String> knownMachines;

```
public NetworkSystemMonitor() {
    machinePanels = new ConcurrentHashMap<>();
    knownMachines = ConcurrentHashMap.newKeySet();
    executorService = Executors.newFixedThreadPool(20);
    
    initializeGUI();
    startNetworkDiscovery();
    startSystemUpdates();
}

private void initializeGUI() {
    setTitle("Network System Monitor");
    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    setSize(1200, 800);
    setLocationRelativeTo(null);
    
    // Create main panel with grid layout
    dashboardPanel = new JPanel();
    dashboardPanel.setLayout(new GridLayout(0, 3, 10, 10));
    dashboardPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
    
    // Create scroll pane
    scrollPane = new JScrollPane(dashboardPanel);
    scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
    scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    
    // Create menu bar
    JMenuBar menuBar = new JMenuBar();
    JMenu fileMenu = new JMenu("File");
    JMenuItem exitItem = new JMenuItem("Exit");
    exitItem.addActionListener(e -> System.exit(0));
    fileMenu.add(exitItem);
    
    JMenu viewMenu = new JMenu("View");
    JMenuItem refreshItem = new JMenuItem("Refresh All");
    refreshItem.addActionListener(e -> refreshAllMachines());
    viewMenu.add(refreshItem);
    
    menuBar.add(fileMenu);
    menuBar.add(viewMenu);
    setJMenuBar(menuBar);
    
    add(scrollPane);
    
    // Status bar
    JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JLabel statusLabel = new JLabel("Monitoring network...");
    statusPanel.add(statusLabel);
    add(statusPanel, BorderLayout.SOUTH);
}

private void startNetworkDiscovery() {
    discoveryTimer = new Timer(30000, new ActionListener() { // Check every 30 seconds
        @Override
        public void actionPerformed(ActionEvent e) {
            executorService.submit(() -> discoverNetworkMachines());
        }
    });
    discoveryTimer.start();
    
    // Initial discovery
    executorService.submit(() -> discoverNetworkMachines());
}

private void startSystemUpdates() {
    updateTimer = new Timer(5000, new ActionListener() { // Update every 5 seconds
        @Override
        public void actionPerformed(ActionEvent e) {
            updateAllMachines();
        }
    });
    updateTimer.start();
}

private void discoverNetworkMachines() {
    try {
        // Get local network interfaces
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        
        while (interfaces.hasMoreElements()) {
            NetworkInterface ni = interfaces.nextElement();
            if (ni.isUp() && !ni.isLoopback()) {
                ni.getInterfaceAddresses().forEach(addr -> {
                    if (addr.getAddress().getAddress().length == 4) { // IPv4
                        scanSubnet(addr.getAddress().getHostAddress());
                    }
                });
            }
        }
    } catch (SocketException e) {
        e.printStackTrace();
    }
}

private void scanSubnet(String localIP) {
    String subnet = localIP.substring(0, localIP.lastIndexOf('.')) + ".";
    
    for (int i = 1; i <= 254; i++) {
        final String host = subnet + i;
        executorService.submit(() -> {
            try {
                InetAddress addr = InetAddress.getByName(host);
                if (addr.isReachable(2000)) { // 2 second timeout
                    if (!knownMachines.contains(host)) {
                        knownMachines.add(host);
                        SwingUtilities.invokeLater(() -> addMachine(host));
                    }
                }
            } catch (IOException e) {
                // Host not reachable
            }
        });
    }
}

private void addMachine(String ipAddress) {
    MachinePanel panel = new MachinePanel(ipAddress);
    machinePanels.put(ipAddress, panel);
    dashboardPanel.add(panel);
    dashboardPanel.revalidate();
    dashboardPanel.repaint();
}

private void updateAllMachines() {
    for (MachinePanel panel : machinePanels.values()) {
        executorService.submit(() -> panel.updateStats());
    }
}

private void refreshAllMachines() {
    knownMachines.clear();
    machinePanels.clear();
    dashboardPanel.removeAll();
    dashboardPanel.revalidate();
    dashboardPanel.repaint();
    executorService.submit(() -> discoverNetworkMachines());
}

private class MachinePanel extends JPanel {
    private String ipAddress;
    private JLabel hostnameLabel;
    private JLabel statusLabel;
    private JProgressBar cpuBar;
    private JProgressBar diskBar;
    private JLabel cpuLabel;
    private JLabel diskLabel;
    private JLabel lastUpdateLabel;
    private boolean isOnline;
    
    public MachinePanel(String ipAddress) {
        this.ipAddress = ipAddress;
        this.isOnline = true;
        initializePanel();
    }
    
    private void initializePanel() {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), 
            ipAddress, 
            TitledBorder.CENTER, 
            TitledBorder.TOP
        ));
        setPreferredSize(new Dimension(350, 200));
        
        // Header panel
        JPanel headerPanel = new JPanel(new GridLayout(2, 1));
        hostnameLabel = new JLabel("Resolving hostname...", JLabel.CENTER);
        hostnameLabel.setFont(hostnameLabel.getFont().deriveFont(Font.BOLD, 14f));
        statusLabel = new JLabel("Online", JLabel.CENTER);
        statusLabel.setForeground(Color.GREEN);
        headerPanel.add(hostnameLabel);
        headerPanel.add(statusLabel);
        
        // Stats panel
        JPanel statsPanel = new JPanel(new GridLayout(4, 1, 5, 5));
        statsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        cpuLabel = new JLabel("CPU Usage: --");
        cpuBar = new JProgressBar(0, 100);
        cpuBar.setStringPainted(true);
        cpuBar.setString("--");
        
        diskLabel = new JLabel("Disk Usage: --");
        diskBar = new JProgressBar(0, 100);
        diskBar.setStringPainted(true);
        diskBar.setString("--");
        
        statsPanel.add(cpuLabel);
        statsPanel.add(cpuBar);
        statsPanel.add(diskLabel);
        statsPanel.add(diskBar);
        
        // Footer
        lastUpdateLabel = new JLabel("Last update: Never", JLabel.CENTER);
        lastUpdateLabel.setFont(lastUpdateLabel.getFont().deriveFont(10f));
        lastUpdateLabel.setForeground(Color.GRAY);
        
        add(headerPanel, BorderLayout.NORTH);
        add(statsPanel, BorderLayout.CENTER);
        add(lastUpdateLabel, BorderLayout.SOUTH);
        
        // Initial hostname resolution
        executorService.submit(() -> resolveHostname());
    }
    
    private void resolveHostname() {
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            String hostname = addr.getHostName();
            SwingUtilities.invokeLater(() -> {
                hostnameLabel.setText(hostname.equals(ipAddress) ? "Unknown Host" : hostname);
            });
        } catch (UnknownHostException e) {
            SwingUtilities.invokeLater(() -> {
                hostnameLabel.setText("Unknown Host");
            });
        }
    }
    
    public void updateStats() {
        try {
            // Check if machine is still reachable
            InetAddress addr = InetAddress.getByName(ipAddress);
            boolean reachable = addr.isReachable(2000);
            
            SwingUtilities.invokeLater(() -> {
                if (reachable) {
                    if (!isOnline) {
                        isOnline = true;
                        statusLabel.setText("Online");
                        statusLabel.setForeground(Color.GREEN);
                    }
                    
                    // Simulate system stats (in a real implementation, you'd use SSH, SNMP, or WMI)
                    updateSimulatedStats();
                    
                    lastUpdateLabel.setText("Last update: " + new Date().toString());
                } else {
                    if (isOnline) {
                        isOnline = false;
                        statusLabel.setText("Offline");
                        statusLabel.setForeground(Color.RED);
                        cpuBar.setValue(0);
                        cpuBar.setString("Offline");
                        diskBar.setValue(0);
                        diskBar.setString("Offline");
                        cpuLabel.setText("CPU Usage: Offline");
                        diskLabel.setText("Disk Usage: Offline");
                    }
                }
            });
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> {
                if (isOnline) {
                    isOnline = false;
                    statusLabel.setText("Offline");
                    statusLabel.setForeground(Color.RED);
                }
            });
        }
    }
    
    private void updateSimulatedStats() {
        // This simulates system statistics
        // In a real implementation, you would:
        // 1. Use SSH to execute commands like 'top', 'df', 'wmic' (Windows)
        // 2. Use SNMP to query system MIBs
        // 3. Use WMI for Windows machines
        // 4. Use custom agents installed on each machine
        
        Random random = new Random();
        int cpuUsage = random.nextInt(100);
        int diskUsage = random.nextInt(100);
        
        cpuBar.setValue(cpuUsage);
        cpuBar.setString(cpuUsage + "%");
        cpuLabel.setText("CPU Usage: " + cpuUsage + "%");
        
        diskBar.setValue(diskUsage);
        diskBar.setString(diskUsage + "%");
        diskLabel.setText("Disk Usage: " + diskUsage + "%");
        
        // Color coding for high usage
        if (cpuUsage > 80) {
            cpuBar.setForeground(Color.RED);
        } else if (cpuUsage > 60) {
            cpuBar.setForeground(Color.ORANGE);
        } else {
            cpuBar.setForeground(Color.GREEN);
        }
        
        if (diskUsage > 90) {
            diskBar.setForeground(Color.RED);
        } else if (diskUsage > 75) {
            diskBar.setForeground(Color.ORANGE);
        } else {
            diskBar.setForeground(Color.GREEN);
        }
    }
}

@Override
public void dispose() {
    if (discoveryTimer != null) {
        discoveryTimer.stop();
    }
    if (updateTimer != null) {
        updateTimer.stop();
    }
    if (executorService != null) {
        executorService.shutdown();
    }
    super.dispose();
}

public static void main(String[] args) {
    SwingUtilities.invokeLater(() -> {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeel());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        new NetworkSystemMonitor().setVisible(true);
    });
}
```

}