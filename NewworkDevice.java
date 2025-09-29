package com.networkmonitor;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Network Device model with metrics history
 */
public class NetworkDevice {
    private String ip;
    private String hostname;
    private String osType;
    private String status;
    private boolean monitoringEnabled;
    private boolean configured;
    private Object sshClient; // Will hold SSH connection
    private LocalDateTime lastUpdate;
    
    // Metrics history (last 300 data points = 5 minutes at 1-second intervals)
    private Deque<Double> cpuHistory;
    private Deque<Double> memoryHistory;
    private Deque<Double> diskHistory;
    private Deque<Double> networkInHistory;
    private Deque<Double> networkOutHistory;
    private Deque<Integer> processHistory;
    private Deque<Double> loadAvgHistory;
    private Deque<LocalDateTime> timestamps;
    
    private static final int MAX_HISTORY = 300;
    
    // Services and hardware info
    private Map<String, Double> topServices;
    private Map<String, String> hardwareInfo;
    
    public NetworkDevice(String ip, String hostname, String osType, String status) {
        this.ip = ip;
        this.hostname = hostname;
        this.osType = osType;
        this.status = status;
        this.monitoringEnabled = false;
        this.configured = false;
        
        // Initialize history deques
        this.cpuHistory = new ConcurrentLinkedDeque<>();
        this.memoryHistory = new ConcurrentLinkedDeque<>();
        this.diskHistory = new ConcurrentLinkedDeque<>();
        this.networkInHistory = new ConcurrentLinkedDeque<>();
        this.networkOutHistory = new ConcurrentLinkedDeque<>();
        this.processHistory = new ConcurrentLinkedDeque<>();
        this.loadAvgHistory = new ConcurrentLinkedDeque<>();
        this.timestamps = new ConcurrentLinkedDeque<>();
        
        this.topServices = new HashMap<>();
        this.hardwareInfo = new HashMap<>();
    }
    
    // Add metric with history management
    public void addCpuMetric(double value) {
        addToHistory(cpuHistory, value);
    }
    
    public void addMemoryMetric(double value) {
        addToHistory(memoryHistory, value);
    }
    
    public void addDiskMetric(double value) {
        addToHistory(diskHistory, value);
    }
    
    public void addNetworkInMetric(double value) {
        addToHistory(networkInHistory, value);
    }
    
    public void addNetworkOutMetric(double value) {
        addToHistory(networkOutHistory, value);
    }
    
    public void addProcessMetric(int value) {
        if (processHistory.size() >= MAX_HISTORY) {
            processHistory.pollFirst();
        }
        processHistory.offerLast(value);
    }
    
    public void addLoadAvgMetric(double value) {
        addToHistory(loadAvgHistory, value);
    }
    
    public void addTimestamp(LocalDateTime timestamp) {
        if (timestamps.size() >= MAX_HISTORY) {
            timestamps.pollFirst();
        }
        timestamps.offerLast(timestamp);
    }
    
    private void addToHistory(Deque<Double> history, double value) {
        if (history.size() >= MAX_HISTORY) {
            history.pollFirst();
        }
        history.offerLast(value);
    }
    
    // Get latest metrics
    public double getLatestCpu() {
        return cpuHistory.isEmpty() ? 0.0 : cpuHistory.peekLast();
    }
    
    public double getLatestMemory() {
        return memoryHistory.isEmpty() ? 0.0 : memoryHistory.peekLast();
    }
    
    public double getLatestDisk() {
        return diskHistory.isEmpty() ? 0.0 : diskHistory.peekLast();
    }
    
    public double getLatestNetworkIn() {
        return networkInHistory.isEmpty() ? 0.0 : networkInHistory.peekLast();
    }
    
    public double getLatestNetworkOut() {
        return networkOutHistory.isEmpty() ? 0.0 : networkOutHistory.peekLast();
    }
    
    public int getLatestProcessCount() {
        return processHistory.isEmpty() ? 0 : processHistory.peekLast();
    }
    
    public double getLatestLoadAvg() {
        return loadAvgHistory.isEmpty() ? 0.0 : loadAvgHistory.peekLast();
    }
    
    // Get average metrics over specified minutes
    public double getAverageCpu(int minutes) {
        return calculateAverage(cpuHistory, minutes * 60);
    }
    
    public double getAverageMemory(int minutes) {
        return calculateAverage(memoryHistory, minutes * 60);
    }
    
    private double calculateAverage(Deque<Double> history, int dataPoints) {
        if (history.isEmpty()) return 0.0;
        
        int count = Math.min(dataPoints, history.size());
        if (count == 0) return 0.0;
        
        double sum = 0.0;
        Iterator<Double> iterator = history.descendingIterator();
        for (int i = 0; i < count && iterator.hasNext(); i++) {
            sum += iterator.next();
        }
        
        return sum / count;
    }
    
    // Get history for charting
    public List<Double> getCpuHistory() {
        return new ArrayList<>(cpuHistory);
    }
    
    public List<Double> getMemoryHistory() {
        return new ArrayList<>(memoryHistory);
    }
    
    public List<Double> getDiskHistory() {
        return new ArrayList<>(diskHistory);
    }
    
    public List<LocalDateTime> getTimestamps() {
        return new ArrayList<>(timestamps);
    }
    
    // Getters and Setters
    public String getIp() {
        return ip;
    }
    
    public void setIp(String ip) {
        this.ip = ip;
    }
    
    public String getHostname() {
        return hostname;
    }
    
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }
    
    public String getOsType() {
        return osType;
    }
    
    public void setOsType(String osType) {
        this.osType = osType;
    }
    
    public String getStatus() {
        return status;
    }
    
    public void setStatus(String status) {
        this.status = status;
    }
    
    public boolean isMonitoringEnabled() {
        return monitoringEnabled;
    }
    
    public void setMonitoringEnabled(boolean monitoringEnabled) {
        this.monitoringEnabled = monitoringEnabled;
    }
    
    public boolean isConfigured() {
        return configured;
    }
    
    public void setConfigured(boolean configured) {
        this.configured = configured;
    }
    
    public Object getSshClient() {
        return sshClient;
    }
    
    public void setSshClient(Object sshClient) {
        this.sshClient = sshClient;
    }
    
    public LocalDateTime getLastUpdate() {
        return lastUpdate;
    }
    
    public void setLastUpdate(LocalDateTime lastUpdate) {
        this.lastUpdate = lastUpdate;
    }
    
    public Map<String, Double> getTopServices() {
        return topServices;
    }
    
    public void setTopServices(Map<String, Double> topServices) {
        this.topServices = topServices;
    }
    
    public Map<String, String> getHardwareInfo() {
        return hardwareInfo;
    }
    
    public void setHardwareInfo(Map<String, String> hardwareInfo) {
        this.hardwareInfo = hardwareInfo;
    }
    
    @Override
    public String toString() {
        return String.format("NetworkDevice[ip=%s, hostname=%s, status=%s, monitoring=%s, configured=%s]",
            ip, hostname, status, monitoringEnabled, configured);
    }
}
