# Device Monitor

<BR>
<BR>
Key Features Implemented:
Core Functionality:

Network Discovery: Automatically scans your subnet to find all connected devices
Device Classification: Identifies device types (computers, printers, routers, switches, media devices)
Port Scanning: Discovers open ports on selected devices
OS Detection: Basic operating system identification using network characteristics

Traffic Monitoring:

Real-time network traffic simulation and monitoring
Traffic analysis with source/destination tracking
Protocol and port monitoring

Security Features:

Intrusion Detection System (IDS): Monitors for suspicious activities including:

Port scanning attempts
Failed login attempts on SSH/RDP ports
Unusual traffic volumes


Security Alerts: Real-time alerts with severity levels
Critical Alert Popups: Immediate notifications for high-severity threats

Remote Management:

Agent Deployment: Options for SSH, WMI, and SNMP deployment methods
Account Creation: Automatically creates monitoring accounts with administrative privileges
Multiple Deployment Strategies: Supports different connection methods for various OS types

User Interface:

Multiple Themes: 4 built-in color themes (Default, Dark, Green, Blue)
Tabbed Interface: Organized sections for devices, network map, traffic, alerts, and logs
Data Export: Export capabilities for devices, traffic, and security alerts
Real-time Updates: Automatic refresh and live monitoring

Pure Java Implementation:

Uses only standard JDK libraries (no external dependencies)
Cross-platform compatibility
Efficient multithreading for network operations

How to Use:

Compile and Run: Save as NetworkMonitorApp.java, compile with javac NetworkMonitorApp.java, and run with java NetworkMonitorApp
Initial Setup: The application automatically starts scanning your local subnet (192.168.1.x by default)
Device Management:

View discovered devices in the "Devices" tab
Select a device and click "Port Scan" to discover open services
Use "Deploy Agent" to install monitoring capabilities


Security Monitoring:

Check the "Security Alerts" tab for real-time threat detection
Monitor the "Traffic Monitor" tab for network activity
Review detailed logs in the "Logs" tab


Customization:

Change themes using the dropdown in the status bar
Modify settings through Tools → Settings
Export data for analysis or reporting



The application provides enterprise-level network monitoring capabilities while maintaining simplicity and using only standard Java libraries. It's designed to scale from small home networks to larger corporate environments.
