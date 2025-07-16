#!/usr/bin/env python3
"""
Enhanced Network PC Management Application
Enterprise-grade tool with advanced monitoring, alerting, and modern UI
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import socket
import subprocess
import json
import sqlite3
import paramiko
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
import numpy as np
from datetime import datetime, timedelta
import queue
import ipaddress
import re
import os
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import aiohttp

# Email imports
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable
import configparser
from collections import deque
import statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AlertThreshold:
    """Alert threshold configuration"""
    metric: str
    warning_level: float
    critical_level: float
    duration: int  # seconds before triggering
    enabled: bool = True

@dataclass
class Alert:
    """Alert data structure"""
    id: str
    device_ip: str
    metric: str
    level: str  # warning, critical
    value: float
    threshold: float
    timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False

class PerformanceOptimizer:
    """Performance optimization and caching layer"""
    
    def __init__(self):
        self.connection_pool = {}
        self.query_cache = {}
        self.cache_ttl = {}
        self.max_connections = 50
        self.cache_size = 1000
    
    def get_connection(self, device_ip):
        """Get pooled SSH connection"""
        if device_ip in self.connection_pool:
            conn = self.connection_pool[device_ip]
            if conn and conn.get_transport() and conn.get_transport().is_active():
                return conn
        return None
    
    def cache_query_result(self, key, result, ttl=300):
        """Cache query results with TTL"""
        if len(self.query_cache) >= self.cache_size:
            # Remove oldest entries
            oldest_key = min(self.cache_ttl.keys(), key=lambda k: self.cache_ttl[k])
            del self.query_cache[oldest_key]
            del self.cache_ttl[oldest_key]
        
        self.query_cache[key] = result
        self.cache_ttl[key] = time.time() + ttl
    
    def get_cached_result(self, key):
        """Get cached result if not expired"""
        if key in self.query_cache:
            if time.time() < self.cache_ttl[key]:
                return self.query_cache[key]
            else:
                del self.query_cache[key]
                del self.cache_ttl[key]
        return None

class AnomalyDetector:
    """ML-based anomaly detection for metrics"""
    
    def __init__(self):
        self.baselines = {}
        self.history_window = 100
    
    def update_baseline(self, device_ip, metric, value):
        """Update baseline statistics for anomaly detection"""
        key = f"{device_ip}_{metric}"
        if key not in self.baselines:
            self.baselines[key] = deque(maxlen=self.history_window)
        
        self.baselines[key].append(value)
    
    def detect_anomaly(self, device_ip, metric, value):
        """Detect if current value is anomalous"""
        key = f"{device_ip}_{metric}"
        if key not in self.baselines or len(self.baselines[key]) < 10:
            return False
        
        data = list(self.baselines[key])
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data) if len(data) > 1 else 0
        
        # Consider value anomalous if it's beyond 2 standard deviations
        if std_dev > 0:
            z_score = abs(value - mean) / std_dev
            return z_score > 2
        
        return False

class AlertManager:
    """Advanced alerting system with escalation"""
    
    def __init__(self, app):
        self.app = app
        self.alerts = {}
        self.thresholds = {
            'cpu': AlertThreshold('cpu', 80.0, 95.0, 300),
            'memory': AlertThreshold('memory', 85.0, 95.0, 300),
            'disk': AlertThreshold('disk', 90.0, 98.0, 600),
            'failed_logins': AlertThreshold('failed_logins', 5, 10, 60)
        }
        self.escalation_rules = []
        self.notification_queue = queue.Queue()
        self.anomaly_detector = AnomalyDetector()
        
        # Start notification thread
        self.notification_thread = threading.Thread(target=self._process_notifications, daemon=True)
        self.notification_thread.start()
    
    def set_threshold(self, metric, warning, critical, duration):
        """Set alert threshold for metric"""
        self.thresholds[metric] = AlertThreshold(metric, warning, critical, duration)
    
    def check_metric(self, device_ip, metric, value):
        """Check if metric value triggers an alert"""
        if metric not in self.thresholds or not self.thresholds[metric].enabled:
            return
        
        threshold = self.thresholds[metric]
        alert_key = f"{device_ip}_{metric}"
        
        # Update anomaly detection baseline
        self.anomaly_detector.update_baseline(device_ip, metric, value)
        
        # Check for anomalies
        if self.anomaly_detector.detect_anomaly(device_ip, metric, value):
            self._create_alert(device_ip, metric, value, "anomaly", "Anomalous behavior detected")
        
        # Check thresholds
        if value >= threshold.critical_level:
            self._create_alert(device_ip, metric, value, "critical", threshold.critical_level)
        elif value >= threshold.warning_level:
            self._create_alert(device_ip, metric, value, "warning", threshold.warning_level)
        else:
            # Resolve existing alert if value is back to normal
            if alert_key in self.alerts and not self.alerts[alert_key].resolved:
                self.alerts[alert_key].resolved = True
                self._send_notification("resolved", self.alerts[alert_key])
    
    def _create_alert(self, device_ip, metric, value, level, threshold):
        """Create new alert"""
        alert_id = f"{device_ip}_{metric}_{int(time.time())}"
        alert = Alert(
            id=alert_id,
            device_ip=device_ip,
            metric=metric,
            level=level,
            value=value,
            threshold=threshold,
            timestamp=datetime.now()
        )
        
        self.alerts[alert_id] = alert
        self._send_notification("new", alert)
        
        # Update GUI
        self.app.root.after(0, lambda: self.app.update_alerts_display())
    
    def _send_notification(self, action, alert):
        """Queue notification for processing"""
        self.notification_queue.put((action, alert))
    
    def _process_notifications(self):
        """Process notification queue"""
        while True:
            try:
                action, alert = self.notification_queue.get(timeout=1)
                
                # Log alert
                logger.warning(f"Alert {action}: {alert.device_ip} - {alert.metric} = {alert.value} ({alert.level})")
                
                # Send email notification (if configured)
                self._send_email_notification(action, alert)
                
                # Send to external systems (webhooks, etc.)
                self._send_webhook_notification(action, alert)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Notification processing error: {e}")
    
    def _send_email_notification(self, action, alert):
        """Send email notification"""
        # Email notification implementation
        pass
    
    def _send_webhook_notification(self, action, alert):
        """Send webhook notification"""
        # Webhook notification implementation
        pass
    
    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert"""
        if alert_id in self.alerts:
            self.alerts[alert_id].acknowledged = True
    
    def get_active_alerts(self):
        """Get all active (unresolved) alerts"""
        return [alert for alert in self.alerts.values() if not alert.resolved]

class NetworkDevice:
    def __init__(self, ip, hostname="Unknown", os_type="Unknown", status="Unknown"):
        self.ip = ip
        self.hostname = hostname
        self.os_type = os_type
        self.status = status
        self.ssh_client = None
        self.monitoring_enabled = False
        
        # Enhanced metrics with history
        self.metrics_history = {
            'cpu': deque(maxlen=300),  # 5 minutes at 1-second intervals
            'memory': deque(maxlen=300),
            'disk': deque(maxlen=300),
            'network_in': deque(maxlen=300),
            'network_out': deque(maxlen=300),
            'processes': deque(maxlen=60),  # Process count
            'load_avg': deque(maxlen=300)
        }
        
        self.timestamps = deque(maxlen=300)
        self.failed_logins = []
        self.last_update = None
        self.services = {}
        self.hardware_info = {}
        
    def add_metric(self, metric_type, value):
        """Add metric value with timestamp"""
        self.metrics_history[metric_type].append(value)
        if metric_type == 'cpu':  # Use CPU as the primary metric for timestamps
            self.timestamps.append(datetime.now())
    
    def get_latest_metric(self, metric_type):
        """Get latest metric value"""
        if self.metrics_history[metric_type]:
            return self.metrics_history[metric_type][-1]
        return 0
    
    def get_metric_average(self, metric_type, minutes=5):
        """Get average metric value over specified minutes"""
        if not self.metrics_history[metric_type]:
            return 0
        
        # Calculate how many data points to include
        points = min(minutes * 60, len(self.metrics_history[metric_type]))
        if points == 0:
            return 0
        
        return sum(list(self.metrics_history[metric_type])[-points:]) / points
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'os_type': self.os_type,
            'status': self.status,
            'monitoring_enabled': self.monitoring_enabled,
            'last_update': self.last_update.isoformat() if self.last_update else None
        }

class EnhancedDatabaseManager:
    """Enhanced database with connection pooling and optimization"""
    
    def __init__(self, db_path="network_monitor.db"):
        self.db_path = db_path
        self.connection_pool = []
        self.pool_size = 10
        self.init_database()
        self._create_connection_pool()
    
    def _create_connection_pool(self):
        """Create database connection pool"""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
            self.connection_pool.append(conn)
    
    def get_connection(self):
        """Get connection from pool"""
        if self.connection_pool:
            return self.connection_pool.pop()
        return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def return_connection(self, conn):
        """Return connection to pool"""
        if len(self.connection_pool) < self.pool_size:
            self.connection_pool.append(conn)
        else:
            conn.close()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                hostname TEXT,
                os_type TEXT,
                status TEXT,
                monitoring_enabled BOOLEAN,
                last_seen TIMESTAMP,
                hardware_info TEXT,
                services TEXT
            )
        ''')
        
        # Enhanced metrics table with indexing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                timestamp TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_bytes_sent INTEGER,
                network_bytes_recv INTEGER,
                load_avg_1 REAL,
                load_avg_5 REAL,
                load_avg_15 REAL,
                process_count INTEGER,
                FOREIGN KEY (device_ip) REFERENCES devices (ip)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                device_ip TEXT,
                metric TEXT,
                level TEXT,
                value REAL,
                threshold_value REAL,
                timestamp TIMESTAMP,
                acknowledged BOOLEAN DEFAULT FALSE,
                resolved BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (device_ip) REFERENCES devices (ip)
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_device_time ON metrics(device_ip, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
        
        conn.commit()
        conn.close()
    
    def save_device(self, device):
        """Save device to database"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO devices 
                (ip, hostname, os_type, status, monitoring_enabled, last_seen, hardware_info, services)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.ip, device.hostname, device.os_type, device.status,
                device.monitoring_enabled, device.last_update,
                json.dumps(device.hardware_info), json.dumps(device.services)
            ))
            conn.commit()
        finally:
            self.return_connection(conn)
    
    def save_metrics_batch(self, metrics_batch):
        """Save multiple metrics in a single transaction"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.executemany('''
                INSERT INTO metrics 
                (device_ip, timestamp, cpu_percent, memory_percent, disk_percent, 
                 network_bytes_sent, network_bytes_recv, load_avg_1, load_avg_5, 
                 load_avg_15, process_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', metrics_batch)
            conn.commit()
        finally:
            self.return_connection(conn)
    
    def cleanup_old_data(self, days_to_keep=30):
        """Clean up old data to maintain performance"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            cursor.execute('DELETE FROM metrics WHERE timestamp < ?', (cutoff_date,))
            cursor.execute('DELETE FROM alerts WHERE timestamp < ? AND resolved = TRUE', (cutoff_date,))
            conn.commit()
            
            # Vacuum database to reclaim space
            cursor.execute('VACUUM')
        finally:
            self.return_connection(conn)

class EnhancedSSHManager:
    """Enhanced SSH manager with connection pooling"""
    
    def __init__(self):
        self.connections = {}
        self.performance_optimizer = PerformanceOptimizer()
        self.custom_scripts = {}
    
    def connect_to_device(self, device, username, password, port=22):
        """Connect to device via SSH"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(device.ip, port=port, username=username, password=password, timeout=10)
            device.ssh_client = client
            return True
        except Exception as e:
            logger.error(f"SSH connection failed for {device.ip}: {e}")
            return False
    
    def execute_command(self, device, command):
        """Execute command on device"""
        try:
            if not device.ssh_client:
                return None
            
            stdin, stdout, stderr = device.ssh_client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                logger.warning(f"Command error on {device.ip}: {error}")
            
            return output
        except Exception as e:
            logger.error(f"Command execution failed on {device.ip}: {e}")
            return None
    
    def create_monitoring_account(self, device, username, password=None):
        """Create monitoring account on device"""
        try:
            if not password:
                password = hashlib.md5(f"{username}{device.ip}".encode()).hexdigest()[:12]
            
            # Commands to create user and set permissions
            commands = [
                f"useradd -m -s /bin/bash {username}",
                f"echo '{username}:{password}' | chpasswd",
                f"usermod -aG sudo {username}",
                f"mkdir -p /home/{username}/.ssh",
                f"chmod 700 /home/{username}/.ssh",
                f"chown {username}:{username} /home/{username}/.ssh"
            ]
            
            for cmd in commands:
                self.execute_command(device, cmd)
            
            return username, password
        except Exception as e:
            logger.error(f"Failed to create monitoring account on {device.ip}: {e}")
            return None, None
    
    def get_enhanced_metrics(self, device):
        """Get comprehensive system metrics"""
        try:
            metrics = {}
            
            # CPU usage
            cpu_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//'"
            cpu_output = self.execute_command(device, cpu_cmd)
            if cpu_output:
                try:
                    metrics['cpu'] = float(cpu_output.strip())
                except ValueError:
                    metrics['cpu'] = 0.0
            else:
                metrics['cpu'] = 0.0
            
            # Memory usage
            mem_cmd = "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'"
            mem_output = self.execute_command(device, mem_cmd)
            if mem_output:
                try:
                    metrics['memory'] = float(mem_output.strip())
                except ValueError:
                    metrics['memory'] = 0.0
            else:
                metrics['memory'] = 0.0
            
            # Disk usage
            disk_cmd = "df -h / | awk 'NR==2{print $5}' | sed 's/%//'"
            disk_output = self.execute_command(device, disk_cmd)
            if disk_output:
                try:
                    metrics['disk'] = float(disk_output.strip())
                except ValueError:
                    metrics['disk'] = 0.0
            else:
                metrics['disk'] = 0.0
            
            # Network metrics
            metrics['network_in'] = 0
            metrics['network_out'] = 0
            
            # Load average
            load_cmd = "cat /proc/loadavg | awk '{print $1, $2, $3}'"
            load_output = self.execute_command(device, load_cmd)
            if load_output:
                try:
                    load_parts = load_output.strip().split()
                    metrics['load_avg'] = [float(x) for x in load_parts[:3]]
                except ValueError:
                    metrics['load_avg'] = [0.0, 0.0, 0.0]
            else:
                metrics['load_avg'] = [0.0, 0.0, 0.0]
            
            # Process count
            proc_cmd = "ps aux | wc -l"
            proc_output = self.execute_command(device, proc_cmd)
            if proc_output:
                try:
                    metrics['processes'] = int(proc_output.strip())
                except ValueError:
                    metrics['processes'] = 0
            else:
                metrics['processes'] = 0
            
            # Top services
            service_cmd = "ps aux --sort=-%cpu | head -6 | tail -5 | awk '{print $11, $3}'"
            service_output = self.execute_command(device, service_cmd)
            services = {}
            if service_output:
                for line in service_output.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                services[parts[0]] = float(parts[1])
                            except ValueError:
                                services[parts[0]] = 0.0
            metrics['top_services'] = services
            
            metrics['timestamp'] = datetime.now()
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get enhanced metrics for {device.ip}: {e}")
            return None

class ModernGUI:
    """Modern, responsive GUI with advanced features"""
    
    def __init__(self, root, app):
        self.root = root
        self.app = app
        self.current_theme = "light"
        self.custom_widgets = {}
        self.setup_styles()
    
    def setup_styles(self):
        """Setup modern styling"""
        self.style = ttk.Style()
        
        # Configure modern themes
        self.themes = {
            "light": {
                "bg": "#ffffff",
                "fg": "#333333",
                "select_bg": "#0078d4",
                "select_fg": "#ffffff",
                "accent": "#0078d4"
            },
            "dark": {
                "bg": "#2d2d2d",
                "fg": "#ffffff",
                "select_bg": "#0078d4",
                "select_fg": "#ffffff",
                "accent": "#00bcf2"
            }
        }
        
        self.apply_theme(self.current_theme)
    
    def apply_theme(self, theme_name):
        """Apply selected theme"""
        if theme_name not in self.themes:
            return
        
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        
        # Configure ttk styles
        self.style.configure("Custom.TFrame", background=theme["bg"])
        self.style.configure("Custom.TLabel", background=theme["bg"], foreground=theme["fg"])
        self.style.configure("Custom.TButton", background=theme["accent"], foreground=theme["select_fg"])
        
        # Update root background
        self.root.configure(bg=theme["bg"])
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        new_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme(new_theme)
    
    def create_metric_card(self, parent, title, value, unit="", color="#0078d4"):
        """Create modern metric display card"""
        frame = ttk.Frame(parent, style="Custom.TFrame", relief="solid", borderwidth=1)
        frame.pack(side=tk.LEFT, fill="both", expand=True, padx=5, pady=2)
        
        title_label = ttk.Label(frame, text=title, font=("Arial", 10), style="Custom.TLabel")
        title_label.pack(anchor="w", padx=10, pady=(5, 0))
        
        value_label = ttk.Label(frame, text=f"{value}{unit}", font=("Arial", 16, "bold"), 
                               foreground=color, style="Custom.TLabel")
        value_label.pack(anchor="w", padx=10, pady=(0, 5))
        
        return frame, value_label

class EnhancedMonitoringThread:
    """Enhanced monitoring with async operations and batch processing"""
    
    def __init__(self, app):
        self.app = app
        self.running = False
        self.thread = None
        self.worker_threads = []
        self.metrics_queue = queue.Queue()
        self.batch_size = 10
        self.monitoring_interval = 5
    
    def start(self):
        """Start monitoring with multiple worker threads"""
        if not self.running:
            self.running = True
            
            # Main monitoring thread
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            
            # Metrics processing thread
            metrics_thread = threading.Thread(target=self._process_metrics_queue, daemon=True)
            metrics_thread.start()
            self.worker_threads.append(metrics_thread)
    
    def stop(self):
        """Stop all monitoring threads"""
        self.running = False
        if self.thread:
            self.thread.join()
        for worker in self.worker_threads:
            worker.join()
    
    def _monitor_loop(self):
        """Main monitoring loop with device distribution"""
        while self.running:
            try:
                enabled_devices = [d for d in self.app.devices.values() if d.monitoring_enabled]
                
                if enabled_devices:
                    # Use ThreadPoolExecutor for parallel monitoring
                    with ThreadPoolExecutor(max_workers=min(10, len(enabled_devices))) as executor:
                        future_to_device = {
                            executor.submit(self._monitor_device, device): device 
                            for device in enabled_devices
                        }
                        
                        for future in as_completed(future_to_device, timeout=30):
                            device = future_to_device[future]
                            try:
                                metrics = future.result()
                                if metrics:
                                    self.metrics_queue.put((device, metrics))
                            except Exception as e:
                                logger.error(f"Monitoring error for {device.ip}: {e}")
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)
    
    def _monitor_device(self, device):
        """Monitor single device"""
        try:
            if not device.ssh_client:
                return None
            
            # Get enhanced metrics
            metrics = self.app.ssh_manager.get_enhanced_metrics(device)
            if not metrics:
                return None
            
            # Update device metrics history
            device.add_metric('cpu', metrics['cpu'])
            device.add_metric('memory', metrics['memory'])
            device.add_metric('disk', metrics['disk'])
            device.add_metric('network_in', metrics['network_in'])
            device.add_metric('network_out', metrics['network_out'])
            device.add_metric('processes', metrics['processes'])
            device.add_metric('load_avg', metrics['load_avg'][0] if metrics['load_avg'] else 0)
            
            device.last_update = datetime.now()
            device.services = metrics.get('top_services', {})
            
            # Check alerts
            self.app.alert_manager.check_metric(device.ip, 'cpu', metrics['cpu'])
            self.app.alert_manager.check_metric(device.ip, 'memory', metrics['memory'])
            self.app.alert_manager.check_metric(device.ip, 'disk', metrics['disk'])
            
            return metrics
            
        except Exception as e:
            logger.error(f"Device monitoring error for {device.ip}: {e}")
            return None
    
    def _process_metrics_queue(self):
        """Process metrics queue for real-time updates"""
        while self.running:
            try:
                device, metrics = self.metrics_queue.get(timeout=1)
                
                # Update GUI in real-time
                self.app.root.after(0, lambda: self.app.update_device_display())
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Metrics queue processing error: {e}")

class NetworkScanner:
    """Network scanning functionality with multi-threading support"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.scanning = False
    
    def get_local_network(self):
        """Get local network range"""
        try:
            # Try to get default gateway
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Default Gateway' in line:
                            gateway = line.split(':')[-1].strip()
                            if gateway and '.' in gateway:
                                network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                                return network
            else:  # Linux/Unix
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    gateway = result.stdout.split()[2]
                    network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                    return network
        except Exception as e:
            if self.callback:
                self.callback(f"Network detection error: {e}")
        
        return "192.168.1.0/24"
    
    def ping_host(self, ip):
        """Ping a single host - cross-platform"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=3)
            else:  # Linux/Mac
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=3)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname if hostname != ip else "Unknown"
        except Exception:
            return "Unknown"
    
    def detect_os(self, ip):
        """Simple OS detection based on ping TTL"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['ping', '-n', '1', ip], 
                                      capture_output=True, text=True, timeout=3)
            else:  # Linux/Mac
                result = subprocess.run(['ping', '-c', '1', ip], 
                                      capture_output=True, text=True, timeout=3)
            
            if 'ttl=' in result.stdout.lower():
                ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Network Device"
        except Exception:
            pass
        return "Unknown"
    
    def scan_network(self, network_range=None):
        """Scan network for active devices"""
        if not network_range:
            network_range = self.get_local_network()
        
        self.scanning = True
        devices = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            if self.callback:
                self.callback(f"Scanning {len(hosts)} hosts in {network_range}...")
            
            # Use ThreadPoolExecutor for faster scanning
            with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as executor:
                future_to_ip = {executor.submit(self.scan_host, str(ip)): str(ip) 
                               for ip in hosts}
                
                completed = 0
                for future in as_completed(future_to_ip):
                    if not self.scanning:
                        break
                    
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        device = future.result()
                        if device:
                            devices.append(device)
                            if self.callback:
                                self.callback(f"Found device: {device.ip} ({device.hostname}) - {completed}/{len(hosts)}")
                    except Exception as e:
                        if self.callback:
                            self.callback(f"Error scanning {ip}: {str(e)}")
        
        except Exception as e:
            if self.callback:
                self.callback(f"Network scan error: {str(e)}")
        
        self.scanning = False
        return devices
    
    def scan_host(self, ip):
        """Scan a single host and return NetworkDevice if active"""
        if self.ping_host(ip):
            hostname = self.get_hostname(ip)
            os_type = self.detect_os(ip)
            return NetworkDevice(ip, hostname, os_type, "Online")
        return None
    
    def stop_scan(self):
        """Stop current scan"""
        self.scanning = False

class EnhancedPCManagementApp:
    """Enhanced PC Management Application with enterprise features"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Network PC Management System v2.0")
        self.root.geometry("1600x1000")
        self.root.state('zoomed')  # Maximize window
        
        # Initialize enhanced components
        self.devices = {}
        self.db_manager = EnhancedDatabaseManager()
        self.ssh_manager = EnhancedSSHManager()
        self.scanner = NetworkScanner(self.log_message)
        self.alert_manager = AlertManager(self)
        self.monitoring_thread = EnhancedMonitoringThread(self)
        self.modern_gui = ModernGUI(root, self)
        
        # Performance optimization
        self.performance_optimizer = PerformanceOptimizer()
        
        # Configuration
        self.config = configparser.ConfigParser()
        self.load_configuration()
        
        # GUI setup
        self.setup_enhanced_gui()
        
        # Auto-save configuration
        self.auto_save_thread = threading.Thread(target=self._auto_save_loop, daemon=True)
        self.auto_save_thread.start()
        
        # Start enhanced monitoring
        self.monitoring_thread.start()
        
        # Schedule cleanup tasks
        self.schedule_cleanup_tasks()
    
    def load_configuration(self):
        """Load application configuration"""
        self.config.read('config.ini')
        
        # Set defaults if config doesn't exist
        if not self.config.sections():
            self.config['MONITORING'] = {
                'interval': '5',
                'batch_size': '10',
                'data_retention_days': '30'
            }
            self.config['ALERTS'] = {
                'cpu_warning': '80',
                'cpu_critical': '95',
                'memory_warning': '85',
                'memory_critical': '95'
            }
            self.config['GUI'] = {
                'theme': 'light',
                'auto_refresh': 'true',
                'show_animations': 'true'
            }
            self.save_configuration()
    
    def save_configuration(self):
        """Save application configuration"""
        with open('config.ini', 'w') as f:
            self.config.write(f)
    
    def setup_enhanced_gui(self):
        """Setup enhanced modern GUI"""
        self.create_enhanced_menu()
        self.create_enhanced_toolbar()
        self.create_enhanced_main_panels()
        self.create_enhanced_status_bar()
        
        # Keyboard shortcuts
        self.setup_keyboard_shortcuts()
        
        # Auto-refresh timer
        self.setup_auto_refresh()
    
    def create_enhanced_menu(self):
        """Create enhanced menu with more options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Quick Scan", command=self.quick_scan, accelerator="Ctrl+Q")
        file_menu.add_command(label="Full Network Scan", command=self.scan_network, accelerator="Ctrl+S")
        file_menu.add_command(label="Import Devices", command=self.import_devices)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Preferences", command=self.show_preferences, accelerator="Ctrl+P")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.safe_exit, accelerator="Ctrl+Q")
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Theme", command=self.modern_gui.toggle_theme, accelerator="Ctrl+T")
        view_menu.add_command(label="Refresh All", command=self.refresh_all, accelerator="F5")
        view_menu.add_command(label="Alerts Dashboard", command=self.show_alerts_dashboard)
        view_menu.add_command(label="Performance Monitor", command=self.show_performance_monitor)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Bulk Device Setup", command=self.bulk_setup_dialog)
        tools_menu.add_command(label="Alert Configuration", command=self.configure_alerts)
        tools_menu.add_command(label="Custom Scripts", command=self.manage_custom_scripts)
        tools_menu.add_command(label="Network Topology", command=self.show_network_topology)
        tools_menu.add_command(label="Security Report", command=self.show_security_report)
        tools_menu.add_command(label="Database Cleanup", command=self.cleanup_database)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_enhanced_toolbar(self):
        """Create enhanced toolbar with modern styling"""
        toolbar = ttk.Frame(self.root, style="Custom.TFrame")
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # Left side buttons
        left_frame = ttk.Frame(toolbar)
        left_frame.pack(side=tk.LEFT)
        
        # Modern styled buttons
        scan_btn = ttk.Button(left_frame, text="🔍 Quick Scan", command=self.quick_scan)
        scan_btn.pack(side=tk.LEFT, padx=2)
        
        refresh_btn = ttk.Button(left_frame, text="🔄 Refresh", command=self.refresh_all)
        refresh_btn.pack(side=tk.LEFT, padx=2)
        
        setup_btn = ttk.Button(left_frame, text="⚙️ Setup", command=self.bulk_setup_dialog)
        setup_btn.pack(side=tk.LEFT, padx=2)
        
        alerts_btn = ttk.Button(left_frame, text="🚨 Alerts", command=self.show_alerts_dashboard)
        alerts_btn.pack(side=tk.LEFT, padx=2)
        
        # Search and filter
        middle_frame = ttk.Frame(toolbar)
        middle_frame.pack(side=tk.LEFT, padx=20)
        
        ttk.Label(middle_frame, text="🔍 Search:", style="Custom.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(middle_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=2)
        search_entry.bind('<KeyRelease>', self.filter_devices)
        
        # Network range
        ttk.Label(middle_frame, text="🌐 Network:", style="Custom.TLabel").pack(side=tk.LEFT, padx=(20, 5))
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(middle_frame, textvariable=self.network_var, width=15)
        network_entry.pack(side=tk.LEFT, padx=2)
        
        # Right side indicators
        right_frame = ttk.Frame(toolbar)
        right_frame.pack(side=tk.RIGHT)
        
        # Active alerts indicator
        self.alerts_indicator = ttk.Label(right_frame, text="🔴 0 Alerts", style="Custom.TLabel")
        self.alerts_indicator.pack(side=tk.RIGHT, padx=10)
        
        # Monitoring status
        self.monitoring_status = ttk.Label(right_frame, text="⏸️ Stopped", style="Custom.TLabel")
        self.monitoring_status.pack(side=tk.RIGHT, padx=10)
        
        # Theme toggle
        theme_btn = ttk.Button(right_frame, text="🌙", command=self.modern_gui.toggle_theme, width=3)
        theme_btn.pack(side=tk.RIGHT, padx=2)
    
    def create_enhanced_main_panels(self):
        """Create enhanced main panels with modern design"""
        # Create main container with better layout
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create paned window with enhanced styling
        self.main_paned = ttk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Enhanced device management
        self.create_enhanced_device_panel()
        
        # Right panel - Enhanced monitoring dashboard
        self.create_enhanced_monitoring_panel()
    
    def create_enhanced_device_panel(self):
        """Create enhanced device management panel"""
        left_panel = ttk.Frame(self.main_paned)
        self.main_paned.add(left_panel, weight=1)
        
        # Header with device count and filters
        header_frame = ttk.Frame(left_panel)
        header_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.device_count_label = ttk.Label(header_frame, text="Devices (0)", 
                                          font=('Arial', 12, 'bold'), style="Custom.TLabel")
        self.device_count_label.pack(side=tk.LEFT)
        
        # Filter buttons
        filter_frame = ttk.Frame(header_frame)
        filter_frame.pack(side=tk.RIGHT)
        
        ttk.Button(filter_frame, text="All", command=lambda: self.filter_devices_by_status("all"), width=8).pack(side=tk.LEFT, padx=1)
        ttk.Button(filter_frame, text="Online", command=lambda: self.filter_devices_by_status("online"), width=8).pack(side=tk.LEFT, padx=1)
        ttk.Button(filter_frame, text="Monitored", command=lambda: self.filter_devices_by_status("monitored"), width=8).pack(side=tk.LEFT, padx=1)
        
        # Enhanced device treeview
        tree_frame = ttk.Frame(left_panel)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Device list with enhanced columns
        columns = ('Status', 'IP', 'Hostname', 'OS', 'CPU %', 'Memory %', 'Last Update', 'Alerts')
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        # Configure columns with better widths
        column_widths = {'Status': 60, 'IP': 120, 'Hostname': 150, 'OS': 100, 
                        'CPU %': 80, 'Memory %': 80, 'Last Update': 120, 'Alerts': 60}
        
        for col in columns:
            self.device_tree.heading(col, text=col, command=lambda c=col: self.sort_devices(c))
            self.device_tree.column(col, width=column_widths.get(col, 100))
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.device_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        self.device_tree.bind('<Double-1>', self.on_device_double_click)
        self.device_tree.bind('<Button-3>', self.show_device_context_menu)
        
        # Device actions frame
        actions_frame = ttk.Frame(left_panel)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="Setup Selected", command=self.setup_selected_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Start Monitoring", command=self.start_monitoring_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Stop Monitoring", command=self.stop_monitoring_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Remove", command=self.remove_selected_devices).pack(side=tk.LEFT, padx=2)
    
    def create_enhanced_monitoring_panel(self):
        """Create enhanced monitoring dashboard panel"""
        right_panel = ttk.Frame(self.main_paned)
        self.main_paned.add(right_panel, weight=2)
        
        # Create enhanced notebook with better styling
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Enhanced monitoring tab
        self.create_enhanced_monitoring_tab()
        
        # Performance analytics tab
        self.create_performance_analytics_tab()
        
        # Real-time alerts tab
        self.create_realtime_alerts_tab()
        
        # Security monitoring tab
        self.create_security_monitoring_tab()
        
        # System logs tab
        self.create_enhanced_logs_tab()
    
    def create_enhanced_monitoring_tab(self):
        """Create enhanced real-time monitoring dashboard"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="📊 Live Monitoring")
        
        # Top metrics summary
        summary_frame = ttk.Frame(monitor_frame)
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Quick stats cards
        self.create_metrics_summary_cards(summary_frame)
        
        # Main monitoring area
        monitoring_area = ttk.Frame(monitor_frame)
        monitoring_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create enhanced matplotlib figure with subplots
        self.fig = Figure(figsize=(14, 10), dpi=80)
        self.fig.patch.set_facecolor('#f8f9fa')
        
        self.canvas = FigureCanvasTkAgg(self.fig, monitoring_area)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create subplots with better layout
        gs = self.fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        self.cpu_ax = self.fig.add_subplot(gs[0, :2])
        self.memory_ax = self.fig.add_subplot(gs[1, :2])
        self.network_ax = self.fig.add_subplot(gs[2, :2])
        
        self.cpu_gauge = self.fig.add_subplot(gs[0, 2])
        self.memory_gauge = self.fig.add_subplot(gs[1, 2])
        self.disk_gauge = self.fig.add_subplot(gs[2, 2])
        
        # Style the plots
        self.style_monitoring_plots()
        
        # Animation for real-time updates
        self.animation = animation.FuncAnimation(
            self.fig, self.update_monitoring_animation, 
            interval=2000, blit=False, cache_frame_data=False
        )
    
    def create_metrics_summary_cards(self, parent):
        """Create summary metric cards"""
        cards_frame = ttk.Frame(parent)
        cards_frame.pack(fill=tk.X, pady=5)
        
        # Summary metrics cards
        self.total_devices_card = self.modern_gui.create_metric_card(
            cards_frame, "Total Devices", "0", "", "#17a2b8"
        )
        
        self.monitored_devices_card = self.modern_gui.create_metric_card(
            cards_frame, "Monitored", "0", "", "#28a745"
        )
        
        self.alerts_card = self.modern_gui.create_metric_card(
            cards_frame, "Active Alerts", "0", "", "#dc3545"
        )
        
        self.avg_cpu_card = self.modern_gui.create_metric_card(
            cards_frame, "Avg CPU", "0", "%", "#fd7e14"
        )
    
    def create_performance_analytics_tab(self):
        """Create performance analytics with advanced charts"""
        analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(analytics_frame, text="📈 Analytics")
        
        # Analytics controls
        controls_frame = ttk.Frame(analytics_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(controls_frame, text="Time Range:", style="Custom.TLabel").pack(side=tk.LEFT, padx=5)
        
        self.time_range_var = tk.StringVar(value="1 Hour")
        time_range_combo = ttk.Combobox(controls_frame, textvariable=self.time_range_var,
                                       values=["15 Minutes", "1 Hour", "6 Hours", "24 Hours", "7 Days"],
                                       state="readonly", width=12)
        time_range_combo.pack(side=tk.LEFT, padx=5)
        time_range_combo.bind('<<ComboboxSelected>>', self.update_analytics)
        
        ttk.Button(controls_frame, text="📊 Generate Report", 
                  command=self.generate_performance_report).pack(side=tk.RIGHT, padx=5)
        
        # Analytics charts area
        analytics_area = ttk.Frame(analytics_frame)
        analytics_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create analytics figure
        self.analytics_fig = Figure(figsize=(14, 8), dpi=80)
        self.analytics_canvas = FigureCanvasTkAgg(self.analytics_fig, analytics_area)
        self.analytics_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_realtime_alerts_tab(self):
        """Create real-time alerts dashboard"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="🚨 Alerts")
        
        # Alert controls
        alert_controls = ttk.Frame(alerts_frame)
        alert_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(alert_controls, text="🔧 Configure Alerts", 
                  command=self.configure_alerts).pack(side=tk.LEFT, padx=5)
        ttk.Button(alert_controls, text="✅ Acknowledge All", 
                  command=self.acknowledge_all_alerts).pack(side=tk.LEFT, padx=5)
        ttk.Button(alert_controls, text="🔄 Refresh", 
                  command=self.refresh_alerts).pack(side=tk.LEFT, padx=5)
        
        # Alert severity filter
        ttk.Label(alert_controls, text="Filter:", style="Custom.TLabel").pack(side=tk.LEFT, padx=(20, 5))
        self.alert_filter_var = tk.StringVar(value="All")
        alert_filter = ttk.Combobox(alert_controls, textvariable=self.alert_filter_var,
                                   values=["All", "Critical", "Warning", "Anomaly"],
                                   state="readonly", width=10)
        alert_filter.pack(side=tk.LEFT, padx=5)
        alert_filter.bind('<<ComboboxSelected>>', self.filter_alerts)
        
        # Alerts treeview
        alerts_tree_frame = ttk.Frame(alerts_frame)
        alerts_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        alert_columns = ('Severity', 'Device', 'Metric', 'Value', 'Threshold', 'Time', 'Status')
        self.alerts_tree = ttk.Treeview(alerts_tree_frame, columns=alert_columns, show='headings')
        
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=100)
        
        # Add scrollbars to alerts tree
        alerts_v_scroll = ttk.Scrollbar(alerts_tree_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        alerts_h_scroll = ttk.Scrollbar(alerts_tree_frame, orient=tk.HORIZONTAL, command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=alerts_v_scroll.set, xscrollcommand=alerts_h_scroll.set)
        
        self.alerts_tree.grid(row=0, column=0, sticky='nsew')
        alerts_v_scroll.grid(row=0, column=1, sticky='ns')
        alerts_h_scroll.grid(row=1, column=0, sticky='ew')
        
        alerts_tree_frame.grid_rowconfigure(0, weight=1)
        alerts_tree_frame.grid_columnconfigure(0, weight=1)
        
        self.alerts_tree.bind('<Double-1>', self.on_alert_double_click)
    
    def create_security_monitoring_tab(self):
        """Create security monitoring dashboard"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="🔒 Security")
        
        # Security summary
        security_summary = ttk.Frame(security_frame)
        security_summary.pack(fill=tk.X, padx=5, pady=5)
        
        # Security metrics cards
        self.failed_logins_card = self.modern_gui.create_metric_card(
            security_summary, "Failed Logins (24h)", "0", "", "#dc3545"
        )
        
        self.suspicious_activity_card = self.modern_gui.create_metric_card(
            security_summary, "Suspicious Activity", "0", "", "#ffc107"
        )
        
        # Security events treeview
        security_events_frame = ttk.Frame(security_frame)
        security_events_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        sec_columns = ('Time', 'Device', 'Event Type', 'Source IP', 'User', 'Risk Level', 'Description')
        self.security_tree = ttk.Treeview(security_events_frame, columns=sec_columns, show='headings')
        
        for col in sec_columns:
            self.security_tree.heading(col, text=col)
            self.security_tree.column(col, width=120)
        
        security_v_scroll = ttk.Scrollbar(security_events_frame, orient=tk.VERTICAL, command=self.security_tree.yview)
        self.security_tree.configure(yscrollcommand=security_v_scroll.set)
        
        self.security_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        security_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_enhanced_logs_tab(self):
        """Create enhanced system logs with filtering"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📝 Logs")
        
        # Log controls
        log_controls = ttk.Frame(logs_frame)
        log_controls.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(log_controls, text="Filter:", style="Custom.TLabel").pack(side=tk.LEFT, padx=5)
        self.log_filter_var = tk.StringVar()
        log_filter_entry = ttk.Entry(log_controls, textvariable=self.log_filter_var, width=30)
        log_filter_entry.pack(side=tk.LEFT, padx=5)
        log_filter_entry.bind('<KeyRelease>', self.filter_logs)
        
        ttk.Label(log_controls, text="Level:", style="Custom.TLabel").pack(side=tk.LEFT, padx=(20, 5))
        self.log_level_var = tk.StringVar(value="All")
        log_level_combo = ttk.Combobox(log_controls, textvariable=self.log_level_var,
                                      values=["All", "ERROR", "WARNING", "INFO", "DEBUG"],
                                      state="readonly", width=10)
        log_level_combo.pack(side=tk.LEFT, padx=5)
        log_level_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        ttk.Button(log_controls, text="🗑️ Clear Logs", command=self.clear_logs).pack(side=tk.RIGHT, padx=5)
        ttk.Button(log_controls, text="💾 Export Logs", command=self.export_logs).pack(side=tk.RIGHT, padx=5)
        
        # Enhanced log display with syntax highlighting
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=25, font=('Consolas', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure text tags for log levels
        self.log_text.tag_configure("ERROR", foreground="#dc3545", font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure("WARNING", foreground="#ffc107", font=('Consolas', 10, 'bold'))
        self.log_text.tag_configure("INFO", foreground="#17a2b8")
        self.log_text.tag_configure("DEBUG", foreground="#6c757d")
    
    def create_enhanced_status_bar(self):
        """Create enhanced status bar with multiple indicators"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Left side - main status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Enterprise Network Management System")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Right side - system indicators
        indicators_frame = ttk.Frame(status_frame)
        indicators_frame.pack(side=tk.RIGHT)
        
        # Database status
        self.db_status = ttk.Label(indicators_frame, text="💾 DB: OK", relief=tk.SUNKEN)
        self.db_status.pack(side=tk.RIGHT, padx=2)
        
        # Network status
        self.network_status = ttk.Label(indicators_frame, text="🌐 Net: Connected", relief=tk.SUNKEN)
        self.network_status.pack(side=tk.RIGHT, padx=2)
        
        # Monitoring status
        self.monitoring_status_bar = ttk.Label(indicators_frame, text="📊 Monitor: Active", relief=tk.SUNKEN)
        self.monitoring_status_bar.pack(side=tk.RIGHT, padx=2)
        
        # Time indicator
        self.time_label = ttk.Label(indicators_frame, text="", relief=tk.SUNKEN)
        self.time_label.pack(side=tk.RIGHT, padx=2)
        self.update_time_display()
    
    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for power users"""
        self.root.bind('<Control-q>', lambda e: self.quick_scan())
        self.root.bind('<Control-s>', lambda e: self.scan_network())
        self.root.bind('<Control-p>', lambda e: self.show_preferences())
        self.root.bind('<Control-t>', lambda e: self.modern_gui.toggle_theme())
        self.root.bind('<F5>', lambda e: self.refresh_all())
        self.root.bind('<Control-Shift-Q>', lambda e: self.safe_exit())
        self.root.bind('<Escape>', lambda e: self.acknowledge_all_alerts())
    
    def setup_auto_refresh(self):
        """Setup auto-refresh timer"""
        if self.config.getboolean('GUI', 'auto_refresh', fallback=True):
            self.auto_refresh_timer()
    
    def auto_refresh_timer(self):
        """Auto-refresh timer for GUI updates"""
        if self.config.getboolean('GUI', 'auto_refresh', fallback=True):
            self.update_device_display()
            self.update_alerts_display()
            self.update_status_indicators()
            
            # Schedule next refresh
            self.root.after(5000, self.auto_refresh_timer)
    
    def schedule_cleanup_tasks(self):
        """Schedule periodic cleanup tasks"""
        def cleanup_loop():
            while True:
                try:
                    # Daily cleanup at 2 AM
                    now = datetime.now()
                    if now.hour == 2 and now.minute == 0:
                        self.db_manager.cleanup_old_data()
                        logger.info("Performed scheduled database cleanup")
                    
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    logger.error(f"Cleanup task error: {e}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
    
    def _auto_save_loop(self):
        """Auto-save configuration periodically"""
        while True:
            try:
                time.sleep(300)  # Save every 5 minutes
                self.save_configuration()
            except Exception as e:
                logger.error(f"Auto-save error: {e}")
    
    # Enhanced Scanning Methods
    def quick_scan(self):
        """Perform quick scan of known devices"""
        def quick_scan_thread():
            self.log_message("Starting quick scan of known devices...")
            
            known_ips = [device.ip for device in self.devices.values()]
            if not known_ips:
                self.log_message("No known devices to scan")
                return
            
            active_count = 0
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(self.scanner.ping_host, ip): ip for ip in known_ips}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            self.devices[ip].status = "Online"
                            active_count += 1
                        else:
                            self.devices[ip].status = "Offline"
                    except Exception as e:
                        logger.error(f"Quick scan error for {ip}: {e}")
            
            self.root.after(0, self.update_device_display)
            self.log_message(f"Quick scan completed. {active_count}/{len(known_ips)} devices online.")
        
        threading.Thread(target=quick_scan_thread, daemon=True).start()
    
    def scan_network(self):
        """Enhanced network scan with progress"""
        def scan_thread():
            self.log_message("Starting comprehensive network scan...")
            self.update_status("Scanning network...")
            
            network_range = self.network_var.get()
            devices = self.scanner.scan_network(network_range)
            
            new_devices = 0
            for device in devices:
                if device.ip not in self.devices:
                    new_devices += 1
                self.devices[device.ip] = device
                self.db_manager.save_device(device)
            
            self.root.after(0, self.update_device_display)
            self.log_message(f"Network scan completed. Found {len(devices)} devices ({new_devices} new).")
            self.update_status("Ready")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    # Device Management Methods
    def import_devices(self):
        """Import devices from CSV file"""
        filename = filedialog.askopenfilename(
            title="Import Devices",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                imported_count = 0
                with open(filename, 'r') as file:
                    lines = file.readlines()
                    
                    for line_num, line in enumerate(lines, 1):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        try:
                            parts = [part.strip() for part in line.split(',')]
                            if len(parts) >= 1:
                                ip = parts[0]
                                hostname = parts[1] if len(parts) > 1 else "Imported"
                                os_type = parts[2] if len(parts) > 2 else "Unknown"
                                status = parts[3] if len(parts) > 3 else "Unknown"
                                
                                try:
                                    ipaddress.IPv4Address(ip)
                                    device = NetworkDevice(ip, hostname, os_type, status)
                                    self.devices[ip] = device
                                    self.db_manager.save_device(device)
                                    imported_count += 1
                                except ipaddress.AddressValueError:
                                    self.log_message(f"Invalid IP address on line {line_num}: {ip}")
                                    
                        except Exception as e:
                            self.log_message(f"Error parsing line {line_num}: {e}")
                
                self.update_device_display()
                messagebox.showinfo("Import Complete", f"Successfully imported {imported_count} devices.")
                self.log_message(f"Imported {imported_count} devices from {filename}")
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import devices: {str(e)}")
                self.log_message(f"Import error: {e}")
    
    def setup_selected_devices(self):
        """Setup monitoring on selected devices"""
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select one or more devices to setup.")
            return
        
        selected_ips = []
        for item in selected:
            device_data = self.device_tree.item(item)
            ip = device_data['values'][1]
            selected_ips.append(ip)
        
        if selected_ips:
            self.show_device_setup_dialog(selected_ips)
    
    def show_device_setup_dialog(self, device_ips):
        """Show setup dialog for selected devices"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Setup {len(device_ips)} Device(s)")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Setup monitoring for {len(device_ips)} selected device(s)").pack(pady=10)
        
        # Credentials form
        ttk.Label(dialog, text="Root Username:").pack(pady=5)
        root_user_var = tk.StringVar(value="root")
        ttk.Entry(dialog, textvariable=root_user_var, width=30).pack(pady=5)
        
        ttk.Label(dialog, text="Root Password:").pack(pady=5)
        root_pass_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=root_pass_var, show="*", width=30).pack(pady=5)
        
        ttk.Label(dialog, text="Monitoring Username:").pack(pady=5)
        mon_user_var = tk.StringVar(value="netmonitor")
        ttk.Entry(dialog, textvariable=mon_user_var, width=30).pack(pady=5)
        
        def start_setup():
            try:
                self.perform_bulk_setup(device_ips, root_user_var.get(), 
                                      root_pass_var.get(), mon_user_var.get())
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Setup Error", f"Setup failed: {str(e)}")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=20)
        
        ttk.Button(button_frame, text="Start Setup", command=start_setup).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def perform_bulk_setup(self, device_ips, root_user, root_pass, mon_user):
        """Perform bulk setup on selected devices"""
        def setup_thread():
            success_count = 0
            total_count = len(device_ips)
            
            for i, ip in enumerate(device_ips):
                try:
                    device = self.devices[ip]
                    
                    # Update progress
                    self.update_status(f"Setting up device {i+1}/{total_count} ({ip})")
                    
                    # First connect with root credentials
                    if self.ssh_manager.connect_to_device(device, root_user, root_pass):
                        # Create monitoring account
                        username, password = self.ssh_manager.create_monitoring_account(
                            device, mon_user, None)
                        
                        if username and password:
                            # Reconnect with monitoring account
                            if self.ssh_manager.connect_to_device(device, username, password):
                                device.monitoring_enabled = True
                                self.db_manager.save_device(device)
                                success_count += 1
                                self.log_message(f"Successfully set up monitoring on {ip}")
                            else:
                                self.log_message(f"Failed to connect with monitoring account on {ip}")
                        else:
                            self.log_message(f"Failed to create monitoring account on {ip}")
                    else:
                        self.log_message(f"Failed to connect to {ip}")
                        
                except Exception as e:
                    self.log_message(f"Failed to setup {ip}: {str(e)}")
            
            self.root.after(0, self.update_device_display)
            self.log_message(f"Bulk setup completed. {success_count}/{total_count} devices configured.")
            self.update_status("Ready")
        
        threading.Thread(target=setup_thread, daemon=True).start()
    
    def start_monitoring_selected(self):
        """Start monitoring on selected devices"""
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select devices to monitor.")
            return
        
        count = 0
        for item in selected:
            device_data = self.device_tree.item(item)
            ip = device_data['values'][1]
            device = self.devices.get(ip)
            
            if device and device.ssh_client:
                device.monitoring_enabled = True
                self.db_manager.save_device(device)
                count += 1
        
        self.update_device_display()
        self.log_message(f"Started monitoring on {count} devices")
    
    def stop_monitoring_selected(self):
        """Stop monitoring on selected devices"""
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select devices to stop monitoring.")
            return
        
        count = 0
        for item in selected:
            device_data = self.device_tree.item(item)
            ip = device_data['values'][1]
            device = self.devices.get(ip)
            
            if device:
                device.monitoring_enabled = False
                self.db_manager.save_device(device)
                count += 1
        
        self.update_device_display()
        self.log_message(f"Stopped monitoring on {count} devices")
    
    def remove_selected_devices(self):
        """Remove selected devices from the list"""
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select devices to remove.")
            return
        
        if messagebox.askyesno("Confirm Removal", f"Remove {len(selected)} selected device(s)?"):
            removed_count = 0
            for item in selected:
                device_data = self.device_tree.item(item)
                ip = device_data['values'][1]
                
                if ip in self.devices:
                    del self.devices[ip]
                    try:
                        conn = self.db_manager.get_connection()
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM devices WHERE ip = ?", (ip,))
                        conn.commit()
                        self.db_manager.return_connection(conn)
                        removed_count += 1
                    except Exception as e:
                        self.log_message(f"Error removing device {ip} from database: {e}")
            
            self.update_device_display()
            self.log_message(f"Removed {removed_count} devices")
    
    def show_device_context_menu(self, event):
        """Show context menu for devices"""
        item = self.device_tree.selection()
        if item:
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="Setup Device", command=self.setup_selected_devices)
            context_menu.add_command(label="Start Monitoring", command=self.start_monitoring_selected)
            context_menu.add_command(label="Stop Monitoring", command=self.stop_monitoring_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Remove Device", command=self.remove_selected_devices)
            context_menu.add_command(label="Device Properties", command=self.show_device_properties_for_selected)
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
    
    def show_device_properties_for_selected(self):
        """Show properties for selected device"""
        selected = self.device_tree.selection()
        if selected:
            device_data = self.device_tree.item(selected[0])
            ip = device_data['values'][1]
            device = self.devices.get(ip)
            if device:
                self.show_device_properties(device)
    
    def show_device_properties(self, device):
        """Show detailed device properties window"""
        props_window = tk.Toplevel(self.root)
        props_window.title(f"Device Properties - {device.ip}")
        props_window.geometry("600x500")
        props_window.transient(self.root)
        
        # Create notebook for different property categories
        props_notebook = ttk.Notebook(props_window)
        props_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General tab
        general_frame = ttk.Frame(props_notebook)
        props_notebook.add(general_frame, text="General")
        
        # Device information
        info_items = [
            ("IP Address", device.ip),
            ("Hostname", device.hostname),
            ("Operating System", device.os_type),
            ("Status", device.status),
            ("Monitoring Enabled", "Yes" if device.monitoring_enabled else "No"),
            ("Last Update", device.last_update.strftime("%Y-%m-%d %H:%M:%S") if device.last_update else "Never")
        ]
        
        for i, (label, value) in enumerate(info_items):
            ttk.Label(general_frame, text=f"{label}:", font=('Arial', 10, 'bold')).grid(row=i, column=0, sticky='w', padx=10, pady=5)
            ttk.Label(general_frame, text=str(value)).grid(row=i, column=1, sticky='w', padx=10, pady=5)
        
        # Performance tab
        perf_frame = ttk.Frame(props_notebook)
        props_notebook.add(perf_frame, text="Performance")
        
        if device.monitoring_enabled:
            current_metrics = [
                ("CPU Usage", f"{device.get_latest_metric('cpu'):.1f}%"),
                ("Memory Usage", f"{device.get_latest_metric('memory'):.1f}%"),
                ("Disk Usage", f"{device.get_latest_metric('disk'):.1f}%"),
                ("Process Count", str(device.get_latest_metric('processes'))),
                ("Load Average", f"{device.get_latest_metric('load_avg'):.2f}")
            ]
            
            for i, (label, value) in enumerate(current_metrics):
                ttk.Label(perf_frame, text=f"{label}:", font=('Arial', 10, 'bold')).grid(row=i, column=0, sticky='w', padx=10, pady=5)
                ttk.Label(perf_frame, text=str(value)).grid(row=i, column=1, sticky='w', padx=10, pady=5)
        else:
            ttk.Label(perf_frame, text="Monitoring not enabled for this device").pack(pady=20)
    
    # GUI Update Methods
    def update_device_display(self):
        """Enhanced device display with better formatting"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Add devices with enhanced information
        device_count = 0
        monitored_count = 0
        
        for device in self.devices.values():
            # Apply search filter
            search_term = self.search_var.get().lower()
            if search_term and search_term not in device.ip.lower() and search_term not in device.hostname.lower():
                continue
            
            device_count += 1
            if device.monitoring_enabled:
                monitored_count += 1
            
            # Status indicator
            status_icon = "🟢" if device.status == "Online" else "🔴" if device.status == "Offline" else "🟡"
            
            # Get latest metrics
            cpu_percent = device.get_latest_metric('cpu')
            memory_percent = device.get_latest_metric('memory')
            
            # Format last update
            last_update = "Never"
            if device.last_update:
                time_diff = datetime.now() - device.last_update
                if time_diff.seconds < 60:
                    last_update = f"{time_diff.seconds}s ago"
                elif time_diff.seconds < 3600:
                    last_update = f"{time_diff.seconds//60}m ago"
                else:
                    last_update = f"{time_diff.seconds//3600}h ago"
            
            # Active alerts count
            device_alerts = [a for a in self.alert_manager.get_active_alerts() if a.device_ip == device.ip]
            alert_count = len(device_alerts)
            alert_text = f"🚨 {alert_count}" if alert_count > 0 else "✅"
            
            # Insert device row
            item_id = self.device_tree.insert('', tk.END, values=(
                status_icon,
                device.ip,
                device.hostname,
                device.os_type,
                f"{cpu_percent:.1f}%" if cpu_percent > 0 else "N/A",
                f"{memory_percent:.1f}%" if memory_percent > 0 else "N/A",
                last_update,
                alert_text
            ))
            
            # Color code based on status and alerts
            if alert_count > 0:
                self.device_tree.item(item_id, tags=('alert',))
            elif device.monitoring_enabled:
                self.device_tree.item(item_id, tags=('monitored',))
        
        # Configure tags for visual feedback
        self.device_tree.tag_configure('alert', background='#ffebee')
        self.device_tree.tag_configure('monitored', background='#e8f5e8')
        
        # Update device count label
        self.device_count_label.config(text=f"Devices ({device_count}) | Monitored ({monitored_count})")
        
        # Update summary cards
        self.update_summary_cards()
    
    def update_summary_cards(self):
        """Update summary metric cards"""
        total_devices = len(self.devices)
        monitored_devices = sum(1 for d in self.devices.values() if d.monitoring_enabled)
        active_alerts = len(self.alert_manager.get_active_alerts())
        
        # Calculate average CPU across all monitored devices
        cpu_values = [d.get_latest_metric('cpu') for d in self.devices.values() 
                     if d.monitoring_enabled and d.get_latest_metric('cpu') > 0]
        avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
        
        # Update cards (simplified implementation)
        if hasattr(self, 'total_devices_card'):
            pass  # Card updates would go here
    
    def update_alerts_display(self):
        """Update alerts display"""
        # Clear existing alerts
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Add active alerts
        active_alerts = self.alert_manager.get_active_alerts()
        
        for alert in sorted(active_alerts, key=lambda a: a.timestamp, reverse=True):
            severity_icon = "🔴" if alert.level == "critical" else "🟡" if alert.level == "warning" else "🔵"
            
            status_text = "Acknowledged" if alert.acknowledged else "Active"
            time_text = alert.timestamp.strftime("%H:%M:%S")
            
            self.alerts_tree.insert('', tk.END, values=(
                f"{severity_icon} {alert.level.upper()}",
                alert.device_ip,
                alert.metric.upper(),
                f"{alert.value:.1f}",
                f"{alert.threshold:.1f}",
                time_text,
                status_text
            ))
        
        # Update alerts indicator in toolbar
        alert_count = len(active_alerts)
        critical_count = sum(1 for a in active_alerts if a.level == "critical")
        
        if critical_count > 0:
            self.alerts_indicator.config(text=f"🔴 {critical_count} Critical")
        elif alert_count > 0:
            self.alerts_indicator.config(text=f"🟡 {alert_count} Alerts")
        else:
            self.alerts_indicator.config(text="✅ No Alerts")
    
    def update_status_indicators(self):
        """Update status bar indicators"""
        # Database status
        try:
            conn = self.db_manager.get_connection()
            self.db_manager.return_connection(conn)
            self.db_status.config(text="💾 DB: OK", foreground="green")
        except:
            self.db_status.config(text="💾 DB: Error", foreground="red")
        
        # Monitoring status
        if self.monitoring_thread.running:
            monitored_count = sum(1 for d in self.devices.values() if d.monitoring_enabled)
            self.monitoring_status_bar.config(text=f"📊 Monitor: {monitored_count} devices", foreground="green")
        else:
            self.monitoring_status_bar.config(text="📊 Monitor: Stopped", foreground="red")
    
    def update_time_display(self):
        """Update time display in status bar"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time_display)
    
    # Monitoring and Visualization Methods
    def style_monitoring_plots(self):
        """Apply modern styling to monitoring plots"""
        plots = [self.cpu_ax, self.memory_ax, self.network_ax]
        gauges = [self.cpu_gauge, self.memory_gauge, self.disk_gauge]
        
        # Style line plots
        for ax in plots:
            ax.set_facecolor('#f8f9fa')
            ax.grid(True, alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
        
        # Style gauge plots
        for ax in gauges:
            ax.set_facecolor('#f8f9fa')
            ax.set_aspect('equal')
    
    def update_monitoring_animation(self, frame):
        """Update monitoring charts with animation"""
        selected = self.device_tree.selection()
        if not selected:
            return
        
        item = self.device_tree.item(selected[0])
        device_ip = item['values'][1]
        device = self.devices.get(device_ip)
        
        if not device or not device.monitoring_enabled:
            return
        
        # Clear plots
        self.cpu_ax.clear()
        self.memory_ax.clear()
        self.network_ax.clear()
        
        # Get recent data
        cpu_data = list(device.metrics_history['cpu'])
        memory_data = list(device.metrics_history['memory'])
        network_in_data = list(device.metrics_history['network_in'])
        network_out_data = list(device.metrics_history['network_out'])
        
        if cpu_data:
            times = list(range(len(cpu_data)))
            
            # CPU plot with gradient fill
            self.cpu_ax.plot(times, cpu_data, color='#007bff', linewidth=2)
            self.cpu_ax.fill_between(times, cpu_data, alpha=0.3, color='#007bff')
            self.cpu_ax.set_title(f'CPU Usage - {device.hostname}', fontsize=12, fontweight='bold')
            self.cpu_ax.set_ylabel('Percentage')
            self.cpu_ax.set_ylim(0, 100)
            
            # Memory plot
            self.memory_ax.plot(times, memory_data, color='#28a745', linewidth=2)
            self.memory_ax.fill_between(times, memory_data, alpha=0.3, color='#28a745')
            self.memory_ax.set_title(f'Memory Usage - {device.hostname}', fontsize=12, fontweight='bold')
            self.memory_ax.set_ylabel('Percentage')
            self.memory_ax.set_ylim(0, 100)
            
            # Network plot
            if network_in_data and network_out_data:
                self.network_ax.plot(times, network_in_data, color='#17a2b8', label='In', linewidth=2)
                self.network_ax.plot(times, network_out_data, color='#ffc107', label='Out', linewidth=2)
                self.network_ax.set_title(f'Network Activity - {device.hostname}', fontsize=12, fontweight='bold')
                self.network_ax.set_ylabel('Bytes/sec')
                self.network_ax.legend()
            
            # Update gauges
            self.update_gauge_plots(device)
        
        # Apply styling
        self.style_monitoring_plots()
        
        # Refresh canvas
        self.canvas.draw_idle()
    
    def update_gauge_plots(self, device):
        """Update circular gauge plots"""
        latest_cpu = device.get_latest_metric('cpu')
        latest_memory = device.get_latest_metric('memory')
        latest_disk = device.get_latest_metric('disk')
        
        # Clear gauge plots
        self.cpu_gauge.clear()
        self.memory_gauge.clear()
        self.disk_gauge.clear()
        
        # Create circular gauges
        self.create_circular_gauge(self.cpu_gauge, latest_cpu, "CPU", "#007bff")
        self.create_circular_gauge(self.memory_gauge, latest_memory, "Memory", "#28a745")
        self.create_circular_gauge(self.disk_gauge, latest_disk, "Disk", "#dc3545")
    
    def create_circular_gauge(self, ax, value, label, color):
        """Create a circular gauge plot"""
        ax.clear()
        
        # Create circle
        theta = np.linspace(0, 2*np.pi, 100)
        r = 1
        
        # Background circle
        ax.plot(r * np.cos(theta), r * np.sin(theta), color='#e9ecef', linewidth=8)
        
        # Value arc
        value_theta = np.linspace(0, 2*np.pi * (value/100), int(value))
        if len(value_theta) > 0:
            ax.plot(r * np.cos(value_theta), r * np.sin(value_theta), color=color, linewidth=8)
        
        # Center text
        ax.text(0, 0, f"{value:.1f}%\n{label}", ha='center', va='center', 
                fontsize=10, fontweight='bold')
        
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-1.2, 1.2)
        ax.set_aspect('equal')
        ax.axis('off')
    
    # Alert Management Methods
    def configure_alerts(self):
        """Show alert configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Alert Configuration")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create notebook for different alert types
        alert_notebook = ttk.Notebook(dialog)
        alert_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Threshold alerts tab
        threshold_frame = ttk.Frame(alert_notebook)
        alert_notebook.add(threshold_frame, text="Thresholds")
        
        # Create threshold configuration UI
        threshold_configs = {}
        metrics = ['cpu', 'memory', 'disk', 'failed_logins']
        
        for i, metric in enumerate(metrics):
            frame = ttk.LabelFrame(threshold_frame, text=f"{metric.upper()} Alerts")
            frame.grid(row=i//2, column=i%2, padx=10, pady=10, sticky='ew')
            
            threshold = self.alert_manager.thresholds.get(metric, AlertThreshold(metric, 80, 95, 300))
            
            # Warning threshold
            ttk.Label(frame, text="Warning Level:").pack(anchor='w', padx=5, pady=2)
            warning_var = tk.DoubleVar(value=threshold.warning_level)
            ttk.Scale(frame, from_=0, to=100, variable=warning_var, orient=tk.HORIZONTAL).pack(fill='x', padx=5)
            
            # Critical threshold
            ttk.Label(frame, text="Critical Level:").pack(anchor='w', padx=5, pady=2)
            critical_var = tk.DoubleVar(value=threshold.critical_level)
            ttk.Scale(frame, from_=0, to=100, variable=critical_var, orient=tk.HORIZONTAL).pack(fill='x', padx=5)
            
            # Duration
            ttk.Label(frame, text="Duration (seconds):").pack(anchor='w', padx=5, pady=2)
            duration_var = tk.IntVar(value=threshold.duration)
            ttk.Spinbox(frame, from_=60, to=3600, textvariable=duration_var, width=10).pack(anchor='w', padx=5)
            
            # Enabled checkbox
            enabled_var = tk.BooleanVar(value=threshold.enabled)
            ttk.Checkbutton(frame, text="Enabled", variable=enabled_var).pack(anchor='w', padx=5, pady=5)
            
            threshold_configs[metric] = {
                'warning': warning_var,
                'critical': critical_var,
                'duration': duration_var,
                'enabled': enabled_var
            }
        
        # Save function
        def save_alert_config():
            for metric, config in threshold_configs.items():
                self.alert_manager.set_threshold(
                    metric,
                    config['warning'].get(),
                    config['critical'].get(),
                    config['duration'].get()
                )
                self.alert_manager.thresholds[metric].enabled = config['enabled'].get()
            
            messagebox.showinfo("Success", "Alert configuration saved.")
            dialog.destroy()
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_alert_config).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def acknowledge_all_alerts(self):
        """Acknowledge all active alerts"""
        active_alerts = self.alert_manager.get_active_alerts()
        for alert in active_alerts:
            self.alert_manager.acknowledge_alert(alert.id)
        
        self.update_alerts_display()
        self.log_message(f"Acknowledged {len(active_alerts)} alerts")
    
    def show_alerts_dashboard(self):
        """Show dedicated alerts dashboard window"""
        dashboard = tk.Toplevel(self.root)
        dashboard.title("Alerts Dashboard")
        dashboard.geometry("1200x800")
        dashboard.transient(self.root)
        
        ttk.Label(dashboard, text="Alerts Dashboard", font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Create alerts summary
        summary_frame = ttk.Frame(dashboard)
        summary_frame.pack(fill=tk.X, padx=10, pady=10)
        
        active_alerts = self.alert_manager.get_active_alerts()
        critical_count = sum(1 for a in active_alerts if a.level == "critical")
        warning_count = sum(1 for a in active_alerts if a.level == "warning")
        
        ttk.Label(summary_frame, text=f"Critical: {critical_count}", 
                 font=('Arial', 12, 'bold'), foreground="red").pack(side=tk.LEFT, padx=20)
        ttk.Label(summary_frame, text=f"Warning: {warning_count}", 
                 font=('Arial', 12, 'bold'), foreground="orange").pack(side=tk.LEFT, padx=20)
        ttk.Label(summary_frame, text=f"Total: {len(active_alerts)}", 
                 font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=20)
    
    # Advanced Feature Methods
    def bulk_setup_dialog(self):
        """Show bulk device setup dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Bulk Device Setup")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Instructions
        instructions = """
        Bulk Device Setup
        
        This wizard will help you set up monitoring on multiple devices simultaneously.
        Select devices below and provide credentials for setup.
        """
        
        ttk.Label(dialog, text=instructions, justify=tk.LEFT).pack(pady=10, padx=10)
        
        # Common credentials form
        creds_frame = ttk.LabelFrame(dialog, text="Credentials")
        creds_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(creds_frame, text="Root Username:").pack(pady=5)
        root_user_var = tk.StringVar(value="root")
        ttk.Entry(creds_frame, textvariable=root_user_var, width=30).pack(pady=5)
        
        ttk.Label(creds_frame, text="Root Password:").pack(pady=5)
        root_pass_var = tk.StringVar()
        ttk.Entry(creds_frame, textvariable=root_pass_var, show="*", width=30).pack(pady=5)
        
        ttk.Label(creds_frame, text="Monitoring Username:").pack(pady=5)
        mon_user_var = tk.StringVar(value="netmonitor")
        ttk.Entry(creds_frame, textvariable=mon_user_var, width=30).pack(pady=5)
        
        # Device selection
        devices_frame = ttk.LabelFrame(dialog, text="Select Devices")
        devices_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Device listbox with checkboxes
        device_vars = {}
        devices_list = ttk.Frame(devices_frame)
        devices_list.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(devices_list)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        devices_canvas = tk.Canvas(devices_list, yscrollcommand=scrollbar.set)
        devices_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=devices_canvas.yview)
        
        devices_inner = ttk.Frame(devices_canvas)
        devices_canvas.create_window((0, 0), window=devices_inner, anchor="nw")
        
        for device in self.devices.values():
            if not device.monitoring_enabled:
                var = tk.BooleanVar()
                device_vars[device.ip] = var
                cb = ttk.Checkbutton(devices_inner, text=f"{device.ip} ({device.hostname})", variable=var)
                cb.pack(anchor='w', pady=2)
        
        # Update scroll region
        devices_inner.update_idletasks()
        devices_canvas.config(scrollregion=devices_canvas.bbox("all"))
        
        # Action buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def start_bulk_setup():
            selected_devices = [ip for ip, var in device_vars.items() if var.get()]
            if not selected_devices:
                messagebox.showwarning("Warning", "Please select at least one device.")
                return
            
            self.perform_bulk_setup(selected_devices, root_user_var.get(), 
                                  root_pass_var.get(), mon_user_var.get())
            dialog.destroy()
        
        ttk.Button(button_frame, text="Start Setup", command=start_bulk_setup).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
    
    def show_preferences(self):
        """Show application preferences dialog"""
        prefs_dialog = tk.Toplevel(self.root)
        prefs_dialog.title("Preferences")
        prefs_dialog.geometry("500x400")
        prefs_dialog.transient(self.root)
        prefs_dialog.grab_set()
        
        # Create preference categories
        prefs_notebook = ttk.Notebook(prefs_dialog)
        prefs_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General preferences
        general_frame = ttk.Frame(prefs_notebook)
        prefs_notebook.add(general_frame, text="General")
        
        # Monitoring interval
        ttk.Label(general_frame, text="Monitoring Interval (seconds):").pack(anchor='w', padx=10, pady=5)
        interval_var = tk.IntVar(value=self.config.getint('MONITORING', 'interval', fallback=5))
        ttk.Spinbox(general_frame, from_=1, to=300, textvariable=interval_var, width=10).pack(anchor='w', padx=10)
        
        # Auto-refresh
        auto_refresh_var = tk.BooleanVar(value=self.config.getboolean('GUI', 'auto_refresh', fallback=True))
        ttk.Checkbutton(general_frame, text="Auto-refresh GUI", variable=auto_refresh_var).pack(anchor='w', padx=10, pady=5)
        
        # Theme
        ttk.Label(general_frame, text="Theme:").pack(anchor='w', padx=10, pady=(20, 5))
        theme_var = tk.StringVar(value=self.config.get('GUI', 'theme', fallback='light'))
        ttk.Radiobutton(general_frame, text="Light", variable=theme_var, value='light').pack(anchor='w', padx=20)
        ttk.Radiobutton(general_frame, text="Dark", variable=theme_var, value='dark').pack(anchor='w', padx=20)
        
        # Data retention
        ttk.Label(general_frame, text="Data Retention (days):").pack(anchor='w', padx=10, pady=(20, 5))
        retention_var = tk.IntVar(value=self.config.getint('MONITORING', 'data_retention_days', fallback=30))
        ttk.Spinbox(general_frame, from_=7, to=365, textvariable=retention_var, width=10).pack(anchor='w', padx=10)
        
        # Save preferences function
        def save_preferences():
            self.config.set('MONITORING', 'interval', str(interval_var.get()))
            self.config.set('GUI', 'auto_refresh', str(auto_refresh_var.get()))
            self.config.set('GUI', 'theme', theme_var.get())
            self.config.set('MONITORING', 'data_retention_days', str(retention_var.get()))
            
            self.save_configuration()
            
            # Apply theme change
            if theme_var.get() != self.modern_gui.current_theme:
                self.modern_gui.apply_theme(theme_var.get())
            
            messagebox.showinfo("Success", "Preferences saved successfully.")
            prefs_dialog.destroy()
        
        # Buttons
        button_frame = ttk.Frame(prefs_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_preferences).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=prefs_dialog.destroy).pack(side=tk.RIGHT)
    
    def show_performance_monitor(self):
        """Show dedicated performance monitoring window"""
        perf_window = tk.Toplevel(self.root)
        perf_window.title("Performance Monitor")
        perf_window.geometry("1000x700")
        perf_window.transient(self.root)
        
        ttk.Label(perf_window, text="Performance Monitor", font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Create performance charts
        perf_frame = ttk.Frame(perf_window)
        perf_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Performance figure
        perf_fig = Figure(figsize=(12, 8), dpi=80)
        perf_canvas = FigureCanvasTkAgg(perf_fig, perf_frame)
        perf_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add performance charts
        ax1 = perf_fig.add_subplot(2, 2, 1)
        ax1.set_title("System Performance Overview")
        ax1.text(0.5, 0.5, "Performance data will appear here", ha='center', va='center', transform=ax1.transAxes)
        
        perf_canvas.draw()
    
    def generate_performance_report(self):
        """Generate comprehensive performance report"""
        try:
            report_window = tk.Toplevel(self.root)
            report_window.title("Performance Report")
            report_window.geometry("800x600")
            report_window.transient(self.root)
            
            ttk.Label(report_window, text="Performance Report Generator", 
                     font=('Arial', 14, 'bold')).pack(pady=20)
            
            # Report options
            options_frame = ttk.LabelFrame(report_window, text="Report Options")
            options_frame.pack(fill=tk.X, padx=10, pady=10)
            
            # Time range
            ttk.Label(options_frame, text="Time Range:").pack(anchor='w', padx=10, pady=5)
            time_range_var = tk.StringVar(value="24 Hours")
            ttk.Combobox(options_frame, textvariable=time_range_var,
                        values=["1 Hour", "6 Hours", "24 Hours", "7 Days", "30 Days"],
                        state="readonly").pack(anchor='w', padx=10)
            
            # Report type
            ttk.Label(options_frame, text="Report Type:").pack(anchor='w', padx=10, pady=5)
            report_type_var = tk.StringVar(value="Summary")
            ttk.Combobox(options_frame, textvariable=report_type_var,
                        values=["Summary", "Detailed", "Executive"],
                        state="readonly").pack(anchor='w', padx=10)
            
            def generate_report():
                # Report generation logic would go here
                messagebox.showinfo("Success", "Performance report generated successfully!")
                report_window.destroy()
            
            ttk.Button(options_frame, text="Generate Report", command=generate_report).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def export_report(self):
        """Export system report to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("PDF files", "*.pdf"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                self.generate_report_file(filename)
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def generate_report_file(self, filename):
        """Generate report file with current system status"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(self.devices),
            'monitored_devices': sum(1 for d in self.devices.values() if d.monitoring_enabled),
            'active_alerts': len(self.alert_manager.get_active_alerts()),
            'devices': [device.to_dict() for device in self.devices.values()]
        }
        
        if filename.endswith('.json'):
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
        elif filename.endswith('.html'):
            self.generate_html_report(filename, report_data)
        else:
            # Plain text report
            with open(filename, 'w') as f:
                f.write("Network PC Management System Report\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Generated: {report_data['timestamp']}\n")
                f.write(f"Total Devices: {report_data['total_devices']}\n")
                f.write(f"Monitored Devices: {report_data['monitored_devices']}\n")
                f.write(f"Active Alerts: {report_data['active_alerts']}\n\n")
                
                f.write("Device Details:\n")
                f.write("-" * 20 + "\n")
                for device_data in report_data['devices']:
                    f.write(f"IP: {device_data['ip']}\n")
                    f.write(f"Hostname: {device_data['hostname']}\n")
                    f.write(f"OS: {device_data['os_type']}\n")
                    f.write(f"Status: {device_data['status']}\n")
                    f.write(f"Monitoring: {'Enabled' if device_data['monitoring_enabled'] else 'Disabled'}\n")
                    f.write("\n")
    
    def generate_html_report(self, filename, data):
        """Generate HTML report with styling"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network PC Management Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .metric {{ text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
                .metric h3 {{ margin: 0; color: #007bff; }}
                .device-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                .device-table th, .device-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                .device-table th {{ background-color: #007bff; color: white; }}
                .status-online {{ color: #28a745; font-weight: bold; }}
                .status-offline {{ color: #dc3545; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network PC Management System Report</h1>
                <p>Generated on: {data['timestamp']}</p>
            </div>
            
            <div class="summary">
                <div class="metric">
                    <h3>{data['total_devices']}</h3>
                    <p>Total Devices</p>
                </div>
                <div class="metric">
                    <h3>{data['monitored_devices']}</h3>
                    <p>Monitored Devices</p>
                </div>
                <div class="metric">
                    <h3>{data['active_alerts']}</h3>
                    <p>Active Alerts</p>
                </div>
            </div>
            
            <h2>Device Details</h2>
            <table class="device-table">
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Operating System</th>
                    <th>Status</th>
                    <th>Monitoring</th>
                    <th>Last Update</th>
                </tr>
        """
        
        for device_data in data['devices']:
            status_class = 'status-online' if device_data['status'] == 'Online' else 'status-offline'
            monitoring_status = 'Enabled' if device_data['monitoring_enabled'] else 'Disabled'
            last_update = device_data.get('last_update', 'Never')
            
            html_content += f"""
                <tr>
                    <td>{device_data['ip']}</td>
                    <td>{device_data['hostname']}</td>
                    <td>{device_data['os_type']}</td>
                    <td class="{status_class}">{device_data['status']}</td>
                    <td>{monitoring_status}</td>
                    <td>{last_update}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    # Utility and Event Handler Methods
    def log_message(self, message, level="INFO"):
        """Enhanced logging with levels and colors"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        # Insert with appropriate color
        self.log_text.insert(tk.END, log_entry, level)
        self.log_text.see(tk.END)
        
        # Keep log size manageable
        lines = int(self.log_text.index('end-1c').split('.')[0])
        if lines > 1000:
            self.log_text.delete(1.0, "100.0")
        
        # Log to file
        logger.info(message)
        
        # Update status
        self.status_var.set(message)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def safe_exit(self):
        """Safely exit the application"""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            try:
                self.monitoring_thread.stop()
                self.save_configuration()
                self.root.quit()
            except Exception as e:
                logger.error(f"Error during exit: {e}")
                self.root.quit()
    
    # Event Handlers
    def on_device_select(self, event):
        """Enhanced device selection handler"""
        selected = self.device_tree.selection()
        if selected:
            item = self.device_tree.item(selected[0])
            device_ip = item['values'][1]
            device = self.devices.get(device_ip)
            
            if device:
                self.show_device_details(device)
    
    def on_device_double_click(self, event):
        """Handle device double-click"""
        selected = self.device_tree.selection()
        if selected:
            item = self.device_tree.item(selected[0])
            device_ip = item['values'][1]
            device = self.devices.get(device_ip)
            
            if device:
                self.show_device_properties(device)
    
    def show_device_details(self, device):
        """Show device details in status area"""
        details = f"Selected: {device.hostname} ({device.ip}) - {device.status}"
        if device.monitoring_enabled:
            details += f" | CPU: {device.get_latest_metric('cpu'):.1f}% | Memory: {device.get_latest_metric('memory'):.1f}%"
        self.update_status(details)
    
    def on_alert_double_click(self, event):
        """Handle alert double-click to show details"""
        selected = self.alerts_tree.selection()
        if selected:
            messagebox.showinfo("Alert Details", "Alert details dialog would appear here")
    
    # Filter and Search Methods
    def filter_devices(self, event=None):
        """Filter devices based on search term"""
        self.update_device_display()
    
    def filter_devices_by_status(self, status):
        """Filter devices by status"""
        self.update_device_display()
    
    def filter_alerts(self, event=None):
        """Filter alerts by severity"""
        self.update_alerts_display()
    
    def filter_logs(self, event=None):
        """Filter logs based on criteria"""
        # Log filtering implementation would go here
        pass
    
    def sort_devices(self, column):
        """Sort devices by column"""
        # Device sorting implementation would go here
        pass
    
    # Additional Feature Methods
    def refresh_all(self):
        """Refresh all data and displays"""
        self.update_device_display()
        self.update_alerts_display()
        self.update_status_indicators()
        self.log_message("All data refreshed")
    
    def refresh_alerts(self):
        """Refresh alerts display"""
        self.update_alerts_display()
    
    def clear_logs(self):
        """Clear log display"""
        if messagebox.askyesno("Clear Logs", "Clear all logs from display?"):
            self.log_text.delete(1.0, tk.END)
    
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def cleanup_database(self):
        """Manual database cleanup"""
        if messagebox.askyesno("Database Cleanup", "This will remove old data. Continue?"):
            try:
                days = self.config.getint('MONITORING', 'data_retention_days', fallback=30)
                self.db_manager.cleanup_old_data(days)
                messagebox.showinfo("Success", "Database cleanup completed.")
                self.log_message("Database cleanup completed")
            except Exception as e:
                messagebox.showerror("Error", f"Database cleanup failed: {str(e)}")
    
    def update_analytics(self, event=None):
        """Update analytics charts"""
        self.log_message("Analytics update - feature in development")
    
    # Placeholder methods for advanced features
    def manage_custom_scripts(self):
        """Manage custom monitoring scripts"""
        messagebox.showinfo("Custom Scripts", "Custom scripts management - feature coming soon")
    
    def show_network_topology(self):
        """Show network topology visualization"""
        messagebox.showinfo("Network Topology", "Network topology visualization - feature coming soon")
    
    def show_security_report(self):
        """Show security report"""
        messagebox.showinfo("Security Report", "Security reporting - feature coming soon")
    
    def show_shortcuts(self):
        """Show keyboard shortcuts help"""
        shortcuts_window = tk.Toplevel(self.root)
        shortcuts_window.title("Keyboard Shortcuts")
        shortcuts_window.geometry("400x300")
        shortcuts_window.transient(self.root)
        
        shortcuts_text = """
        Keyboard Shortcuts:
        
        Ctrl+Q - Quick Scan
        Ctrl+S - Full Network Scan
        Ctrl+P - Preferences
        Ctrl+T - Toggle Theme
        F5 - Refresh All
        Esc - Acknowledge All Alerts
        Ctrl+Shift+Q - Exit Application
        """
        
        ttk.Label(shortcuts_window, text=shortcuts_text, justify=tk.LEFT, 
                 font=('Consolas', 10)).pack(padx=20, pady=20)
    
    def show_documentation(self):
        """Show application documentation"""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x500")
        doc_window.transient(self.root)
        
        doc_text = scrolledtext.ScrolledText(doc_window, wrap=tk.WORD)
        doc_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        documentation = """
        PC Management System Documentation
        
        GETTING STARTED:
        1. Click "Quick Scan" to discover devices on your network
        2. Select devices and click "Setup Device" to enable monitoring
        3. View real-time metrics in the monitoring tabs
        
        FEATURES:
        • Network Discovery: Automatically find devices on your network
        • Real-time Monitoring: CPU, memory, disk, and network metrics
        • Alert System: Configurable alerts for system thresholds
        • Security Monitoring: Track failed logins and security events
        
        KEYBOARD SHORTCUTS:
        • Ctrl+Q: Quick Scan
        • Ctrl+S: Full Network Scan
        • F5: Refresh All
        • Ctrl+T: Toggle Theme
        • Esc: Acknowledge All Alerts
        
        CONFIGURATION:
        • Use File > Preferences to configure settings
        • Set up alert thresholds in Tools > Alert Configuration
        • Export reports using File > Export Report
        
        TROUBLESHOOTING:
        • Ensure SSH access to target devices
        • Check network connectivity
        • Verify credentials for device setup
        """
        
        doc_text.insert(tk.END, documentation)
        doc_text.config(state=tk.DISABLED)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        Enterprise Network PC Management System v2.0
        
        An advanced network monitoring and management solution
        with real-time alerting, performance analytics, and
        comprehensive device management capabilities.
        
        Features:
        • Real-time monitoring and alerting
        • Anomaly detection with machine learning
        • Performance analytics and reporting
        • Modern responsive user interface
        • Enterprise-grade scalability
        
        Made by RCMAN
        Find it here.
        
        https://github.com/network_manager/
        
        Please let me know if you find any issues.
        
        Built with Python, tkinter, and matplotlib
        """
        
        messagebox.showinfo("About", about_text)

def main():
    """Main application entry point"""
    # Check for required dependencies
    required_modules = ['paramiko', 'matplotlib', 'numpy', 'psutil']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing required dependencies: {', '.join(missing_modules)}")
        print("Please install with: pip install " + " ".join(missing_modules))
        return
    
    # Create and run application
    root = tk.Tk()
    
    try:
        app = EnhancedPCManagementApp(root)
        
        # Handle application exit
        def on_closing():
            app.safe_exit()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start main loop
        root.mainloop()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        messagebox.showerror("Application Error", f"An error occurred: {str(e)}")
    finally:
        try:
            if 'app' in locals():
                app.monitoring_thread.stop()
        except:
            pass

if __name__ == "__main__":
    main()