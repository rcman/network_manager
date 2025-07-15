#!/usr/bin/env python3
"""
Enhanced Network PC Management Application
Enterprise-grade tool with advanced monitoring, alerting, and modern UI
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, Toplevel, simpledialog
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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable
import configparser
from collections import deque
import statistics
import platform # Added for platform-specific commands

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

# --- NetworkScanner Class ---
class NetworkScanner:
    """Scans the network to discover devices."""
    def __init__(self, log_callback: Callable):
        self.log_callback = log_callback

    def ping_host(self, ip: str) -> bool:
        """Pings a single host to check if it's online. Returns True if online, False otherwise."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', ip]
            startupinfo = None
            if platform.system().lower() == 'windows':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            response = subprocess.run(command, capture_output=True, text=True, timeout=2, startupinfo=startupinfo)
            return response.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def get_hostname(self, ip: str) -> str:
        """Tries to resolve the hostname for a given IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"

    def scan_network(self, network_range: str) -> List['NetworkDevice']:
        """Scans a network range (CIDR notation) and returns a list of found devices."""
        found_devices = []
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            ips_to_scan = [str(ip) for ip in network.hosts()]
            self.log_callback(f"Scanning {len(ips_to_scan)} IPs in {network_range}...")

            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in ips_to_scan}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            hostname = self.get_hostname(ip)
                            device = NetworkDevice(ip=ip, hostname=hostname, status="Online")
                            found_devices.append(device)
                            self.log_message(f"Found device: {ip} ({hostname})", "INFO")
                    except Exception as e:
                        logger.error(f"Error processing scan result for {ip}: {e}")

        except ValueError:
            self.log_callback(f"Invalid network range: {network_range}", "ERROR")
            messagebox.showerror("Error", f"Invalid network range: {network_range}. Please use CIDR notation (e.g., 192.168.1.0/24).")
        except Exception as e:
            logger.error(f"Network scan failed: {e}")

        return found_devices

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

class AnomalyDetector:
    """ML-based anomaly detection for metrics"""

    def __init__(self):
        self.baselines = {}
        self.history_window = 100

    def update_baseline(self, device_ip, metric, value):
        key = f"{device_ip}_{metric}"
        if key not in self.baselines:
            self.baselines[key] = deque(maxlen=self.history_window)
        self.baselines[key].append(value)

    def detect_anomaly(self, device_ip, metric, value):
        key = f"{device_ip}_{metric}"
        if key not in self.baselines or len(self.baselines[key]) < 20:
            return False
        data = list(self.baselines[key])
        mean = statistics.mean(data)
        std_dev = statistics.stdev(data) if len(data) > 1 else 0
        if std_dev > 0:
            z_score = abs(value - mean) / std_dev
            return z_score > 2.5
        return False

class AlertManager:
    """Advanced alerting system with escalation"""
    def __init__(self, app):
        self.app = app
        self.alerts = {}
        self.thresholds = {
            'cpu': AlertThreshold('cpu', 80.0, 95.0, 300),
            'memory': AlertThreshold('memory', 85.0, 95.0, 300),
            'disk': AlertThreshold('disk', 90.0, 98.0, 600)
        }
        self.anomaly_detector = AnomalyDetector()
        self.notification_queue = queue.Queue()
        self.notification_thread = threading.Thread(target=self._process_notifications, daemon=True)
        self.notification_thread.start()

    def check_metric(self, device_ip, metric, value):
        if metric not in self.thresholds or not self.thresholds[metric].enabled:
            return

        self.anomaly_detector.update_baseline(device_ip, metric, value)
        if self.anomaly_detector.detect_anomaly(device_ip, metric, value):
            self._create_alert(device_ip, metric, value, "anomaly", "Anomalous Behavior")

        threshold = self.thresholds[metric]
        alert_key = f"{device_ip}_{metric}"
        
        level = None
        if value >= threshold.critical_level:
            level = "critical"
        elif value >= threshold.warning_level:
            level = "warning"

        existing_alert = next((a for a in self.get_active_alerts() if a.device_ip == device_ip and a.metric == metric), None)

        if level:
            if not existing_alert or existing_alert.level != level:
                self._create_alert(device_ip, metric, value, level, threshold.critical_level if level == "critical" else threshold.warning_level)
        elif existing_alert:
            self.resolve_alert(existing_alert.id)

    def _create_alert(self, device_ip, metric, value, level, threshold_val):
        alert_id = f"{device_ip}_{metric}_{int(time.time())}"
        alert = Alert(
            id=alert_id, device_ip=device_ip, metric=metric,
            level=level, value=value, threshold=threshold_val, timestamp=datetime.now()
        )
        self.alerts[alert_id] = alert
        self._send_notification("new", alert)
        self.app.root.after(0, self.app.update_alerts_display)

    def resolve_alert(self, alert_id):
        if alert_id in self.alerts and not self.alerts[alert_id].resolved:
            self.alerts[alert_id].resolved = True
            self._send_notification("resolved", self.alerts[alert_id])
            self.app.root.after(0, self.app.update_alerts_display)

    def _send_notification(self, action, alert):
        self.notification_queue.put((action, alert))

    def _process_notifications(self):
        while True:
            try:
                action, alert = self.notification_queue.get(timeout=1)
                logger.warning(f"Alert {action}: {alert.device_ip} - {alert.metric} = {alert.value} ({alert.level})")
                # self._send_email_notification(action, alert) # Placeholder for real implementation
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Notification processing error: {e}")

    def acknowledge_alert(self, alert_id):
        if alert_id in self.alerts:
            self.alerts[alert_id].acknowledged = True
            self.app.root.after(0, self.app.update_alerts_display)

    def get_active_alerts(self):
        return [alert for alert in self.alerts.values() if not alert.resolved]

@dataclass
class NetworkDevice:
    ip: str
    hostname: str = "Unknown"
    os_type: str = "Unknown"
    status: str = "Unknown"
    monitoring_enabled: bool = False
    ssh_client: Optional[paramiko.SSHClient] = None
    last_update: Optional[datetime] = None
    credentials: Optional[Dict[str, str]] = None

    def __post_init__(self):
        self.metrics_history = {
            'cpu': deque(maxlen=300),
            'memory': deque(maxlen=300),
            'disk': deque(maxlen=300),
            'network_in': deque(maxlen=300),
            'network_out': deque(maxlen=300),
        }
        self.timestamps = deque(maxlen=300)
    
    def add_metric(self, metric_type, value):
        self.metrics_history[metric_type].append(value)
        if metric_type == 'cpu':
            self.timestamps.append(datetime.now())

    def get_latest_metric(self, metric_type):
        return self.metrics_history[metric_type][-1] if self.metrics_history[metric_type] else 0

class EnhancedDatabaseManager:
    def __init__(self, db_path="network_monitor.db"):
        self.db_path = db_path
        self.connection_pool = queue.Queue(maxsize=10)
        self._create_connection_pool()
        self.init_database()

    def _create_connection_pool(self):
        for _ in range(self.connection_pool.maxsize):
            try:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
                self.connection_pool.put(conn)
            except Exception as e:
                logger.error(f"Failed to create DB connection: {e}")

    def get_connection(self):
        return self.connection_pool.get(timeout=5)

    def return_connection(self, conn):
        self.connection_pool.put(conn)

    def init_database(self):
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY, hostname TEXT, os_type TEXT, status TEXT,
                    monitoring_enabled BOOLEAN, last_seen TIMESTAMP, credentials TEXT
                )''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, timestamp TIMESTAMP,
                    cpu_percent REAL, memory_percent REAL, disk_percent REAL,
                    network_bytes_sent INTEGER, network_bytes_recv INTEGER,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip) ON DELETE CASCADE
                )''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_device_time ON metrics(device_ip, timestamp)')
            conn.commit()
        finally:
            self.return_connection(conn)

    def save_device(self, device: NetworkDevice):
        conn = self.get_connection()
        try:
            creds_json = json.dumps(device.credentials) if device.credentials else None
            with conn:
                conn.execute('''
                    INSERT INTO devices (ip, hostname, os_type, status, monitoring_enabled, last_seen, credentials)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        hostname=excluded.hostname, os_type=excluded.os_type, status=excluded.status,
                        monitoring_enabled=excluded.monitoring_enabled, last_seen=excluded.last_seen,
                        credentials=excluded.credentials
                ''', (device.ip, device.hostname, device.os_type, device.status,
                      device.monitoring_enabled, datetime.now(), creds_json))
        except Exception as e:
            logger.error(f"Database error saving device {device.ip}: {e}")
        finally:
            self.return_connection(conn)

    def save_metrics_batch(self, metrics_batch):
        if not metrics_batch: return
        conn = self.get_connection()
        try:
            with conn:
                conn.executemany('INSERT INTO metrics (device_ip, timestamp, cpu_percent, memory_percent, disk_percent, network_bytes_sent, network_bytes_recv) VALUES (?, ?, ?, ?, ?, ?, ?)', metrics_batch)
        except Exception as e:
            logger.error(f"Database batch insert error: {e}")
        finally:
            self.return_connection(conn)

    def cleanup_old_data(self, days_to_keep=30):
        conn = self.get_connection()
        try:
            with conn:
                cutoff_date = datetime.now() - timedelta(days=days_to_keep)
                conn.execute('DELETE FROM metrics WHERE timestamp < ?', (cutoff_date,))
                conn.execute('VACUUM')
        except Exception as e:
            logger.error(f"Database cleanup error: {e}")
        finally:
            self.return_connection(conn)

class EnhancedSSHManager:
    def connect_to_device(self, device: NetworkDevice, username: str, password: Optional[str] = None, pkey: Optional[paramiko.PKey] = None):
        if device.ssh_client and device.ssh_client.get_transport() and device.ssh_client.get_transport().is_active():
            return
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=device.ip, username=username, password=password, pkey=pkey, timeout=10, look_for_keys=False)
            device.ssh_client = client
            device.credentials = {'username': username, 'password': password} # Store for reconnects
            logger.info(f"SSH connection established to {device.ip}")
        except Exception as e:
            logger.error(f"SSH connection failed for {device.ip}: {e}")
            device.ssh_client = None
            raise e

    def execute_command(self, device: NetworkDevice, command: str, timeout: int = 15) -> str:
        if not device.ssh_client or not device.ssh_client.get_transport() or not device.ssh_client.get_transport().is_active():
            raise ConnectionError(f"No active SSH connection to {device.ip}")
        try:
            _, stdout, stderr = device.ssh_client.exec_command(command, timeout=timeout)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            if exit_status != 0:
                logger.warning(f"Command on {device.ip} exited with status {exit_status}. Error: {error}")
            return output
        except Exception as e:
            logger.error(f"Failed to execute command on {device.ip}: {e}")
            device.ssh_client.close()
            device.ssh_client = None
            raise e

    def get_enhanced_metrics(self, device: NetworkDevice):
        try:
            metrics = {}
            # Combined command for efficiency, compatible with most Linux systems
            full_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}' && free | awk '/Mem:/ {printf \"%.1f\", $3/$2 * 100.0}' && df -h / | awk 'NR==2{print $5}' | sed 's/%//'"
            output = self.execute_command(device, full_cmd)
            lines = [line.strip() for line in output.split('\n')]
            
            metrics['cpu'] = float(lines[0]) if len(lines) > 0 and lines[0] else 0.0
            metrics['memory'] = float(lines[1]) if len(lines) > 1 and lines[1] else 0.0
            metrics['disk'] = float(lines[2]) if len(lines) > 2 and lines[2] else 0.0
            # Simplified network metrics; real-world usage would compare over time
            metrics['network_in'] = 0
            metrics['network_out'] = 0
            metrics['timestamp'] = datetime.now()
            return metrics
        except Exception as e:
            logger.error(f"Failed to get enhanced metrics for {device.ip}: {e}")
            device.status = "Connection Lost"
            return None

    def create_monitoring_account(self, device: NetworkDevice, root_user: str, root_pass: str, new_user: str):
        try:
            root_client = paramiko.SSHClient()
            root_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            root_client.connect(device.ip, username=root_user, password=root_pass, timeout=10)
            
            new_pass = hashlib.sha256(os.urandom(60)).hexdigest()[:16]
            setup_commands = [
                f"useradd -m -s /bin/bash {new_user} || echo 'User likely exists'",
                f"echo '{new_user}:{new_pass}' | chpasswd"
            ]
            for cmd in setup_commands:
                _, _, stderr = root_client.exec_command(cmd)
                error = stderr.read().decode()
                if error and "already exists" not in error:
                    logger.warning(f"Setup command '{cmd}' on {device.ip} produced stderr: {error}")
            
            root_client.close()
            logger.info(f"Successfully created/set password for monitoring user '{new_user}' on {device.ip}")
            return new_user, new_pass
        except Exception as e:
            logger.error(f"Failed to create monitoring account on {device.ip}: {e}")
            raise e

class ModernGUI:
    def __init__(self, root, app):
        self.root = root
        self.app = app
        self.current_theme = "light"
        self.setup_styles()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.themes = {
            "light": {"bg": "#f8f9fa", "fg": "#212529", "select_bg": "#0078d4", "select_fg": "#ffffff", "accent": "#0078d4", "entry_bg": "#ffffff", "tree_bg": "#ffffff", "tree_fg": "#212529"},
            "dark": {"bg": "#212529", "fg": "#f8f9fa", "select_bg": "#0078d4", "select_fg": "#ffffff", "accent": "#00bcf2", "entry_bg": "#343a40", "tree_bg": "#343a40", "tree_fg": "#f8f9fa"}
        }
        self.apply_theme(self.app.config.get('GUI', 'theme', fallback='light'))

    def apply_theme(self, theme_name):
        if theme_name not in self.themes: return
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        self.root.configure(bg=theme["bg"])
        self.style.configure(".", background=theme["bg"], foreground=theme["fg"], fieldbackground=theme["entry_bg"])
        self.style.configure("TFrame", background=theme["bg"])
        self.style.configure("TLabel", background=theme["bg"], foreground=theme["fg"])
        self.style.configure("TButton", background=theme["accent"], foreground=theme["select_fg"], borderwidth=0, padding=5)
        self.style.map("TButton", background=[('active', theme["select_bg"])])
        self.style.configure("TNotebook", background=theme["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=theme["bg"], foreground=theme["fg"], padding=[10, 5])
        self.style.map("TNotebook.Tab", background=[("selected", theme["accent"])], foreground=[("selected", theme["select_fg"])])
        self.style.configure("Treeview", background=theme["tree_bg"], foreground=theme["tree_fg"], fieldbackground=theme["tree_bg"])
        self.style.map("Treeview", background=[('selected', theme["select_bg"])], foreground=[('selected', theme["select_fg"])])
        self.style.configure("TScrollbar", troughcolor=theme["bg"], background=theme["accent"])

    def toggle_theme(self):
        new_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme(new_theme)
        self.app.config.set('GUI', 'theme', new_theme)
        self.app.save_configuration()

class EnhancedMonitoringThread:
    def __init__(self, app):
        self.app = app
        self.running = False
        self.thread = None
        self.metrics_batch = []
        self.batch_lock = threading.Lock()
        self.monitoring_interval = 5

    def start(self):
        if not self.running:
            self.running = True
            self.monitoring_interval = self.app.config.getint('MONITORING', 'interval', fallback=5)
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            self.db_thread = threading.Thread(target=self._batch_db_writer, daemon=True)
            self.db_thread.start()

    def stop(self):
        self.running = False
        if self.thread: self.thread.join(timeout=2)
        if self.db_thread: self.db_thread.join(timeout=2)
        self._save_batch()

    def _monitor_loop(self):
        while self.running:
            try:
                enabled_devices = [d for d in self.app.devices.values() if d.monitoring_enabled]
                if enabled_devices:
                    with ThreadPoolExecutor(max_workers=min(10, len(enabled_devices) or 1)) as executor:
                        list(executor.map(self._monitor_device, enabled_devices))
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)

    def _monitor_device(self, device: NetworkDevice):
        try:
            metrics = self.app.ssh_manager.get_enhanced_metrics(device)
            if not metrics:
                self.app.root.after(0, self.app.update_device_display)
                return

            device.add_metric('cpu', metrics['cpu'])
            device.add_metric('memory', metrics['memory'])
            device.add_metric('disk', metrics['disk'])
            device.last_update = datetime.now()
            device.status = "Online"

            self.app.alert_manager.check_metric(device.ip, 'cpu', metrics['cpu'])
            self.app.alert_manager.check_metric(device.ip, 'memory', metrics['memory'])
            self.app.alert_manager.check_metric(device.ip, 'disk', metrics['disk'])

            batch_entry = (
                device.ip, metrics['timestamp'], metrics['cpu'], metrics['memory'],
                metrics['disk'], metrics['network_in'], metrics['network_out']
            )
            with self.batch_lock:
                self.metrics_batch.append(batch_entry)
            
            self.app.root.after(0, self.app.update_device_display)
        except Exception as e:
            if isinstance(e, paramiko.AuthenticationException):
                self.app.log_message(f"Authentication failed for {device.ip}. Stopping monitoring.", "ERROR")
                device.monitoring_enabled = False
            else:
                logger.error(f"Device monitoring error for {device.ip}: {e}")
            device.status = "Monitor Error"
            self.app.root.after(0, self.app.update_device_display)

    def _batch_db_writer(self):
        while self.running:
            time.sleep(30)
            self._save_batch()

    def _save_batch(self):
        with self.batch_lock:
            if not self.metrics_batch: return
            batch_to_save = self.metrics_batch.copy()
            self.metrics_batch.clear()
        try:
            self.app.db_manager.save_metrics_batch(batch_to_save)
            logger.info(f"Saved {len(batch_to_save)} metrics to database.")
        except Exception as e:
            logger.error(f"Failed to save metrics batch to DB: {e}")
            with self.batch_lock: self.metrics_batch.extend(batch_to_save)


class EnhancedPCManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Network PC Management System v2.0")
        self.root.geometry("1600x1000")
        
        self.devices: Dict[str, NetworkDevice] = {}
        self.db_manager = EnhancedDatabaseManager()
        self.config = configparser.ConfigParser()
        self.load_configuration()
        
        self.ssh_manager = EnhancedSSHManager()
        self.scanner = NetworkScanner(self.log_message)
        self.alert_manager = AlertManager(self)
        self.monitoring_thread = EnhancedMonitoringThread(self)
        self.modern_gui = ModernGUI(root, self)

        self.sort_column = 'IP'
        self.sort_reverse = False

        self.setup_enhanced_gui()
        self.load_devices_from_db()
        self.monitoring_thread.start()
        self.schedule_cleanup_tasks()
        self.root.protocol("WM_DELETE_WINDOW", self.safe_exit)

    def load_devices_from_db(self):
        conn = self.db_manager.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, hostname, os_type, status, monitoring_enabled, credentials FROM devices")
            for row in cursor.fetchall():
                ip, hostname, os_type, status, monitoring_enabled, creds_json = row
                device = NetworkDevice(ip, hostname, os_type, status)
                device.monitoring_enabled = bool(monitoring_enabled)
                if creds_json:
                    device.credentials = json.loads(creds_json)
                self.devices[ip] = device
            self.log_message(f"Loaded {len(self.devices)} devices from database.")
        except Exception as e:
            logger.error(f"Failed to load devices from DB: {e}")
        finally:
            self.db_manager.return_connection(conn)
        self.update_device_display()

    def load_configuration(self):
        if not os.path.exists('config.ini'):
            self.create_default_config()
        self.config.read('config.ini')

    def create_default_config(self):
        self.config['MONITORING'] = {'interval': '15', 'data_retention_days': '30'}
        self.config['GUI'] = {'theme': 'light'}
        self.save_configuration()

    def save_configuration(self):
        try:
            with open('config.ini', 'w') as f:
                self.config.write(f)
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    # --- GUI SETUP ---
    def setup_enhanced_gui(self):
        self.create_enhanced_menu()
        self.create_enhanced_toolbar()
        self.create_enhanced_main_panels()
        self.create_enhanced_status_bar()
        self.setup_keyboard_shortcuts()
        self.auto_refresh_timer()

    def create_enhanced_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Quick Scan", command=self.quick_scan)
        file_menu.add_command(label="Full Network Scan", command=self.scan_network)
        file_menu.add_separator()
        file_menu.add_command(label="Preferences", command=self.show_preferences)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.safe_exit)
        # ... other menus ...

    def create_enhanced_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="🔍 Scan", command=self.scan_network).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=2)

        self.network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(toolbar, textvariable=self.network_var, width=18).pack(side=tk.LEFT, padx=(10,2))
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=20, fill=tk.X, expand=True)
        search_entry.bind('<KeyRelease>', self.filter_devices)

    def create_enhanced_main_panels(self):
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left Panel (Devices)
        left_panel = ttk.Frame(main_container)
        self.create_enhanced_device_panel(left_panel)
        main_container.add(left_panel, weight=1)

        # Right Panel (Details)
        right_panel = ttk.Frame(main_container)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.create_enhanced_monitoring_tab()
        self.create_realtime_alerts_tab()
        self.create_enhanced_logs_tab()
        main_container.add(right_panel, weight=2)
    
    def create_enhanced_device_panel(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        columns = ('Status', 'IP', 'Hostname', 'OS', 'CPU %', 'Memory %', 'Alerts')
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        for col in columns:
            self.device_tree.heading(col, text=col, command=lambda c=col: self.sort_devices(c))
        
        v_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=v_scroll.set)
        self.device_tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')

        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        actions_frame = ttk.Frame(parent)
        actions_frame.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
        ttk.Button(actions_frame, text="Setup...", command=self.setup_selected_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Start Mon.", command=self.start_monitoring_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Stop Mon.", command=self.stop_monitoring_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Remove", command=self.remove_selected_devices).pack(side=tk.RIGHT, padx=2)

    def create_enhanced_monitoring_tab(self):
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="📊 Live Monitoring")
        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=monitor_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        gs = self.fig.add_gridspec(2, 2, hspace=0.4, wspace=0.3)
        self.cpu_ax = self.fig.add_subplot(gs[0, :])
        self.memory_ax = self.fig.add_subplot(gs[1, 0])
        self.disk_gauge_ax = self.fig.add_subplot(gs[1, 1])
        self.animation = animation.FuncAnimation(self.fig, self.update_monitoring_animation, interval=2000, cache_frame_data=False)

    def create_realtime_alerts_tab(self):
        alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(alerts_tab, text="🚨 Alerts")
        alert_cols = ('Severity', 'Device', 'Metric', 'Value', 'Time', 'Status')
        self.alerts_tree = ttk.Treeview(alerts_tab, columns=alert_cols, show='headings')
        for col in alert_cols: self.alerts_tree.heading(col, text=col)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_enhanced_logs_tab(self):
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📝 Logs")
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=10, font=('Consolas', 10), wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_configure("ERROR", foreground="#dc3545")
        self.log_text.tag_configure("INFO", foreground="#17a2b8")

    def create_enhanced_status_bar(self):
        status_frame = ttk.Frame(self.root, relief=tk.SUNKEN)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, anchor='w').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def setup_keyboard_shortcuts(self):
        self.root.bind('<Control-s>', lambda e: self.scan_network())
        self.root.bind('<F5>', lambda e: self.refresh_all())

    # --- CORE LOGIC ---
    def scan_network(self):
        def scan_thread():
            self.update_status("Scanning network...")
            network_range = self.network_var.get()
            found_devices = self.scanner.scan_network(network_range)
            new_devices_count = 0
            for device in found_devices:
                if device.ip not in self.devices:
                    self.devices[device.ip] = device
                    self.db_manager.save_device(device)
                    new_devices_count += 1
            self.root.after(0, self.update_device_display)
            self.log_message(f"Scan complete. Found {len(found_devices)} active devices ({new_devices_count} new).")
        threading.Thread(target=scan_thread, daemon=True).start()

    def get_selected_devices(self) -> List[NetworkDevice]:
        selected_items = self.device_tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more devices from the list.")
            return []
        return [self.devices[self.device_tree.item(item, 'values')[1]] for item in selected_items]

    def start_monitoring_selected(self):
        devices = self.get_selected_devices()
        if not devices: return
        
        # If any selected device already has credentials, use them. Otherwise, prompt.
        if all(d.credentials for d in devices):
             for device in devices:
                self._start_monitoring_for_device(device, device.credentials['username'], device.credentials['password'])
        else:
            # Prompt for credentials
            from tkinter import simpledialog
            username = simpledialog.askstring("Credentials", "Enter SSH Username:", parent=self.root)
            if not username: return
            password = simpledialog.askstring("Credentials", "Enter SSH Password:", show='*', parent=self.root)

            for device in devices:
                self._start_monitoring_for_device(device, username, password)

    def _start_monitoring_for_device(self, device, username, password):
        def start_mon_thread():
            try:
                self.log_message(f"Attempting to connect to {device.ip} for monitoring...")
                self.ssh_manager.connect_to_device(device, username, password)
                device.monitoring_enabled = True
                device.status = "Monitoring"
                self.db_manager.save_device(device)
                self.log_message(f"Successfully started monitoring {device.ip}.", "INFO")
                self.root.after(0, self.update_device_display)
            except Exception as e:
                self.log_message(f"Failed to start monitoring {device.ip}: {e}", "ERROR")
                messagebox.showerror("Error", f"Could not connect to {device.ip}.\nCheck credentials and network connectivity.")

        threading.Thread(target=start_mon_thread, daemon=True).start()

    def stop_monitoring_selected(self):
        for device in self.get_selected_devices():
            device.monitoring_enabled = False
            if device.ssh_client:
                device.ssh_client.close()
                device.ssh_client = None
            device.status = "Online" if self.scanner.ping_host(device.ip) else "Offline"
            self.db_manager.save_device(device)
        self.update_device_display()

    def remove_selected_devices(self):
        devices = self.get_selected_devices()
        if not devices: return
        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove {len(devices)} device(s)?"):
            for device in devices:
                del self.devices[device.ip]
                # Optional: Delete from DB
                # conn = self.db_manager.get_connection()
                # conn.execute("DELETE FROM devices WHERE ip = ?", (device.ip,))
                # self.db_manager.return_connection(conn)
            self.update_device_display()

    def setup_selected_devices(self):
        devices = self.get_selected_devices()
        if not devices: return
        
        dialog = Toplevel(self.root)
        dialog.title("Device Setup Wizard")
        # ... More complex dialog creation ...
        messagebox.showinfo("Setup", "This would launch a wizard to create monitoring users, deploy scripts, etc.", parent=dialog)
    
    # --- DISPLAY & UPDATES ---
    def update_device_display(self):
        search_term = self.search_var.get().lower()
        
        self.device_tree.delete(*self.device_tree.get_children())
        
        # Filter and sort devices
        devices_to_display = list(self.devices.values())
        if search_term:
            devices_to_display = [d for d in devices_to_display if search_term in d.ip or search_term in d.hostname.lower()]

        # Sorting logic
        col_index = self.device_tree['columns'].index(self.sort_column)
        try:
            # Attempt numeric sort for specific columns
            if self.sort_column in ['CPU %', 'Memory %']:
                devices_to_display.sort(key=lambda d: float(d.get_latest_metric(self.sort_column.split()[0].lower()) or -1), reverse=self.sort_reverse)
            else:
                # Default string sort
                 key_map = {'IP': 'ip', 'Hostname': 'hostname', 'OS': 'os_type', 'Status': 'status'}
                 devices_to_display.sort(key=lambda d: getattr(d, key_map[self.sort_column], '').lower(), reverse=self.sort_reverse)
        except Exception as e:
            logger.warning(f"Could not sort by {self.sort_column}: {e}")

        for device in devices_to_display:
            status_icon = "🟢" if device.status in ["Online", "Monitoring"] else "🔴" if device.status == "Offline" else "🟡"
            cpu = device.get_latest_metric('cpu')
            mem = device.get_latest_metric('memory')
            alert_count = len([a for a in self.alert_manager.get_active_alerts() if a.device_ip == device.ip])
            alert_text = f"🚨 {alert_count}" if alert_count > 0 else "✅"
            values = (
                f"{status_icon} {device.status}", device.ip, device.hostname, device.os_type,
                f"{cpu:.1f}" if cpu else "N/A", f"{mem:.1f}" if mem else "N/A",
                alert_text
            )
            self.device_tree.insert('', tk.END, values=values, iid=device.ip)

    def sort_devices(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self.update_device_display()

    def update_monitoring_animation(self, frame):
        selected = self.device_tree.selection()
        device = self.devices.get(self.device_tree.item(selected[0])['values'][1]) if selected else None
        
        self.cpu_ax.clear()
        self.memory_ax.clear()
        self.disk_gauge_ax.clear()
        
        if device and device.monitoring_enabled:
            cpu_data = list(device.metrics_history['cpu'])
            mem_data = list(device.metrics_history['memory'])
            disk_val = device.get_latest_metric('disk')
            if cpu_data:
                self.cpu_ax.plot(cpu_data, color='#007bff')
                self.cpu_ax.set_title(f'CPU Usage ({device.hostname})', fontweight='bold')
                self.cpu_ax.set_ylim(0, 105)

                self.memory_ax.plot(mem_data, color='#28a745')
                self.memory_ax.set_title('Memory Usage')
                self.memory_ax.set_ylim(0, 105)

            self.create_circular_gauge(self.disk_gauge_ax, disk_val, 'Disk', '#dc3545')
        
        self.style_monitoring_plots()
        self.canvas.draw_idle()

    def create_circular_gauge(self, ax, value, label, color):
        theme = self.modern_gui.themes[self.modern_gui.current_theme]
        ax.set_xlim(-1.2, 1.2); ax.set_ylim(-1.2, 1.2)
        ax.set_aspect('equal'); ax.axis('off')
        ax.add_artist(plt.Circle((0, 0), 1, color=theme['tree_bg'], fill=False, linewidth=12))
        if value > 0:
            angle = 90 - (value / 100) * 360
            wedge = plt.matplotlib.patches.Wedge((0, 0), 1, angle, 90, linewidth=12, facecolor=color, edgecolor=color)
            ax.add_artist(wedge)
        ax.text(0, 0, f"{value:.1f}%\n{label}", ha='center', va='center', fontsize=12, fontweight='bold', color=theme['fg'])

    def style_monitoring_plots(self):
        theme = self.modern_gui.themes[self.modern_gui.current_theme]
        self.fig.patch.set_facecolor(theme['bg'])
        for ax in [self.cpu_ax, self.memory_ax, self.disk_gauge_ax]:
            ax.set_facecolor(theme['bg'])
            ax.tick_params(colors=theme['fg'])
            for spine in ax.spines.values(): spine.set_color(theme['fg'])
            ax.title.set_color(theme['fg'])

    def log_message(self, message, level="INFO"):
        if not hasattr(self, 'log_text'): return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
        self.update_status(message)

    def auto_refresh_timer(self):
        # self.update_device_display() # This is now handled by monitoring events
        self.update_alerts_display()
        self.root.after(5000, self.auto_refresh_timer)

    def schedule_cleanup_tasks(self):
        threading.Timer(3600, self.db_manager.cleanup_old_data).start()

    def filter_devices(self, event=None): self.update_device_display()
    def on_device_select(self, event): pass # Handled by animation loop
    def refresh_all(self): self.update_device_display()
    def update_status(self, msg): self.status_var.set(msg[:100])
    def update_alerts_display(self):
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        for alert in self.alert_manager.get_active_alerts():
            severity = "🔴 Crit" if alert.level == "critical" else "🟡 Warn"
            status = "Ack" if alert.acknowledged else "New"
            self.alerts_tree.insert('', 'end', values=(severity, alert.device_ip, alert.metric, f"{alert.value:.1f}", alert.timestamp.strftime('%H:%M'), status))
    
    def show_preferences(self):
        current_interval = self.config.getint('MONITORING', 'interval', fallback=15)
        new_interval = simpledialog.askinteger("Preferences", "Set monitoring interval (seconds):",
                                               initialvalue=current_interval, minvalue=5, maxvalue=300)
        if new_interval:
            self.config.set('MONITORING', 'interval', str(new_interval))
            self.save_configuration()
            self.monitoring_thread.monitoring_interval = new_interval
            self.log_message(f"Monitoring interval updated to {new_interval} seconds.")


    def safe_exit(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.monitoring_thread.stop()
            self.save_configuration()
            self.root.destroy()

def main():
    try:
        root = tk.Tk()
        app = EnhancedPCManagementApp(root)
        root.mainloop()
    except ImportError as e:
        messagebox.showerror("Dependency Error", f"Missing required module: {e.name}\nPlease install it using: pip install {e.name}")
    except Exception as e:
        logger.critical(f"Unhandled application error: {e}", exc_info=True)
        messagebox.showerror("Fatal Error", f"A critical error occurred: {e}\nCheck network_monitor.log for details.")

if __name__ == "__main__":
    main()