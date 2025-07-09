"""
Configuration settings for Network Traffic Analyzer
"""

# Network Interface Settings
DEFAULT_INTERFACE = "eth0"  # Change to "wlan0" for WiFi on Linux, "Wi-Fi" on Windows
PACKET_COUNT_LIMIT = 10000  # Maximum packets to store in memory

# Dashboard Settings
DASHBOARD_TITLE = "🔒 Network Traffic Analyzer"
REFRESH_INTERVAL = 2  # seconds
AUTO_REFRESH = True

# Threat Detection Settings
THREAT_THRESHOLDS = {
    'port_scan_threshold': 10,  # connections to different ports
    'ddos_threshold': 100,      # packets per second from single IP
    'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389]
}

# Geolocation Settings
GEOIP_DATABASE_PATH = "data/geoip/GeoLite2-City.mmdb"
FALLBACK_GEOLOCATION_API = "<http://ip-api.com/json/>"

# Logging Settings
LOG_LEVEL = "INFO"
LOG_FILE = "data/logs/network_analyzer.log"

# Color Scheme
COLORS = {
    'primary': '#1f77b4',
    'danger': '#ff4757',
    'warning': '#ffa502',
    'success': '#2ed573',
    'info': '#3742fa'
}
