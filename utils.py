"""
Utility functions for Network Traffic Analyzer
"""

import logging
import os
from datetime import datetime
import json

def setup_logging():
    """Setup logging configuration"""
    os.makedirs("data/logs", exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('data/logs/network_analyzer.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def format_bytes(bytes_value):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} TB"

def get_network_interfaces():
    """Get available network interfaces"""
    import psutil
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces.append({
                    'name': interface,
                    'ip': addr.address
                })
    return interfaces

def save_packet_data(packets, filename):
    """Save packet data to JSON file"""
    os.makedirs("data", exist_ok=True)
    with open(f"data/{filename}", 'w') as f:
        json.dump(packets, f, default=str, indent=2)

def load_packet_data(filename):
    """Load packet data from JSON file"""
    try:
        with open(f"data/{filename}", 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def get_protocol_color(protocol):
    """Get color for protocol visualization"""
    colors = {
        'TCP': '#1f77b4',
        'UDP': '#ff7f0e',
        'ICMP': '#2ca02c',
        'HTTP': '#d62728',
        'HTTPS': '#9467bd'
    }
    return colors.get(protocol, '#7f7f7f')
