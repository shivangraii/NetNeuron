"""
Threat detection and analysis functionality
"""

import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import pandas as pd

logger = logging.getLogger(__name__)

class ThreatDetector:
    """Threat detection and analysis"""

    def __init__(self):
        self.connection_tracker = defaultdict(set)  # IP -> set of ports
        self.packet_counter = defaultdict(list)     # IP -> list of timestamps
        self.suspicious_ips = set()
        self.alerts = []

        # Suspicious ports (commonly targeted)
        self.suspicious_ports = {
            22: 'SSH',
            23: 'Telnet',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'SQL Server',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }

        logger.info("ThreatDetector initialized")

    def analyze_packet(self, packet_info):
        """Analyze individual packet for threats"""
        threats = []
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        timestamp = packet_info.get('timestamp', datetime.now())

        if not src_ip:
            return threats

        # Port scanning detection
        if dst_port:
            self.connection_tracker[src_ip].add(dst_port)
            if len(self.connection_tracker[src_ip]) > 10:  # Threshold
                threats.append({
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'source_ip': src_ip,
                    'description': f'Port scanning detected from {src_ip}',
                    'ports_scanned': len(self.connection_tracker[src_ip])
                })

        # DDoS detection (high packet rate)
        self.packet_counter[src_ip].append(timestamp)
        # Keep only last minute of data
        cutoff_time = timestamp - timedelta(minutes=1)
        self.packet_counter[src_ip] = [
            t for t in self.packet_counter[src_ip] if t > cutoff_time
        ]

        if len(self.packet_counter[src_ip]) > 100:  # Threshold
            threats.append({
                'type': 'Potential DDoS',
                'severity': 'CRITICAL',
                'source_ip': src_ip,
                'description': f'High packet rate from {src_ip}',
                'packet_rate': len(self.packet_counter[src_ip])
            })

        # Suspicious port detection
        if dst_port in self.suspicious_ports:
            threats.append({
                'type': 'Suspicious Port Access',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'destination_port': dst_port,
                'service': self.suspicious_ports[dst_port],
                'description': f'Access to suspicious port {dst_port} ({self.suspicious_ports[dst_port]})'
            })

        # Add threats to alerts
        for threat in threats:
            threat['timestamp'] = timestamp
            self.alerts.append(threat)
            self.suspicious_ips.add(src_ip)

        return threats

    def get_threat_summary(self):
        """Get summary of detected threats"""
        if not self.alerts:
            return {
                'total_threats': 0,
                'threat_types': {},
                'severity_distribution': {},
                'top_threat_sources': {}
            }

        df = pd.DataFrame(self.alerts)

        return {
            'total_threats': len(self.alerts),
            'threat_types': df['type'].value_counts().to_dict(),
            'severity_distribution': df['severity'].value_counts().to_dict(),
            'top_threat_sources': df['source_ip'].value_counts().head(5).to_dict(),
            'recent_alerts': self.alerts[-10:]  # Last 10 alerts
        }

    def get_security_score(self):
        """Calculate overall security score (0-100)"""
        base_score = 100

        # Deduct points for threats
        threat_penalties = {
            'CRITICAL': 20,
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2
        }

        for alert in self.alerts[-50:]:  # Consider last 50 alerts
            severity = alert.get('severity', 'LOW')
            base_score -= threat_penalties.get(severity, 1)

        return max(0, min(100, base_score))

    def clear_old_data(self, hours=24):
        """Clear old threat data"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        self.alerts = [alert for alert in self.alerts if alert['timestamp'] > cutoff_time]
        logger.info(f"Cleared threat data older than {hours} hours")
