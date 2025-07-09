"""
Packet capture and processing functionality
"""

from scapy.all import *
import threading
import queue
from datetime import datetime
import logging
from collections import defaultdict
import pandas as pd

logger = logging.getLogger(__name__)

class PacketCapture:
    """Main packet capture class"""

    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.capture_active = False
        self.capture_thread = None
        self.packet_data = []
        self.packet_count = 0
        self.start_time = datetime.now()
        self.lock = threading.Lock()

        # Protocol mapping
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            47: 'GRE'
        }

        logger.info(f"PacketCapture initialized for interface: {interface}")

    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            if IP in packet:
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': self.get_protocol_name(packet[IP].proto),
                    'size': len(packet),
                    'ttl': packet[IP].ttl,
                    'time_relative': (datetime.now() - self.start_time).total_seconds()
                }

                # Add TCP-specific information
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'tcp_flags': packet[TCP].flags,
                        'window_size': packet[TCP].window
                    })

                # Add UDP-specific information
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })

                # Add ICMP-specific information
                elif ICMP in packet:
                    packet_info.update({
                        'icmp_type': packet[ICMP].type,
                        'icmp_code': packet[ICMP].code
                    })

                with self.lock:
                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Prevent memory overflow
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

                self.packet_queue.put(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def start_capture(self, packet_count=0, filter_str=""):
        """Start packet capture"""
        if self.capture_active:
            logger.warning("Capture already active")
            return

        self.capture_active = True
        logger.info(f"Starting packet capture on {self.interface}")

        def capture_packets():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    filter=filter_str,
                    count=packet_count,
                    stop_filter=lambda x: not self.capture_active
                )
            except Exception as e:
                logger.error(f"Capture error: {str(e)}")

        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        logger.info("Packet capture stopped")

    def get_dataframe(self):
        """Get packet data as pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data.copy())

    def get_statistics(self):
        """Get capture statistics"""
        with self.lock:
            df = pd.DataFrame(self.packet_data)
            if len(df) == 0:
                return {}

            stats = {
                'total_packets': len(df),
                'protocols': df['protocol'].value_counts().to_dict(),
                'top_sources': df['src_ip'].value_counts().head(5).to_dict(),
                'top_destinations': df['dst_ip'].value_counts().head(5).to_dict(),
                'capture_duration': (datetime.now() - self.start_time).total_seconds(),
                'packets_per_second': len(df) / max((datetime.now() - self.start_time).total_seconds(), 1)
            }

            return stats
