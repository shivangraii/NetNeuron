"""
IP Geolocation functionality
"""

import requests
import logging
from functools import lru_cache
import json

logger = logging.getLogger(__name__)

class GeoLocator:
    """IP Geolocation service"""

    def __init__(self):
        self.cache = {}
        self.api_url = "<http://ip-api.com/json/>"
        logger.info("GeoLocator initialized")

    @lru_cache(maxsize=1000)
    def get_location(self, ip_address):
        """Get location information for IP address"""
        if not ip_address or self.is_private_ip(ip_address):
            return {
                'country': 'Private/Local',
                'city': 'Local Network',
                'latitude': 0,
                'longitude': 0,
                'isp': 'Local'
            }

        try:
            response = requests.get(f"{self.api_url}{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', 'Unknown'),
                        'region': data.get('regionName', 'Unknown')
                    }
        except Exception as e:
            logger.error(f"Geolocation error for {ip_address}: {str(e)}")

        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'isp': 'Unknown'
        }

    def is_private_ip(self, ip):
        """Check if IP is private/local"""
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '169.254.'
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)

    def get_threat_map_data(self, packet_data):
        """Get geolocation data for threat mapping"""
        locations = []
        ip_counts = {}

        for packet in packet_data:
            src_ip = packet.get('src_ip')
            if src_ip and not self.is_private_ip(src_ip):
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

        for ip, count in ip_counts.items():
            location = self.get_location(ip)
            if location['latitude'] != 0 or location['longitude'] != 0:
                locations.append({
                    'ip': ip,
                    'count': count,
                    'lat': location['latitude'],
                    'lon': location['longitude'],
                    'country': location['country'],
                    'city': location['city'],
                    'isp': location['isp']
                })

        return locations
