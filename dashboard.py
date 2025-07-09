"""
Streamlit dashboard for Network Traffic Analyzer
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
from datetime import datetime, timedelta
import numpy as np

from packet_capture import PacketCapture
from threat_detection import ThreatDetector
from geolocation import GeoLocator
from utils import setup_logging, get_network_interfaces, format_bytes

# Setup logging
logger = setup_logging()

class NetworkDashboard:
    """Main dashboard class"""

    def __init__(self):
        self.setup_page_config()
        self.initialize_session_state()

    def setup_page_config(self):
        """Configure Streamlit page"""
        st.set_page_config(
            page_title="🔒 Network Traffic Analyzer",
            page_icon="🔒",
            layout="wide",
            initial_sidebar_state="expanded"
        )

    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'packet_capture' not in st.session_state:
            st.session_state.packet_capture = None
        if 'threat_detector' not in st.session_state:
            st.session_state.threat_detector = ThreatDetector()
        if 'geo_locator' not in st.session_state:
            st.session_state.geo_locator = GeoLocator()
        if 'capture_active' not in st.session_state:
            st.session_state.capture_active = False
        if 'start_time' not in st.session_state:
            st.session_state.start_time = time.time()

    def render_sidebar(self):
        """Render sidebar controls"""
        st.sidebar.title("🔧 Controls")

        # Interface selection
        interfaces = get_network_interfaces()
        interface_names = [iface['name'] for iface in interfaces]

        selected_interface = st.sidebar.selectbox(
            "Select Network Interface",
            interface_names,
            index=0 if interface_names else None
        )

        # Capture controls
        col1, col2 = st.sidebar.columns(2)

        with col1:
            if st.button("🚀 Start Capture", disabled=st.session_state.capture_active):
                self.start_capture(selected_interface)

        with col2:
            if st.button("⏹️ Stop Capture", disabled=not st.session_state.capture_active):
                self.stop_capture()

        # Packet filter
        st.sidebar.subheader("🔍 Packet Filter")
        filter_protocol = st.sidebar.selectbox(
            "Protocol Filter",
            ["All", "TCP", "UDP", "ICMP"]
        )

        # Auto-refresh toggle
        auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh", value=True)

        if auto_refresh:
            time.sleep(2)
            st.rerun()

        return selected_interface, filter_protocol

    def start_capture(self, interface):
        """Start packet capture"""
        try:
            st.session_state.packet_capture = PacketCapture(interface)
            st.session_state.packet_capture.start_capture()
            st.session_state.capture_active = True
            st.session_state.start_time = time.time()
            st.sidebar.success(f"✅ Capture started on {interface}")
            logger.info(f"Capture started on interface: {interface}")
        except Exception as e:
            st.sidebar.error(f"❌ Error starting capture: {str(e)}")
            logger.error(f"Error starting capture: {str(e)}")

    def stop_capture(self):
        """Stop packet capture"""
        if st.session_state.packet_capture:
            st.session_state.packet_capture.stop_capture()
            st.session_state.capture_active = False
            st.sidebar.success("⏹️ Capture stopped")
            logger.info("Capture stopped")

    def render_metrics(self):
        """Render key metrics"""
        if not st.session_state.packet_capture:
            st.info("👆 Please start packet capture from the sidebar")
            return

        stats = st.session_state.packet_capture.get_statistics()
        threat_summary = st.session_state.threat_detector.get_threat_summary()
        security_score = st.session_state.threat_detector.get_security_score()

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric(
                "📦 Total Packets",
                f"{stats.get('total_packets', 0):,}",
                delta=f"{stats.get('packets_per_second', 0):.1f}/sec"
            )

        with col2:
            st.metric(
                "⚠️ Threats Detected",
                threat_summary.get('total_threats', 0),
                delta=None
            )

        with col3:
            duration = time.time() - st.session_state.start_time
            st.metric(
                "⏱️ Capture Duration",
                f"{duration:.0f}s",
                delta=None
            )

        with col4:
            st.metric(
                "🛡️ Security Score",
                f"{security_score}/100",
                delta=None,
                delta_color="inverse"
            )

        with col5:
            protocols = stats.get('protocols', {})
            dominant_protocol = max(protocols.keys(), key=protocols.get) if protocols else "None"
            st.metric(
                "📊 Dominant Protocol",
                dominant_protocol,
                delta=f"{protocols.get(dominant_protocol, 0)} packets"
            )

    def render_protocol_distribution(self, df):
        """Render protocol distribution chart"""
        if len(df) == 0:
            st.info("No data to display")
            return

        protocol_counts = df['protocol'].value_counts()

        fig = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="📊 Protocol Distribution",
            color_discrete_sequence=px.colors.qualitative.Set3
        )

        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

    def render_traffic_timeline(self, df):
        """Render traffic timeline"""
        if len(df) == 0:
            st.info("No data to display")
            return

        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size().reset_index()
        df_grouped.columns = ['timestamp', 'packet_count']

        fig = px.line(
            df_grouped,
            x='timestamp',
            y='packet_count',
            title="📈 Packets Per Second Timeline",
            labels={'packet_count': 'Packets/Second', 'timestamp': 'Time'}
        )

        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Packets per Second",
            hovermode='x unified'
        )

        st.plotly_chart(fig, use_container_width=True)

    def render_top_talkers(self, df):
        """Render top talkers chart"""
        if len(df) == 0:
            st.info("No data to display")
            return

        col1, col2 = st.columns(2)

        with col1:
            top_sources = df['src_ip'].value_counts().head(10)
            fig_src = px.bar(
                x=top_sources.values,
                y=top_sources.index,
                orientation='h',
                title="🔝 Top Source IPs",
                labels={'x': 'Packet Count', 'y': 'Source IP'}
            )
            fig_src.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_src, use_container_width=True)

        with col2:
            top_destinations = df['dst_ip'].value_counts().head(10)
            fig_dst = px.bar(
                x=top_destinations.values,
                y=top_destinations.index,
                orientation='h',
                title="🎯 Top Destination IPs",
                labels={'x': 'Packet Count', 'y': 'Destination IP'}
            )
            fig_dst.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_dst, use_container_width=True)

    def render_threat_map(self, df):
        """Render geographical threat map"""
        if len(df) == 0:
            st.info("No data to display")
            return

        # Get geolocation data
        locations = st.session_state.geo_locator.get_threat_map_data(df.to_dict('records'))

        if not locations:
            st.info("No geographical data available")
            return

        # Create map
        fig = go.Figure(data=go.Scattergeo(
            lon=[loc['lon'] for loc in locations],
            lat=[loc['lat'] for loc in locations],
            text=[f"{loc['ip']}<br>{loc['city']}, {loc['country']}<br>Packets: {loc['count']}" for loc in locations],
            mode='markers',
            marker=dict(
                size=[min(loc['count'] / 10, 20) for loc in locations],
                color=[loc['count'] for loc in locations],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Packet Count")
            )
        ))

        fig.update_layout(
            title="🌍 Global Traffic Sources",
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='equirectangular'
            )
        )

        st.plotly_chart(fig, use_container_width=True)

    def render_threat_alerts(self):
        """Render threat alerts"""
        threat_summary = st.session_state.threat_detector.get_threat_summary()

        if threat_summary['total_threats'] == 0:
            st.success("🛡️ No threats detected")
            return

        st.subheader("⚠️ Recent Threat Alerts")

        alerts = threat_summary.get('recent_alerts', [])
        for alert in alerts[-5:]:  # Show last 5 alerts
            severity_colors = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }

            severity_icon = severity_colors.get(alert['severity'], '⚪')

            with st.expander(f"{severity_icon} {alert['type']} - {alert['severity']}"):
                st.write(f"**Source IP:** {alert.get('source_ip', 'Unknown')}")
                st.write(f"**Description:** {alert['description']}")
                st.write(f"**Time:** {alert['timestamp']}")

                if 'destination_port' in alert:
                    st.write(f"**Target Port:** {alert['destination_port']}")
                if 'service' in alert:
                    st.write(f"**Service:** {alert['service']}")

    def render_packet_details(self, df):
        """Render detailed packet information"""
        if len(df) == 0:
            st.info("No packets captured yet")
            return

        st.subheader("📋 Recent Packet Details")

        # Show last 20 packets
        recent_packets = df.tail(20)[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'size']]

        # Format the dataframe for better display
        recent_packets['timestamp'] = pd.to_datetime(recent_packets['timestamp']).dt.strftime('%H:%M:%S')
        recent_packets['size'] = recent_packets['size'].apply(lambda x: f"{x} bytes")

        st.dataframe(
            recent_packets,
            use_container_width=True,
            hide_index=True
        )

    def run(self):
        """Main dashboard runner"""
        st.title("🔒 Network Traffic Analyzer Dashboard")
        st.markdown("---")

        # Render sidebar
        selected_interface, filter_protocol = self.render_sidebar()

        # Render main content
        self.render_metrics()

        if st.session_state.packet_capture:
            df = st.session_state.packet_capture.get_dataframe()

            # Apply protocol filter
            if filter_protocol != "All" and len(df) > 0:
                df = df[df['protocol'] == filter_protocol]

            # Analyze packets for threats
            for _, packet in df.iterrows():
                st.session_state.threat_detector.analyze_packet(packet.to_dict())

            # Create tabs for different views
            tab1, tab2, tab3, tab4 = st.tabs(["📊 Analytics", "🌍 Geo Map", "⚠️ Threats", "📋 Details"])

            with tab1:
                col1, col2 = st.columns(2)
                with col1:
                    self.render_protocol_distribution(df)
                with col2:
                    self.render_traffic_timeline(df)

                self.render_top_talkers(df)

            with tab2:
                self.render_threat_map(df)

            with tab3:
                self.render_threat_alerts()

            with tab4:
                self.render_packet_details(df)

# Run the dashboard
if __name__ == "__main__":
    dashboard = NetworkDashboard()
    dashboard.run()
