#!/usr/bin/env python3
"""
Network Traffic Monitor - Main Entry Point
Captures and analyzes real-time network traffic with anomaly detection
"""

import click
import sys
import signal
from pathlib import Path
from packet_sniffer import PacketSniffer
from protocol_analyzer import ProtocolAnalyzer
from network_analyzer import NetworkAnalyzer
from anomaly_detector import AnomalyDetector
from dashboard import Dashboard
from alerts import AlertSystem
from report_generator import ReportGenerator
from config import Config
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Main network monitoring application"""
    
    def __init__(self, config=None):
        self.config = config or Config()
        self.sniffer = PacketSniffer(self.config)
        self.analyzer = ProtocolAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.anomaly_detector = AnomalyDetector(self.config)
        self.dashboard = Dashboard()
        self.alerts = AlertSystem(self.config)
        self.report_gen = ReportGenerator()
        self.running = True
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.running = False
        click.echo("\n\n👋 Stopping monitor...")
    
    def start_monitoring(self, interface=None, filter_str=None, show_dashboard=False):
        """Start capturing and analyzing network traffic"""
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.dashboard.display_header(interface)
        
        try:
            packet_count = 0
            for packet in self.sniffer.capture(interface, filter_str):
                if not self.running:
                    break
                
                packet_count += 1
                
                # Analyze packet
                protocol_info = self.analyzer.analyze(packet)
                self.network_analyzer.process_packet(packet, protocol_info)
                
                # Check for anomalies
                anomalies = self.anomaly_detector.check_packet(packet, protocol_info)
                if anomalies:
                    self.alerts.raise_alert(anomalies)
                    self.dashboard.display_alert(anomalies)
                
                # Update dashboard periodically
                if packet_count % 10 == 0 and show_dashboard:
                    stats = self.network_analyzer.get_statistics()
                    self.dashboard.update(stats)
                
                # Print packet info
                self.dashboard.display_packet(protocol_info)
        
        except PermissionError:
            self.dashboard.error("Root/Administrator privileges required for packet capture")
            sys.exit(1)
        except Exception as e:
            self.dashboard.error(f"Capture error: {str(e)}")
            sys.exit(1)
    
    def start_dashboard_mode(self, interface=None, filter_str=None):
        """Start in real-time dashboard mode"""
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.dashboard.display_dashboard_header(interface)
        
        try:
            for packet in self.sniffer.capture(interface, filter_str):
                if not self.running:
                    break
                
                protocol_info = self.analyzer.analyze(packet)
                self.network_analyzer.process_packet(packet, protocol_info)
                
                # Check for anomalies
                anomalies = self.anomaly_detector.check_packet(packet, protocol_info)
                if anomalies:
                    self.alerts.raise_alert(anomalies)
                
                # Update dashboard in real-time
                stats = self.network_analyzer.get_statistics()
                self.dashboard.render_dashboard(stats, anomalies)
        
        except PermissionError:
            self.dashboard.error("Root/Administrator privileges required")
            sys.exit(1)
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze existing PCAP file"""
        try:
            self.dashboard.display_header(f"File: {pcap_file}")
            
            packets = self.sniffer.read_pcap(pcap_file)
            
            for packet in packets:
                protocol_info = self.analyzer.analyze(packet)
                self.network_analyzer.process_packet(packet, protocol_info)
                self.dashboard.display_packet(protocol_info)
            
            stats = self.network_analyzer.get_statistics()
            self.dashboard.display_statistics(stats)
        
        except FileNotFoundError:
            self.dashboard.error(f"PCAP file not found: {pcap_file}")
            sys.exit(1)
        except Exception as e:
            self.dashboard.error(f"Analysis error: {str(e)}")
            sys.exit(1)
    
    def export_report(self, format_type, output_file=None):
        """Export network statistics and analysis report"""
        stats = self.network_analyzer.get_statistics()
        
        if format_type == 'json':
            report = self.report_gen.generate_json(stats)
        elif format_type == 'csv':
            report = self.report_gen.generate_csv(stats)
        elif format_type == 'html':
            report = self.report_gen.generate_html(stats)
        else:
            self.dashboard.error(f"Unsupported format: {format_type}")
            return
        
        output_file = output_file or f"network_report.{format_type}"
        self.report_gen.save_report(report, output_file)
        self.dashboard.success(f"Report exported to {output_file}")


@click.command()
@click.option('--interface', type=str, help='Network interface to monitor')
@click.option('--filter', type=str, help='BPF filter (e.g., "tcp port 80")')
@click.option('--dashboard', is_flag=True, help='Show real-time dashboard')
@click.option('--pcap', type=str, help='Analyze PCAP file')
@click.option('--analyze', is_flag=True, help='Analyze packets')
@click.option('--export', type=str, help='Export report (json/csv/html)')
@click.option('--anomaly-detection', is_flag=True, help='Enable anomaly detection')
@click.option('--ddos-detection', is_flag=True, help='Enable DDoS detection')
def main(interface, filter, dashboard, pcap, analyze, export, anomaly_detection, ddos_detection):
    """
    🌐 Network Traffic Monitor - Real-time packet capture and analysis
    
    Examples:
    
    sudo python main.py --interface eth0 --dashboard
    
    sudo python main.py --interface eth0 --filter "tcp port 80"
    
    sudo python main.py --pcap capture.pcap --analyze
    
    sudo python main.py --interface eth0 --export json
    """
    
    config = Config()
    config.ANOMALY_DETECTION = anomaly_detection
    config.DDOS_DETECTION = ddos_detection
    
    monitor = NetworkMonitor(config)
    
    try:
        if pcap:
            monitor.analyze_pcap_file(pcap)
        elif export:
            monitor.export_report(export)
        elif dashboard:
            monitor.start_dashboard_mode(interface, filter)
        else:
            monitor.start_monitoring(interface, filter, show_dashboard=False)
    
    except KeyboardInterrupt:
        click.echo("\n\n👋 Monitor stopped")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
