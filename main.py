#!/usr/bin/env python3
"""
Network Traffic Monitor - Main Entry Point (2026 Edition)
Captures and analyzes real-time network traffic with anomaly detection

Modern Python implementation with type hints, async support, and advanced monitoring
"""

import click
import sys
import signal
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
from packet_sniffer import PacketSniffer
from protocol_analyzer import ProtocolAnalyzer
from network_analyzer import NetworkAnalyzer
from anomaly_detector import AnomalyDetector
from dashboard import Dashboard
from alerts import AlertSystem
from report_generator import ReportGenerator
from config import Config
import logging
from datetime import datetime

# Setup logging with modern formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Main network monitoring application (2026 Edition)"""
    
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.sniffer = PacketSniffer(self.config)
        self.analyzer = ProtocolAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.anomaly_detector = AnomalyDetector(self.config)
        self.dashboard = Dashboard()
        self.alerts = AlertSystem(self.config)
        self.report_gen = ReportGenerator()
        self.running = True
        self.start_time = datetime.now()
    
    def signal_handler(self, sig: int, frame: Any) -> None:
        """Handle Ctrl+C gracefully"""
        self.running = False
        click.echo("\n\n👋 Stopping monitor...")
        logger.info(f"Monitor session ended. Duration: {datetime.now() - self.start_time}")
    
    def start_monitoring(self, interface: Optional[str] = None, filter_str: Optional[str] = None, show_dashboard: bool = False) -> None:
        """Start capturing and analyzing network traffic"""
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.dashboard.display_header(interface)
        logger.info(f"Starting network monitoring on interface: {interface or 'default'}")
        
        try:
            packet_count = 0
            anomaly_count = 0
            
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
                    anomaly_count += 1
                    self.alerts.raise_alert(anomalies)
                    self.dashboard.display_alert(anomalies)
                
                # Update statistics periodically
                if packet_count % 50 == 0:
                    stats = self.network_analyzer.get_statistics()
                    if show_dashboard:
                        self.dashboard.update(stats)
                    logger.debug(f"Processed {packet_count} packets, {anomaly_count} anomalies detected")
                
                # Display packet info
                self.dashboard.display_packet(protocol_info)
        
        except PermissionError:
            self.dashboard.error("Root/Administrator privileges required for packet capture")
            logger.error("Permission denied: requires root/admin privileges")
            sys.exit(1)
        except Exception as e:
            self.dashboard.error(f"Capture error: {str(e)}")
            logger.exception(f"Unexpected error during capture: {e}")
            sys.exit(1)
        finally:
            logger.info(f"Monitoring completed. Total packets: {packet_count}, Anomalies: {anomaly_count}")
    
    def start_dashboard_mode(self, interface: Optional[str] = None, filter_str: Optional[str] = None) -> None:
        """Start in real-time dashboard mode"""
        signal.signal(signal.SIGINT, self.signal_handler)
        self.dashboard.display_dashboard_header(interface)
        logger.info("Dashboard mode started")
        
        try:
            packet_count = 0
            for packet in self.sniffer.capture(interface, filter_str):
                if not self.running:
                    break
                
                packet_count += 1
                protocol_info = self.analyzer.analyze(packet)
                self.network_analyzer.process_packet(packet, protocol_info)
                
                # Check for anomalies
                anomalies = self.anomaly_detector.check_packet(packet, protocol_info)
                if anomalies:
                    self.alerts.raise_alert(anomalies)
                
                # Update dashboard in real-time (every 20 packets)
                if packet_count % 20 == 0:
                    stats = self.network_analyzer.get_statistics()
                    self.dashboard.render_dashboard(stats, anomalies)
        
        except PermissionError:
            self.dashboard.error("Root/Administrator privileges required")
            logger.error("Permission denied")
            sys.exit(1)
        finally:
            logger.info(f"Dashboard session ended. Total packets: {packet_count}")
    
    def analyze_pcap_file(self, pcap_file: str) -> None:
        """Analyze existing PCAP file"""
        try:
            self.dashboard.display_header(f"File: {pcap_file}")
            logger.info(f"Analyzing PCAP file: {pcap_file}")
            
            packet_count = 0
            for packet in self.sniffer.read_pcap(pcap_file):
                packet_count += 1
                protocol_info = self.analyzer.analyze(packet)
                self.network_analyzer.process_packet(packet, protocol_info)
                self.dashboard.display_packet(protocol_info)
            
            stats = self.network_analyzer.get_statistics()
            self.dashboard.display_statistics(stats)
            logger.info(f"PCAP analysis complete: {packet_count} packets")
        
        except FileNotFoundError:
            self.dashboard.error(f"PCAP file not found: {pcap_file}")
            logger.error(f"File not found: {pcap_file}")
            sys.exit(1)
        except Exception as e:
            self.dashboard.error(f"Analysis error: {str(e)}")
            logger.exception(f"Error analyzing PCAP: {e}")
            sys.exit(1)
    
    def export_report(self, format_type: str, output_file: Optional[str] = None) -> None:
        """Export network statistics and analysis report"""
        try:
            stats = self.network_analyzer.get_statistics()
            
            if format_type == 'json':
                report = self.report_gen.generate_json(stats)
            elif format_type == 'csv':
                report = self.report_gen.generate_csv(stats)
            elif format_type == 'html':
                report = self.report_gen.generate_html(stats)
            else:
                self.dashboard.error(f"Unsupported format: {format_type}")
                logger.error(f"Unsupported export format: {format_type}")
                return
            
            output_file = output_file or f"network_report.{format_type}"
            self.report_gen.save_report(report, output_file)
            self.dashboard.success(f"Report exported to {output_file}")
            logger.info(f"Report exported: {output_file}")
        except Exception as e:
            self.dashboard.error(f"Export error: {str(e)}")
            logger.exception(f"Error exporting report: {e}")


@click.command()
@click.option('--interface', type=str, default=None, help='Network interface to monitor')
@click.option('--filter', type=str, default=None, help='BPF filter (e.g., "tcp port 80")')
@click.option('--dashboard', is_flag=True, help='Show real-time dashboard')
@click.option('--pcap', type=str, default=None, help='Analyze PCAP file')
@click.option('--analyze', is_flag=True, help='Analyze packets')
@click.option('--export', type=str, default=None, help='Export report (json/csv/html)')
@click.option('--anomaly-detection', is_flag=True, help='Enable anomaly detection')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def main(interface: Optional[str], filter: Optional[str], dashboard: bool, pcap: Optional[str], 
         analyze: bool, export: Optional[str], anomaly_detection: bool, verbose: bool) -> None:
    """
    🌐 Network Traffic Monitor 2026 - Real-time packet capture and analysis
    
    Examples:
    
    sudo python main.py --interface eth0 --dashboard
    
    sudo python main.py --interface eth0 --filter "tcp port 80"
    
    sudo python main.py --pcap capture.pcap --analyze
    
    sudo python main.py --interface eth0 --export json
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    config = Config()
    config.ANOMALY_DETECTION = anomaly_detection
    config.VERBOSE = verbose
    
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
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
