"""Packet capture and sniffing module"""

import sys
from scapy.all import sniff, IP, IPv6, ICMP, TCP, UDP, DNS, ARP, conf
from config import Config
import logging

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures network packets from specified interface"""
    
    def __init__(self, config=None):
        self.config = config or Config()
    
    def get_interfaces(self):
        """Get list of available network interfaces"""
        return conf.ifaces
    
    def capture(self, interface=None, packet_filter=None, packet_count=0):
        """
        Capture packets from specified interface
        
        Args:
            interface: Network interface name (None = default)
            packet_filter: BPF filter string
            packet_count: Number of packets (0 = infinite)
        
        Yields:
            Scapy packet objects
        """
        try:
            # Use default interface if not specified
            if interface is None:
                interfaces = self.get_interfaces()
                if not interfaces:
                    raise Exception("No network interfaces available")
                interface = list(interfaces.keys())[0]
                logger.info(f"Using interface: {interface}")
            
            # Set capture options
            kwargs = {
                'iface': interface,
                'prn': lambda x: x,  # Process function
                'store': False,  # Don't store packets in memory
                'filter': packet_filter or self.config.DEFAULT_FILTER or '',
                'timeout': self.config.TIMEOUT / 1000,  # Convert ms to seconds
                'immediate_mode': self.config.IMMEDIATE_MODE,
            }
            
            if packet_count > 0:
                kwargs['count'] = packet_count
            
            logger.info(f"Starting packet capture on {interface}")
            if packet_filter:
                logger.info(f"Using filter: {packet_filter}")
            
            # Use generator pattern to yield packets
            for packet in sniff(**kwargs):
                yield packet
        
        except PermissionError:
            raise PermissionError("Root/Administrator privileges required for packet capture")
        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
            raise
    
    def read_pcap(self, filepath):
        """
        Read packets from PCAP file
        
        Args:
            filepath: Path to PCAP file
        
        Yields:
            Scapy packet objects
        """
        try:
            from scapy.all import rdpcap
            packets = rdpcap(filepath)
            for packet in packets:
                yield packet
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error reading PCAP file: {str(e)}")
            raise
    
    def write_pcap(self, packets, filepath):
        """
        Save packets to PCAP file
        
        Args:
            packets: List of Scapy packet objects
            filepath: Output PCAP file path
        """
        try:
            from scapy.all import wrpcap
            wrpcap(filepath, packets)
            logger.info(f"Saved {len(packets)} packets to {filepath}")
        except Exception as e:
            logger.error(f"Error writing PCAP file: {str(e)}")
            raise
