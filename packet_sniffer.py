"""Packet capture and sniffing module (2026 Edition)"""

import logging
from typing import Optional, Iterator, List, Any
from scapy.all import sniff, conf, IP, IPv6
from config import Config

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures network packets from specified interface (2026 Edition)"""
    
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        # Disable IPv6 resolving for performance
        conf.ipv6_resolving = False
    
    def get_interfaces(self) -> dict:
        """Get list of available network interfaces"""
        return conf.ifaces
    
    def get_active_interfaces(self) -> List[str]:
        """Get list of active network interfaces"""
        try:
            import psutil
            active = []
            for iface_name, iface_info in psutil.net_if_addrs().items():
                if iface_info:  # Has IP addresses
                    active.append(iface_name)
            return active
        except Exception as e:
            logger.warning(f"Could not get active interfaces: {e}")
            return list(self.get_interfaces().keys())
    
    def capture(self, interface: Optional[str] = None, packet_filter: Optional[str] = None, 
                packet_count: int = 0) -> Iterator[Any]:
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
                interfaces = self.get_active_interfaces()
                if not interfaces:
                    raise Exception("No active network interfaces available")
                interface = interfaces[0]
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
                logger.info(f"Using BPF filter: {packet_filter}")
            
            # Use generator pattern to yield packets
            for packet in sniff(**kwargs):
                yield packet
        
        except PermissionError:
            raise PermissionError("Root/Administrator privileges required for packet capture")
        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
            raise
    
    def read_pcap(self, filepath: str) -> Iterator[Any]:
        """
        Read packets from PCAP file
        
        Args:
            filepath: Path to PCAP file
        
        Yields:
            Scapy packet objects
        """
        try:
            from scapy.all import rdpcap
            logger.info(f"Reading PCAP file: {filepath}")
            packets = rdpcap(filepath)
            for packet in packets:
                yield packet
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error reading PCAP file: {str(e)}")
            raise
    
    def write_pcap(self, packets: List[Any], filepath: str) -> None:
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
