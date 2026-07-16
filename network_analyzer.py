"""Network statistics and traffic analysis"""

import logging
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """Analyzes network traffic and generates statistics"""
    
    def __init__(self) -> None:
        self.packets: List[Tuple[float, Dict[str, Any]]] = []
        self.connections: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': Counter()})
        self.protocol_stats: Counter = Counter()
        self.port_stats: Counter = Counter()
        self.ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.start_time = time.time()
        self.packet_count = 0
        self.total_bytes = 0
        self.max_packet_size = 0
        self.min_packet_size = float('inf')
    
    def process_packet(self, packet: Any, protocol_info: Dict[str, Any]) -> None:
        """Process and analyze a packet"""
        self.packets.append((time.time(), protocol_info))
        self.packet_count += 1
        packet_size = protocol_info['packet_size']
        self.total_bytes += packet_size
        self.max_packet_size = max(self.max_packet_size, packet_size)
        self.min_packet_size = min(self.min_packet_size, packet_size)
        
        # Track protocols
        protocol = protocol_info.get('protocol', 'Unknown')
        self.protocol_stats[protocol] += 1
        
        # Track connections
        if protocol_info.get('src_ip') and protocol_info.get('dst_ip'):
            conn_key = f"{protocol_info['src_ip']} -> {protocol_info['dst_ip']}"
            self.connections[conn_key]['packets'] += 1
            self.connections[conn_key]['bytes'] += packet_size
            self.connections[conn_key]['protocols'][protocol] += 1
            
            # Track IP statistics
            self.ip_stats[protocol_info['src_ip']]['packets'] += 1
            self.ip_stats[protocol_info['src_ip']]['bytes'] += packet_size
        
        # Track ports
        if protocol_info.get('dst_port'):
            self.port_stats[protocol_info['dst_port']] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive network statistics"""
        elapsed_time = time.time() - self.start_time
        
        return {
            'timestamp': datetime.now().isoformat(),
            'elapsed_seconds': elapsed_time,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.packet_count / elapsed_time if elapsed_time > 0 else 0,
            'bytes_per_second': self.total_bytes / elapsed_time if elapsed_time > 0 else 0,
            'avg_packet_size': self.total_bytes / self.packet_count if self.packet_count > 0 else 0,
            'max_packet_size': self.max_packet_size,
            'min_packet_size': self.min_packet_size if self.min_packet_size != float('inf') else 0,
            'protocols': dict(self.protocol_stats.most_common()),
            'top_ports': dict(self.port_stats.most_common(10)),
            'connections': self._get_top_connections(10),
            'top_ips': self._get_top_ips(10),
        }
    
    def _get_top_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top connections by traffic"""
        sorted_conns = sorted(
            self.connections.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        return [
            {
                'connection': conn,
                'packets': data['packets'],
                'bytes': data['bytes'],
            }
            for conn, data in sorted_conns[:limit]
        ]
    
    def _get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top IP addresses by traffic"""
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        return [
            {
                'ip': ip,
                'packets': data['packets'],
                'bytes': data['bytes'],
            }
            for ip, data in sorted_ips[:limit]
        ]
    
    def get_protocol_distribution(self) -> Dict[str, float]:
        """Get protocol distribution percentages"""
        total = sum(self.protocol_stats.values())
        if total == 0:
            return {}
        
        return {
            protocol: (count / total) * 100
            for protocol, count in self.protocol_stats.items()
        }
    
    def get_connection_rate(self) -> float:
        """Get connections per second"""
        elapsed_time = time.time() - self.start_time
        if elapsed_time == 0:
            return 0.0
        return len(self.connections) / elapsed_time
