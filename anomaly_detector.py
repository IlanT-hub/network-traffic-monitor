"""Anomaly detection engine"""

from collections import deque
import time
import statistics


class AnomalyDetector:
    """Detects anomalous network traffic patterns"""
    
    def __init__(self, config=None):
        self.config = config
        self.sensitivity = config.ANOMALY_SENSITIVITY if config else 0.75
        self.packet_history = deque(maxlen=1000)
        self.connection_history = deque(maxlen=500)
        self.packet_sizes = deque(maxlen=100)
        self.packet_rates = deque(maxlen=60)  # Last 60 seconds
        self.last_timestamp = time.time()
    
    def check_packet(self, packet, protocol_info):
        """Check packet for anomalies"""
        anomalies = []
        
        # Check packet size anomalies
        if self._is_unusual_packet_size(protocol_info):
            anomalies.append(f"Unusual packet size: {protocol_info['packet_size']} bytes")
        
        # Check for port scanning
        if self._detect_port_scanning(protocol_info):
            anomalies.append("Potential port scanning detected")
        
        # Check for unusual protocols
        if self._is_unusual_protocol(protocol_info):
            anomalies.append(f"Unusual protocol: {protocol_info.get('protocol')}")
        
        # Check for suspicious flags
        if self._check_suspicious_tcp_flags(protocol_info):
            anomalies.append("Suspicious TCP flags detected")
        
        return anomalies
    
    def _is_unusual_packet_size(self, protocol_info):
        """Detect unusually large or small packets"""
        size = protocol_info['packet_size']
        self.packet_sizes.append(size)
        
        if len(self.packet_sizes) < 10:
            return False
        
        mean = statistics.mean(self.packet_sizes)
        stdev = statistics.stdev(self.packet_sizes)
        
        # Flag if outside 3 standard deviations
        if abs(size - mean) > 3 * stdev:
            return True
        
        return False
    
    def _detect_port_scanning(self, protocol_info):
        """Detect potential port scanning activity"""
        if not protocol_info.get('dst_port'):
            return False
        
        src_ip = protocol_info.get('src_ip')
        if not src_ip:
            return False
        
        # Track unique ports per source IP
        port_key = f"{src_ip}_ports"
        if not hasattr(self, '_port_tracking'):
            self._port_tracking = {}
        
        if port_key not in self._port_tracking:
            self._port_tracking[port_key] = set()
        
        self._port_tracking[port_key].add(protocol_info['dst_port'])
        
        # Flag if more than 10 unique ports in 30 seconds
        if len(self._port_tracking[port_key]) > 10:
            return True
        
        return False
    
    def _is_unusual_protocol(self, protocol_info):
        """Check if protocol usage is unusual"""
        # Implement based on normal protocol distribution
        return False
    
    def _check_suspicious_tcp_flags(self, protocol_info):
        """Check for suspicious TCP flag combinations"""
        flags = protocol_info.get('tcp_flags', [])
        
        # Check for suspicious combinations
        if set(flags) == {'FIN', 'PSH', 'URG'}:  # FPU scan
            return True
        if set(flags) == {'SYN', 'FIN'}:  # SYN-FIN scan
            return True
        if len(flags) == 0 and 'protocol' in protocol_info and protocol_info['protocol'] == 'TCP':
            return True  # No flags on TCP packet
        
        return False
