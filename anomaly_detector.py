"""Anomaly detection engine (2026 Edition with ML-ready structure)"""

import logging
from collections import deque
from typing import List, Dict, Any, Optional
import time
import statistics

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detects anomalous network traffic patterns (2026 ML-ready Edition)"""
    
    def __init__(self, config: Optional[Any] = None) -> None:
        self.config = config
        self.sensitivity = config.ANOMALY_SENSITIVITY if config else 0.75
        self.packet_history: deque = deque(maxlen=1000)
        self.connection_history: deque = deque(maxlen=500)
        self.packet_sizes: deque = deque(maxlen=100)
        self.packet_rates: deque = deque(maxlen=60)  # Last 60 seconds
        self.last_timestamp = time.time()
        self._port_tracking: Dict[str, set] = {}
        self._connection_tracking: Dict[str, int] = {}
    
    def check_packet(self, packet: Any, protocol_info: Dict[str, Any]) -> List[str]:
        """Check packet for anomalies"""
        anomalies: List[str] = []
        
        if not self.config or not self.config.ANOMALY_DETECTION:
            return anomalies
        
        # Check packet size anomalies
        if self._is_unusual_packet_size(protocol_info):
            anomalies.append(f"⚠️  Unusual packet size: {protocol_info['packet_size']} bytes")
        
        # Check for port scanning
        if self._detect_port_scanning(protocol_info):
            anomalies.append("🔍 Potential port scanning detected")
        
        # Check for suspicious flags
        if self._check_suspicious_tcp_flags(protocol_info):
            anomalies.append("⚡ Suspicious TCP flags detected")
        
        # Check for high-frequency connections from single IP
        if self._detect_connection_flood(protocol_info):
            anomalies.append("🌊 Potential connection flood detected")
        
        return anomalies
    
    def _is_unusual_packet_size(self, protocol_info: Dict[str, Any]) -> bool:
        """Detect unusually large or small packets"""
        size = protocol_info['packet_size']
        self.packet_sizes.append(size)
        
        if len(self.packet_sizes) < 10:
            return False
        
        try:
            mean = statistics.mean(self.packet_sizes)
            stdev = statistics.stdev(self.packet_sizes)
            
            # Flag if outside 3 standard deviations
            if stdev > 0 and abs(size - mean) > 3 * stdev:
                return True
        except Exception as e:
            logger.debug(f"Error calculating packet size anomaly: {e}")
        
        return False
    
    def _detect_port_scanning(self, protocol_info: Dict[str, Any]) -> bool:
        """Detect potential port scanning activity"""
        if not protocol_info.get('dst_port'):
            return False
        
        src_ip = protocol_info.get('src_ip')
        if not src_ip:
            return False
        
        # Track unique ports per source IP
        port_key = f"{src_ip}_ports"
        
        if port_key not in self._port_tracking:
            self._port_tracking[port_key] = set()
        
        self._port_tracking[port_key].add(protocol_info['dst_port'])
        
        # Flag if more than 10 unique ports (indicating port scan)
        if len(self._port_tracking[port_key]) > 10:
            return True
        
        return False
    
    def _check_suspicious_tcp_flags(self, protocol_info: Dict[str, Any]) -> bool:
        """Check for suspicious TCP flag combinations"""
        flags = protocol_info.get('tcp_flags', [])
        
        if not flags:
            return False
        
        flags_set = set(flags)
        
        # Check for suspicious combinations
        suspicious_patterns = [
            {'FIN', 'PSH', 'URG'},  # FPU scan
            {'SYN', 'FIN'},  # SYN-FIN scan
            {'SYN', 'RST'},  # SYN-RST scan
        ]
        
        for pattern in suspicious_patterns:
            if flags_set == pattern:
                return True
        
        return False
    
    def _detect_connection_flood(self, protocol_info: Dict[str, Any]) -> bool:
        """Detect potential connection flood (DDoS-like behavior)"""
        src_ip = protocol_info.get('src_ip')
        if not src_ip:
            return False
        
        current_time = time.time()
        key = f"{src_ip}_conns"
        
        if key not in self._connection_tracking:
            self._connection_tracking[key] = 0
        
        self._connection_tracking[key] += 1
        
        # Flag if more than 100 connections per minute from single IP
        return self._connection_tracking.get(key, 0) > 100
