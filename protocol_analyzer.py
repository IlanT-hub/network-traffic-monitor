"""Protocol detection and packet parsing"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Raw
import logging

logger = logging.getLogger(__name__)


class ProtocolAnalyzer:
    """Analyzes packets and detects protocols"""
    
    def __init__(self):
        self.protocol_map = {
            6: 'TCP',
            17: 'UDP',
            1: 'ICMP',
        }
    
    def analyze(self, packet):
        """Analyze packet and extract protocol information"""
        info = {
            'timestamp': float(packet.time),
            'packet_size': len(packet),
            'protocols': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': 'Unknown',
            'flags': [],
            'payload': None,
        }
        
        # IP layer
        if IP in packet:
            ip_layer = packet[IP]
            info['src_ip'] = ip_layer.src
            info['dst_ip'] = ip_layer.dst
            info['ttl'] = ip_layer.ttl
            info['length'] = ip_layer.len
            info['protocol'] = self.protocol_map.get(ip_layer.proto, 'IP')
            info['protocols'].append('IPv4')
        
        # IPv6 layer
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            info['src_ip'] = ipv6_layer.src
            info['dst_ip'] = ipv6_layer.dst
            info['protocol'] = self.protocol_map.get(ipv6_layer.nxt, 'IPv6')
            info['protocols'].append('IPv6')
        
        # TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            info['src_port'] = tcp_layer.sport
            info['dst_port'] = tcp_layer.dport
            info['protocol'] = 'TCP'
            info['tcp_flags'] = self._parse_tcp_flags(tcp_layer.flags)
            info['seq'] = tcp_layer.seq
            info['ack'] = tcp_layer.ack
            info['window'] = tcp_layer.window
            info['protocols'].append('TCP')
        
        # UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            info['src_port'] = udp_layer.sport
            info['dst_port'] = udp_layer.dport
            info['protocol'] = 'UDP'
            info['protocols'].append('UDP')
        
        # ICMP layer
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            info['protocol'] = 'ICMP'
            info['icmp_type'] = icmp_layer.type
            info['icmp_code'] = icmp_layer.code
            info['protocols'].append('ICMP')
        
        # ARP layer
        if ARP in packet:
            arp_layer = packet[ARP]
            info['protocol'] = 'ARP'
            info['src_mac'] = arp_layer.hwsrc
            info['dst_mac'] = arp_layer.hwdst
            info['protocols'].append('ARP')
        
        # Application layer protocols
        info.update(self._detect_app_protocols(packet, info))
        
        # Payload
        if Raw in packet:
            info['payload'] = packet[Raw].load[:100]  # First 100 bytes
        
        return info
    
    def _parse_tcp_flags(self, flags):
        """Parse TCP flags"""
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR',
        }
        return [flag_map.get(f, f) for f in str(flags)]
    
    def _detect_app_protocols(self, packet, info):
        """Detect application layer protocols"""
        app_info = {}
        
        dst_port = info.get('dst_port')
        src_port = info.get('src_port')
        
        if not dst_port and not src_port:
            return app_info
        
        port = dst_port or src_port
        
        # Common port mappings
        port_protocol_map = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            8080: 'HTTP', 8443: 'HTTPS',
        }
        
        if port in port_protocol_map:
            app_info['app_protocol'] = port_protocol_map[port]
        
        # DNS detection
        if DNS in packet:
            app_info['app_protocol'] = 'DNS'
            app_info['dns_queries'] = self._parse_dns(packet[DNS])
        
        return app_info
    
    def _parse_dns(self, dns_layer):
        """Parse DNS queries"""
        queries = []
        if dns_layer.qdcount > 0:
            for i in range(dns_layer.qdcount):
                q = dns_layer.qd[i]
                queries.append({
                    'name': q.qname.decode() if hasattr(q.qname, 'decode') else str(q.qname),
                    'type': q.qtype,
                })
        return queries
