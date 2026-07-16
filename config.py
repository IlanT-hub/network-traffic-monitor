"""Configuration settings for Network Traffic Monitor"""

import os
from pathlib import Path


class Config:
    """Application configuration"""
    
    # Network interface settings
    DEFAULT_INTERFACE = None  # Auto-detect
    PACKET_COUNT = 0  # 0 = infinite
    SNAPSHOT_LENGTH = 65535  # Maximum bytes to capture per packet
    
    # Capture settings
    TIMEOUT = 1000  # Milliseconds
    PROMISCUOUS = True  # Capture all packets on network
    IMMEDIATE_MODE = False
    
    # Filter settings
    DEFAULT_FILTER = None
    
    # Analysis settings
    PACKET_BUFFER_SIZE = 1000
    STATS_UPDATE_INTERVAL = 5  # seconds
    
    # Anomaly detection
    ANOMALY_DETECTION = True
    ANOMALY_SENSITIVITY = 0.75  # 0.0 to 1.0
    ANOMALY_THRESHOLD = 0.8
    
    # DDoS Detection
    DDOS_DETECTION = False
    DDOS_PACKET_RATE_THRESHOLD = 1000  # packets per second
    DDOS_BYTE_RATE_THRESHOLD = 1000000  # bytes per second
    
    # Alert settings
    ALERTS_ENABLED = True
    ALERT_THRESHOLD = 0.7
    
    # Geolocation
    GEOIP_ENABLED = False
    GEOIP_DB_PATH = None
    
    # Data storage
    DATA_DIR = Path(__file__).parent / "data"
    CAPTURES_DIR = DATA_DIR / "captures"
    REPORTS_DIR = DATA_DIR / "reports"
    LOGS_DIR = DATA_DIR / "logs"
    
    # Display settings
    COLORS_ENABLED = True
    VERBOSE = False
    MAX_DISPLAY_PACKETS = 20
    
    # Protocol tracking
    TRACK_PROTOCOLS = {
        'TCP': True,
        'UDP': True,
        'ICMP': True,
        'DNS': True,
        'HTTP': True,
        'HTTPS': True,
        'SSH': True,
        'FTP': True,
        'SMTP': True,
        'POP3': True,
    }
    
    # Port ranges for common services
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        8080: 'HTTP-ALT',
    }
    
    def __init__(self):
        """Initialize configuration and create necessary directories"""
        self._create_directories()
        self._load_env_vars()
    
    def _create_directories(self):
        """Create necessary data directories"""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_env_vars(self):
        """Load settings from environment variables"""
        from dotenv import load_dotenv
        load_dotenv()
        
        self.DEFAULT_INTERFACE = os.getenv('DEFAULT_INTERFACE', self.DEFAULT_INTERFACE)
        self.ANOMALY_DETECTION = os.getenv('ANOMALY_DETECTION', 'true').lower() == 'true'
        self.DDOS_DETECTION = os.getenv('DDOS_DETECTION', 'false').lower() == 'true'
        self.VERBOSE = os.getenv('VERBOSE', 'false').lower() == 'true'
