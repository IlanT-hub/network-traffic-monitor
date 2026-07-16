"""Configuration settings for Network Traffic Monitor"""

import os
from pathlib import Path
from typing import Dict, Optional


class Config:
    """Application configuration"""
    
    # Application metadata
    VERSION = "1.0.0"
    APP_NAME = "Network Traffic Monitor"
    
    # Network interface settings
    DEFAULT_INTERFACE: Optional[str] = None  # Auto-detect
    PACKET_COUNT: int = 0  # 0 = infinite
    SNAPSHOT_LENGTH: int = 65535  # Maximum bytes to capture per packet
    
    # Capture settings
    TIMEOUT: int = 1000  # Milliseconds
    PROMISCUOUS: bool = True  # Capture all packets on network
    IMMEDIATE_MODE: bool = True  # Immediate packet delivery
    
    # Filter settings
    DEFAULT_FILTER: Optional[str] = None
    
    # Analysis settings
    PACKET_BUFFER_SIZE: int = 2000  # Increased for better analysis
    STATS_UPDATE_INTERVAL: int = 5  # seconds
    
    # Anomaly detection
    ANOMALY_DETECTION: bool = True
    ANOMALY_SENSITIVITY: float = 0.75  # 0.0 to 1.0
    ANOMALY_THRESHOLD: float = 0.8
    ENABLE_ML_DETECTION: bool = False  # Future ML-based detection
    
    # DDoS Detection
    DDOS_DETECTION: bool = False
    DDOS_PACKET_RATE_THRESHOLD: int = 1000  # packets per second
    DDOS_BYTE_RATE_THRESHOLD: int = 1000000  # bytes per second
    
    # Alert settings
    ALERTS_ENABLED: bool = True
    ALERT_THRESHOLD: float = 0.7
    ALERT_COOLDOWN: int = 60  # seconds between similar alerts
    
    # Geolocation (optional)
    GEOIP_ENABLED: bool = False
    GEOIP_DB_PATH: Optional[str] = None
    
    # Data storage
    DATA_DIR = Path(__file__).parent / "data"
    CAPTURES_DIR = DATA_DIR / "captures"
    REPORTS_DIR = DATA_DIR / "reports"
    LOGS_DIR = DATA_DIR / "logs"
    
    # Display settings
    COLORS_ENABLED: bool = True
    VERBOSE: bool = False
    MAX_DISPLAY_PACKETS: int = 50
    DASHBOARD_UPDATE_INTERVAL: int = 1  # seconds
    
    # Protocol tracking
    TRACK_PROTOCOLS: Dict[str, bool] = {
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
        'IMAP': True,
        'QUIC': True,  # HTTP/3
        'MQTT': True,  # IoT
        'CoAP': True,  # IoT
    }
    
    # Port ranges for common services
    COMMON_PORTS: Dict[int, str] = {
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
        465: 'SMTPS',
        587: 'SMTP-TLS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT',
        27017: 'MongoDB',
        3389: 'RDP',
        5900: 'VNC',
    }
    
    def __init__(self) -> None:
        """Initialize configuration and create necessary directories"""
        self._create_directories()
        self._load_env_vars()
    
    def _create_directories(self) -> None:
        """Create necessary data directories"""
        for directory in [self.DATA_DIR, self.CAPTURES_DIR, self.REPORTS_DIR, self.LOGS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _load_env_vars(self) -> None:
        """Load settings from environment variables"""
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        
        self.DEFAULT_INTERFACE = os.getenv('DEFAULT_INTERFACE', self.DEFAULT_INTERFACE)
        self.ANOMALY_DETECTION = os.getenv('ANOMALY_DETECTION', 'true').lower() == 'true'
        self.DDOS_DETECTION = os.getenv('DDOS_DETECTION', 'false').lower() == 'true'
        self.VERBOSE = os.getenv('VERBOSE', 'false').lower() == 'true'
        self.GEOIP_ENABLED = os.getenv('GEOIP_ENABLED', 'false').lower() == 'true'
