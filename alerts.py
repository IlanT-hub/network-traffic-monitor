"""Alert system for network anomalies (2026 Edition)"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AlertSystem:
    """Manages and logs alerts with cooldown (2026 Edition)"""
    
    def __init__(self, config: Optional[Any] = None) -> None:
        self.config = config
        self.alerts_log: List[Dict[str, Any]] = []
        self.alert_cooldown: Dict[str, datetime] = {}  # Track alert cooldown
    
    def raise_alert(self, anomalies: List[str]) -> None:
        """Log and raise alert for anomalies with cooldown"""
        for anomaly in anomalies:
            # Check cooldown
            if self._is_on_cooldown(anomaly):
                continue
            
            alert = {
                'timestamp': datetime.now().isoformat(),
                'message': anomaly,
                'severity': self._determine_severity(anomaly),
            }
            self.alerts_log.append(alert)
            logger.warning(f"ALERT: {anomaly}")
            
            # Set cooldown
            cooldown_time = self.config.ALERT_COOLDOWN if self.config else 60
            self.alert_cooldown[anomaly] = datetime.now() + timedelta(seconds=cooldown_time)
    
    def _is_on_cooldown(self, anomaly: str) -> bool:
        """Check if alert is on cooldown"""
        if anomaly not in self.alert_cooldown:
            return False
        return datetime.now() < self.alert_cooldown[anomaly]
    
    def _determine_severity(self, anomaly_message: str) -> str:
        """Determine alert severity level"""
        msg_lower = anomaly_message.lower()
        
        if any(keyword in msg_lower for keyword in ['port scanning', 'flood', 'suspicious']):
            return 'HIGH'
        elif 'unusual' in msg_lower:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all logged alerts"""
        return self.alerts_log
    
    def clear_alerts(self) -> None:
        """Clear alert log"""
        self.alerts_log.clear()
