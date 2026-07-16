"""Alert system for network anomalies"""

from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AlertSystem:
    """Manages and logs alerts"""
    
    def __init__(self, config=None):
        self.config = config
        self.alerts_log = []
    
    def raise_alert(self, anomalies):
        """Log and raise alert for anomalies"""
        for anomaly in anomalies:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'message': anomaly,
                'severity': self._determine_severity(anomaly),
            }
            self.alerts_log.append(alert)
            logger.warning(f"ALERT: {anomaly}")
    
    def _determine_severity(self, anomaly_message):
        """Determine alert severity level"""
        if 'port scanning' in anomaly_message.lower():
            return 'HIGH'
        elif 'unusual' in anomaly_message.lower():
            return 'MEDIUM'
        else:
            return 'LOW'
