"""Report generation module (2026 Edition)"""

import json
import csv
import logging
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates network analysis reports (2026 Edition)"""
    
    def __init__(self) -> None:
        self.config = Config()
    
    def generate_json(self, stats: Dict[str, Any]) -> str:
        """Generate JSON report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'version': self.config.VERSION,
            'statistics': stats,
        }
        return json.dumps(report, indent=2, default=str)
    
    def generate_csv(self, stats: Dict[str, Any]) -> str:
        """Generate CSV report"""
        csv_content = "Metric,Value\n"
        csv_content += f"Generated,{datetime.now().isoformat()}\n"
        csv_content += f"Version,{self.config.VERSION}\n\n"
        
        for key, value in stats.items():
            if isinstance(value, (dict, list)):
                continue
            csv_content += f"{key},{value}\n"
        
        return csv_content
    
    def generate_html(self, stats: Dict[str, Any]) -> str:
        """Generate HTML report (2026 styled)"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Analysis Report 2026</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        header h1 {{ margin-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        th {{ background-color: #667eea; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background-color: #f9f9f9; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ color: #667eea; margin-bottom: 10px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; }}
        footer {{ text-align: center; color: #999; margin-top: 40px; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🌐 Network Traffic Analysis Report 2026</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stat-grid">
        """
        
        # Add stat cards
        key_stats = [
            ('Total Packets', stats.get('packet_count', 0), '📦'),
            ('Total Data', self._format_bytes(stats.get('total_bytes', 0)), '💾'),
            ('Duration', f"{stats.get('elapsed_seconds', 0):.1f}s", '⏱️'),
            ('Packets/sec', f"{stats.get('packets_per_second', 0):.2f}", '⚡'),
        ]
        
        for label, value, icon in key_stats:
            html += f"""
            <div class="stat-card">
                <h3>{icon} {label}</h3>
                <div class="stat-value">{value}</div>
            </div>
            """
        
        html += "</div>"
        
        # Add detailed table
        html += """
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
        """
        
        for key, value in stats.items():
            if isinstance(value, dict):
                continue
            html += f"<tr><td>{key}</td><td>{value}</td></tr>\n"
        
        html += """
        </table>
        <footer>
            <p>Network Traffic Monitor 2026 | Advanced packet analysis and monitoring</p>
        </footer>
    </div>
</body>
</html>
        """
        return html
    
    def save_report(self, content: str, filename: str) -> None:
        """Save report to file"""
        try:
            filepath = self.config.REPORTS_DIR / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Report saved: {filepath}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise
    
    @staticmethod
    def _format_bytes(bytes_value: float) -> str:
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"
