"""Report generation module"""

import json
import csv
from pathlib import Path
from config import Config
from datetime import datetime


class ReportGenerator:
    """Generates network analysis reports"""
    
    def __init__(self):
        self.config = Config()
    
    def generate_json(self, stats):
        """Generate JSON report"""
        return json.dumps(stats, indent=2)
    
    def generate_csv(self, stats):
        """Generate CSV report"""
        # Simplified CSV generation
        csv_content = "Metric,Value\n"
        for key, value in stats.items():
            if isinstance(value, dict):
                continue
            csv_content += f"{key},{value}\n"
        return csv_content
    
    def generate_html(self, stats):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>Network Analysis Report</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
        """
        
        for key, value in stats.items():
            if isinstance(value, dict):
                continue
            html += f"<tr><td>{key}</td><td>{value}</td></tr>\n"
        
        html += "</table></body></html>"
        return html
    
    def save_report(self, content, filename):
        """Save report to file"""
        filepath = self.config.REPORTS_DIR / filename
        with open(filepath, 'w') as f:
            f.write(content)
