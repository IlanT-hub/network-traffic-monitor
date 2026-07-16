"""Terminal UI dashboard for network monitoring (2026 Edition)"""

import logging
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from datetime import datetime

logger = logging.getLogger(__name__)


class Dashboard:
    """Beautiful terminal dashboard for network monitoring (2026 Edition)"""
    
    def __init__(self) -> None:
        self.console = Console()
        self.packet_log: List[Dict[str, Any]] = []
    
    def display_header(self, interface: Optional[str] = None) -> None:
        """Display initial header"""
        title = "🌐 NETWORK TRAFFIC MONITOR 2026 🌐"
        self.console.print(Panel(title, style="bold cyan", expand=False))
        if interface:
            self.console.print(f"[cyan]Interface:[/cyan] {interface}")
        self.console.print()
    
    def display_dashboard_header(self, interface: Optional[str] = None) -> None:
        """Display dashboard mode header"""
        self.display_header(interface)
        self.console.print("[bold yellow]Press Ctrl+C to stop[/bold yellow]\n")
    
    def display_packet(self, protocol_info: Dict[str, Any]) -> None:
        """Display packet information"""
        src = f"{protocol_info.get('src_ip', 'N/A')}:{protocol_info.get('src_port', 'N/A')}"
        dst = f"{protocol_info.get('dst_ip', 'N/A')}:{protocol_info.get('dst_port', 'N/A')}"
        protocol = protocol_info.get('protocol', 'Unknown')
        size = protocol_info.get('packet_size', 0)
        
        output = f"[cyan]{src}[/cyan] → [green]{dst}[/green] | [yellow]{protocol}[/yellow] | {size} bytes"
        self.console.print(output)
    
    def display_alert(self, anomalies: List[str]) -> None:
        """Display anomaly alerts"""
        for anomaly in anomalies:
            self.console.print(f"[bold red]{anomaly}[/bold red]")
    
    def display_statistics(self, stats: Dict[str, Any]) -> None:
        """Display network statistics"""
        self.console.print(Panel("📊 NETWORK STATISTICS", style="bold cyan"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        
        stats_items = [
            ("Total Packets", f"{stats.get('packet_count', 0):,}"),
            ("Total Bytes", f"{self._format_bytes(stats.get('total_bytes', 0))}"),
            ("Duration", f"{stats.get('elapsed_seconds', 0):.1f}s"),
            ("Packets/sec", f"{stats.get('packets_per_second', 0):.2f}"),
            ("Bytes/sec", f"{self._format_bytes(stats.get('bytes_per_second', 0))}"),
            ("Avg Packet Size", f"{stats.get('avg_packet_size', 0):.0f} bytes"),
        ]
        
        for label, value in stats_items:
            table.add_row(f"[cyan]{label}[/cyan]", f"[yellow]{value}[/yellow]")
        
        self.console.print(table)
        self.console.print()
    
    def render_dashboard(self, stats: Dict[str, Any], anomalies: List[str]) -> None:
        """Render complete real-time dashboard"""
        self.console.clear()
        self.display_dashboard_header(None)
        self.display_statistics(stats)
        
        if anomalies:
            self.console.print("[bold red]ANOMALIES DETECTED:[/bold red]")
            for anomaly in anomalies:
                self.console.print(f"  {anomaly}")
            self.console.print()
    
    def update(self, stats: Dict[str, Any]) -> None:
        """Update dashboard with new statistics"""
        self.display_statistics(stats)
    
    def error(self, message: str) -> None:
        """Display error message"""
        self.console.print(f"[bold red]❌ Error: {message}[/bold red]")
    
    def success(self, message: str) -> None:
        """Display success message"""
        self.console.print(f"[bold green]✅ {message}[/bold green]")
    
    @staticmethod
    def _format_bytes(bytes_value: float) -> str:
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"
