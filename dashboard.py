"""Terminal UI dashboard for network monitoring"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from datetime import datetime
import time


class Dashboard:
    """Beautiful terminal dashboard for network monitoring"""
    
    def __init__(self):
        self.console = Console()
        self.packet_log = []
    
    def display_header(self, interface):
        """Display initial header"""
        title = "🌐 NETWORK TRAFFIC MONITOR 🌐"
        self.console.print(Panel(title, style="bold cyan", expand=False))
        if interface:
            self.console.print(f"Interface: {interface}")
        self.console.print()
    
    def display_dashboard_header(self, interface):
        """Display dashboard mode header"""
        self.display_header(interface)
        self.console.print("[bold yellow]Press Ctrl+C to stop[/bold yellow]\n")
    
    def display_packet(self, protocol_info):
        """Display packet information"""
        src = f"{protocol_info.get('src_ip', 'N/A')}:{protocol_info.get('src_port', 'N/A')}"
        dst = f"{protocol_info.get('dst_ip', 'N/A')}:{protocol_info.get('dst_port', 'N/A')}"
        protocol = protocol_info.get('protocol', 'Unknown')
        size = protocol_info.get('packet_size', 0)
        
        output = f"[cyan]{src}[/cyan] -> [green]{dst}[/green] | {protocol} | {size} bytes"
        self.console.print(output)
    
    def display_alert(self, anomalies):
        """Display anomaly alerts"""
        for anomaly in anomalies:
            self.console.print(f"[bold red]⚠️  ALERT: {anomaly}[/bold red]")
    
    def display_statistics(self, stats):
        """Display network statistics"""
        self.console.print(Panel("📊 NETWORK STATISTICS", style="bold cyan"))
        
        table = Table(show_header=False, box=None)
        
        stats_items = [
            ("Total Packets", f"{stats.get('packet_count', 0)}"),
            ("Total Bytes", f"{stats.get('total_bytes', 0):,}"),
            ("Duration", f"{stats.get('elapsed_seconds', 0):.1f}s"),
            ("Packets/sec", f"{stats.get('packets_per_second', 0):.2f}"),
            ("Bytes/sec", f"{stats.get('bytes_per_second', 0):.0f}"),
        ]
        
        for label, value in stats_items:
            table.add_row(f"[cyan]{label}[/cyan]", f"[yellow]{value}[/yellow]")
        
        self.console.print(table)
        self.console.print()
    
    def render_dashboard(self, stats, anomalies):
        """Render complete real-time dashboard"""
        # Clear and redraw (simplified version)
        self.console.clear()
        self.display_dashboard_header(None)
        self.display_statistics(stats)
        
        if anomalies:
            for anomaly in anomalies:
                self.console.print(f"[bold red]⚠️  {anomaly}[/bold red]")
    
    def error(self, message):
        """Display error message"""
        self.console.print(f"[bold red]❌ Error: {message}[/bold red]")
    
    def success(self, message):
        """Display success message"""
        self.console.print(f"[bold green]✅ {message}[/bold green]")
