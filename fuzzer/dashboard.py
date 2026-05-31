import math
from typing import Dict, List, Optional
from rich.console import Console, RenderableType
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.progress import Progress, BarColumn, TextColumn
from rich.layout import Layout
from rich.live import Live
from rich.box import ROUNDED
from rich.align import Align
from fuzzer.logger import FuzzResult

class FuzzDashboard:
    def __init__(self, total_requests: int, url: str, method: str):
        self.total_requests = total_requests
        self.url = url
        self.method = method
        self.completed = 0
        
        # Stat counters
        self.count_2xx = 0
        self.count_3xx = 0
        self.count_4xx = 0
        self.count_5xx = 0
        self.count_timeouts = 0
        self.count_errors = 0
        
        # Latencies
        self.latencies: List[float] = []
        
        # Histogram buckets (in seconds)
        self.buckets = [
            ("< 10ms", 0.010),
            ("10-50ms", 0.050),
            ("50-100ms", 0.100),
            ("100-250ms", 0.250),
            ("250-500ms", 0.500),
            ("500-1s", 1.000),
            ("> 1s", float('inf'))
        ]
        self.bucket_counts = {b[0]: 0 for b in self.buckets}

    def update(self, result: FuzzResult):
        self.completed += 1
        
        if result.timeout:
            self.count_timeouts += 1
        elif result.error:
            self.count_errors += 1
        elif result.status_code:
            code = result.status_code
            if 200 <= code < 300:
                self.count_2xx += 1
            elif 300 <= code < 400:
                self.count_3xx += 1
            elif 400 <= code < 500:
                self.count_4xx += 1
            elif 500 <= code < 600:
                self.count_5xx += 1
        else:
            self.count_errors += 1
            
        if result.ttfb is not None:
            latency_sec = result.ttfb
            self.latencies.append(latency_sec)
            
            # Place in bucket
            for label, limit in self.buckets:
                if latency_sec < limit:
                    self.bucket_counts[label] += 1
                    break

    def _get_latency_stats(self) -> Dict[str, float]:
        if not self.latencies:
            return {"min": 0.0, "max": 0.0, "avg": 0.0, "p95": 0.0}
            
        sorted_lats = sorted(self.latencies)
        n = len(sorted_lats)
        p95_idx = min(math.ceil(n * 0.95) - 1, n - 1)
        
        return {
            "min": sorted_lats[0],
            "max": sorted_lats[-1],
            "avg": sum(sorted_lats) / n,
            "p95": sorted_lats[p95_idx]
        }

    def get_renderable(self) -> Panel:
        # 1. Title / Header Panel
        header_table = Table.grid(expand=True)
        header_table.add_column(justify="left", ratio=1)
        header_table.add_column(justify="right", ratio=1)
        header_table.add_row(
            f"[bold magenta]⚡ API FUZZER ENGINE v1.0.0[/bold magenta] [yellow]| Target: {self.url}[/yellow]",
            f"[bold cyan]Method: {self.method}[/bold cyan] [green]| Concurrency Safe[/green]"
        )

        # 2. Main content tables (split horizontally)
        # Left side: Request Metrics
        metrics_table = Table(box=ROUNDED, show_header=True, expand=True)
        metrics_table.add_column("[bold cyan]Metric[/bold cyan]", style="dim", width=18)
        metrics_table.add_column("[bold cyan]Count[/bold cyan]", justify="right")
        metrics_table.add_column("[bold cyan]Percentage[/bold cyan]", justify="right")
        
        pct_2xx = (self.count_2xx / self.completed * 100) if self.completed else 0.0
        pct_3xx = (self.count_3xx / self.completed * 100) if self.completed else 0.0
        pct_4xx = (self.count_4xx / self.completed * 100) if self.completed else 0.0
        pct_5xx = (self.count_5xx / self.completed * 100) if self.completed else 0.0
        pct_to = (self.count_timeouts / self.completed * 100) if self.completed else 0.0
        pct_err = (self.count_errors / self.completed * 100) if self.completed else 0.0

        metrics_table.add_row("Success (2xx)", f"[bold green]{self.count_2xx}[/bold green]", f"{pct_2xx:.1f}%")
        metrics_table.add_row("Redirects (3xx)", f"[bold blue]{self.count_3xx}[/bold blue]", f"{pct_3xx:.1f}%")
        metrics_table.add_row("Client Errors (4xx)", f"[bold yellow]{self.count_4xx}[/bold yellow]", f"{pct_4xx:.1f}%")
        metrics_table.add_row("Server Errors (5xx)", f"[bold red]{self.count_5xx}[/bold red]", f"{pct_5xx:.1f}%")
        metrics_table.add_row("Timeouts (TO)", f"[bold magenta]{self.count_timeouts}[/bold magenta]", f"{pct_to:.1f}%")
        metrics_table.add_row("Network Errors", f"[bold red]{self.count_errors}[/bold red]", f"{pct_err:.1f}%")

        # Right side: Latency statistics & Histogram
        lats = self._get_latency_stats()
        latency_table = Table(box=ROUNDED, show_header=False, expand=True)
        latency_table.add_column("Stat", style="dim", width=15)
        latency_table.add_column("Value", justify="right")
        
        latency_table.add_row("Min TTFB", f"[bold green]{lats['min']*1000:.1f} ms[/bold green]")
        latency_table.add_row("Max TTFB", f"[bold red]{lats['max']*1000:.1f} ms[/bold red]")
        latency_table.add_row("Avg TTFB", f"[bold yellow]{lats['avg']*1000:.1f} ms[/bold yellow]")
        latency_table.add_row("95th Pct TTFB", f"[bold cyan]{lats['p95']*1000:.1f} ms[/bold cyan]")

        # 3. Histogram bar generation
        histo_table = Table(box=ROUNDED, show_header=True, expand=True)
        histo_table.add_column("[bold cyan]Range[/bold cyan]", width=12)
        histo_table.add_column("[bold cyan]Distribution[/bold cyan]")
        
        max_bucket_val = max(self.bucket_counts.values()) if any(self.bucket_counts.values()) else 1
        for label, _ in self.buckets:
            val = self.bucket_counts[label]
            # Calculate block characters length
            bar_len = int((val / max_bucket_val) * 20) if val else 0
            bar = "█" * bar_len + "░" * (20 - bar_len)
            
            # Format bar color based on speed
            if label in ["< 10ms", "10-50ms", "50-100ms"]:
                bar_color = "green"
            elif label in ["100-250ms", "250-500ms"]:
                bar_color = "yellow"
            else:
                bar_color = "red"
                
            histo_table.add_row(
                label,
                f"[{bar_color}]{bar}[/{bar_color}] ({val})"
            )

        # 4. Progress Section
        progress_table = Table.grid(expand=True)
        progress_table.add_column(ratio=8)
        progress_table.add_column(ratio=2, justify="right")
        
        pct_completed = (self.completed / self.total_requests) if self.total_requests else 1.0
        bar_progress = int(pct_completed * 40)
        progress_bar = "█" * bar_progress + "░" * (40 - bar_progress)
        
        progress_table.add_row(
            f"[bold cyan]Progress:[/bold cyan] [green]{progress_bar}[/green]",
            f"[bold]{self.completed} / {self.total_requests}[/bold] ({pct_completed*100:.1f}%)"
        )

        # 5. Assemble everything in columns
        layout_grid = Table.grid(expand=True, padding=1)
        layout_grid.add_column(ratio=5)
        layout_grid.add_column(ratio=5)
        
        # Combine Left Column
        left_column = Table.grid(expand=True)
        left_column.add_row("[bold yellow]Status Code Counts[/bold yellow]")
        left_column.add_row(metrics_table)
        left_column.add_row("[bold yellow]Latency Statistics[/bold yellow]")
        left_column.add_row(latency_table)
        
        # Combine Right Column
        right_column = Table.grid(expand=True)
        right_column.add_row("[bold yellow]TTFB Latency Histogram[/bold yellow]")
        right_column.add_row(histo_table)
        
        layout_grid.add_row(left_column, right_column)

        # Master layout assembly
        master_grid = Table.grid(expand=True, padding=1)
        master_grid.add_row(header_table)
        master_grid.add_row(layout_grid)
        master_grid.add_row(progress_table)

        return Panel(
            master_grid,
            box=ROUNDED,
            title="[bold yellow]API FUZZER DASHBOARD[/bold yellow]",
            border_style="magenta",
            padding=(1, 2)
        )
