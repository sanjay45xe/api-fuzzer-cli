import json
import asyncio
import os
from typing import List, Optional, Dict
import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.box import ROUNDED

from fuzzer.config import FuzzerConfig
from fuzzer.generator import generate_payloads
from fuzzer.engine import FuzzEngine
from fuzzer.logger import FuzzSessionLogger, FuzzResult
from fuzzer.dashboard import FuzzDashboard

app = typer.Typer(help="🌩️ Asynchronous API Fuzzing CLI Tool for Security & SRE Auditing.")
console = Console()

def parse_headers(headers_list: Optional[List[str]]) -> Dict[str, str]:
    headers = {}
    if not headers_list:
        return headers
    for h in headers_list:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()
        else:
            console.print(f"[bold yellow]Warning:[/bold yellow] Header '{h}' is invalid. Must be in 'Name: Value' format.")
    return headers

@app.command(name="run")
def run(
    url: str = typer.Argument(..., help="The target API endpoint URL."),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method to use (e.g. POST, PUT, PATCH, GET)."),
    template_path: Optional[str] = typer.Option(None, "--template", "-t", help="Path to the JSON template file for structured fuzzing."),
    concurrency: int = typer.Option(10, "--concurrency", "-c", min=1, max=500, help="Number of concurrent requests (semaphore limit)."),
    timeout: float = typer.Option(5.0, "--timeout", "-o", min=0.1, help="Request timeout in seconds."),
    headers_list: Optional[List[str]] = typer.Option(None, "--header", "-H", help="Custom HTTP headers. Example: -H 'Authorization: Bearer token'."),
    output_path: str = typer.Option("fuzz_results.json", "--output", "-f", help="Output file path to save structured JSON results.")
):
    """
    🌩️ Launch the high-concurrency API fuzzer against a target endpoint.
    """
    console.print(Panel("[bold magenta]Starting API Fuzzing Tool...[/bold magenta]\n[dim]Initializing payload generator, config validation, and async request pool.[/dim]", border_style="magenta", box=ROUNDED))
    
    # 1. Parse and Validate config
    headers = parse_headers(headers_list)
    try:
        config = FuzzerConfig(
            url=url,
            method=method,
            template_path=template_path,
            concurrency=concurrency,
            timeout=timeout,
            headers=headers,
            output=output_path
        )
    except Exception as e:
        console.print(f"\n[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 2. Parse JSON template if provided
    template = None
    if config.template_path:
        if not os.path.exists(config.template_path):
            console.print(f"\n[bold red]Error:[/bold red] JSON template file not found at '{config.template_path}'")
            raise typer.Exit(code=1)
        try:
            with open(config.template_path, "r", encoding="utf-8") as f:
                template = json.load(f)
            console.print(f"[green]Successfully loaded JSON template from {config.template_path}[/green]")
        except json.JSONDecodeError as e:
            console.print(f"\n[bold red]Error:[/bold red] JSON template is not a valid JSON structure: {e}")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"\n[bold red]Error reading template file:[/bold red] {e}")
            raise typer.Exit(code=1)

    # 3. Generate Payloads
    try:
        payloads = generate_payloads(template)
        console.print(f"[bold green]Generated {len(payloads)} fuzzed payloads[/bold green] (Type, Boundary, and Malformed JSON cases)")
    except Exception as e:
        console.print(f"\n[bold red]Error generating payloads:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 4. Set up session logger & dashboard
    session_logger = FuzzSessionLogger(config.output)
    dashboard = FuzzDashboard(len(payloads), config.url, config.method)

    # Real-time request complete callback
    def on_request_complete(result: FuzzResult):
        dashboard.update(result)
        session_logger.log_result(result)

    # 5. Run async engine
    engine = FuzzEngine(config, on_request_complete=on_request_complete)
    
    console.print("\n[bold yellow]Spawning asynchronous execution engine...[/bold yellow]\n")
    
    try:
        with Live(dashboard.get_renderable(), auto_refresh=True, refresh_per_second=8) as live:
            # Custom loop updates
            async def run_async():
                await engine.run(payloads)
                
            # Run the coroutine synchronously inside the typer command
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_async())
            finally:
                loop.close()
                
            # Final update
            live.update(dashboard.get_renderable())
    except KeyboardInterrupt:
        console.print("\n[bold red]Fuzzing run aborted by user (KeyboardInterrupt).[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Execution error:[/bold red] {e}")

    # 6. Save results to output
    session_logger.save()
    
    # 7. Print final summary
    lats = dashboard._get_latency_stats()
    failures = dashboard.count_5xx + dashboard.count_timeouts + dashboard.count_errors
    
    summary_text = (
        f"Total Completed: {dashboard.completed} / {len(payloads)}\n"
        f"Success (2xx): [green]{dashboard.count_2xx}[/green]\n"
        f"Client Errors (4xx): [yellow]{dashboard.count_4xx}[/yellow]\n"
        f"Server Errors (5xx): [red]{dashboard.count_5xx}[/red]\n"
        f"Timeouts / Failures: [bold magenta]{dashboard.count_timeouts + dashboard.count_errors}[/bold magenta]\n\n"
        f"Avg Latency: [bold]{lats['avg']*1000:.1f} ms[/bold] | 95th Percentile: [bold]{lats['p95']*1000:.1f} ms[/bold]\n"
        f"Fuzz results saved to: [cyan]{config.output}[/cyan]"
    )
    
    summary_color = "red" if failures > 0 else "green"
    console.print("\n")
    console.print(Panel(
        summary_text,
        title="[bold]Fuzzing Session Complete Summary[/bold]",
        border_style=summary_color,
        box=ROUNDED,
        padding=(1, 2)
    ))

if __name__ == "__main__":
    app()
